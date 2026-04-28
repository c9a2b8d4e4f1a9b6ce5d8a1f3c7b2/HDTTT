### Title
Atomic Transaction Group Integrity Broken by Direct Hedera Submission from Malicious Signer

### Summary
The Hedera Transaction Tool allows authenticated signers to access fully-signed transaction bytes via the API. A malicious signer can extract those bytes and submit individual transactions from an `atomic` group directly to the Hedera network, bypassing the tool's group execution logic. The backend's `executeTransactionGroup` function silently skips already-executed transactions, causing the atomic group to partially execute and violating the atomicity guarantee the system promises.

### Finding Description

**Root Cause**

The `TransactionGroup` entity exposes an `atomic` flag intended to guarantee all-or-nothing execution. The scheduler in `prepareTransactions` correctly routes atomic groups through `collateGroupAndExecute` → `executeTransactionGroup`. However, the atomicity is enforced only at the application layer (the scheduler groups them together); there is no on-chain enforcement. Each transaction in a group is an independent Hedera transaction with its own `transactionId` and `validStart`. [1](#0-0) 

**Attack Path**

1. A malicious user is added as a signer to an atomic transaction group (a normal, legitimate role).
2. They sign their required transactions. Once all required signers have signed, the group transitions to `WAITING_FOR_EXECUTION` and the signed `transactionBytes` are accessible via the API.
3. The attacker fetches the signed `transactionBytes` for one or more individual transactions in the group via `GET /transaction-groups/:id`.
4. Using any Hedera SDK client (outside the tool), the attacker submits a subset of those transactions directly to the Hedera consensus node.
5. When the tool's scheduler fires `executeTransactionGroup`, the function first filters group items: [2](#0-1) 

If the chain service has already updated the DB status to `EXECUTED`, the already-submitted transaction is silently dropped from the execution set. If the chain service has not yet updated the status, `_executeTransaction` submits it again, receives `DUPLICATE_TRANSACTION`, and the `isDuplicate` branch returns `null` — also silently skipping it: [3](#0-2) 

6. The remaining transactions in the group execute successfully. The atomic group has now partially executed.

**Why Existing Locks Do Not Prevent This**

`executeTransactionGroup` holds a `MurLock` keyed on `transactionGroup.id + "_group"`. The single-transaction path `executeTransaction` holds a `MurLock` keyed on `transaction.id`. These are orthogonal locks and do not prevent a direct Hedera submission from racing the group execution. [4](#0-3) 

**Why the Scheduler Does Not Protect Atomic Groups**

`prepareTransactions` routes atomic groups to `collateGroupAndExecute`, but this only controls the tool's own submission path. It cannot prevent a signer from submitting bytes directly to Hedera. [5](#0-4) 

### Impact Explanation

An atomic group is intended to execute all-or-nothing. A malicious signer can cause partial execution: some transactions in the group land on-chain while others do not. For groups representing coordinated financial operations (e.g., multi-account transfers, sequential file updates, account key rotations), partial execution can cause:

- Permanent state inconsistency on the Hedera ledger (e.g., funds transferred out but corresponding credit not applied).
- Unrecoverable corruption of multi-step workflows (e.g., a file update chunk applied without the preceding create).
- The remaining transactions may expire before the group creator can reschedule, causing permanent loss of the intended operation.

### Likelihood Explanation

The attacker must be an authenticated signer of the target group — a role granted by the group creator. This is a realistic insider-threat scenario. Once a signer has signed, they possess the transaction bytes and can submit them to any Hedera node using the public SDK. No privileged keys, admin access, or cryptographic breaks are required. The Hedera network is public and permissionless for submission.

### Recommendation

1. **Do not expose signed `transactionBytes` to signers after the group reaches `WAITING_FOR_EXECUTION`.** Signers need the bytes to sign, but once signing is complete, the bytes should be withheld from API responses for atomic groups.
2. **Enforce atomicity at the execution layer**: before executing any transaction in an atomic group, verify that ALL group members are still in `WAITING_FOR_EXECUTION` status with a single atomic DB read inside the `MurLock`. If any member has already been executed or is a duplicate, abort the entire group and mark all remaining members as `FAILED`.
3. **Detect and handle partial execution**: the chain service should detect when a transaction belonging to an atomic group is submitted externally and immediately cancel or fail the remaining group members.

### Proof of Concept

**Setup**: Atomic group with transactions A, B, C. All three are fully signed (`WAITING_FOR_EXECUTION`). Attacker is a legitimate signer.

**Steps**:
```
1. GET /transaction-groups/{groupId}
   → Response includes transactionBytes for transaction A

2. Using Hedera SDK directly (outside the tool):
   const tx = Transaction.fromBytes(transactionBytesA);
   await tx.execute(hederaClient);
   // Transaction A is now on-chain

3. Tool's scheduler fires executeTransactionGroup:
   - groupItems filtered: A is EXECUTED → removed
   - B and C are validated and executed
   - Group "completes" with only B and C on-chain

4. Result: Atomic group partially executed.
   Transaction A executed independently; B and C executed as a pair.
   The intended all-or-nothing guarantee is violated.
``` [6](#0-5)

### Citations

**File:** back-end/libs/common/src/database/entities/transaction-group.entity.ts (L12-16)
```typescript
  @Column({ default: false })
  atomic: boolean;

  @Column({ default: false })
  sequential: boolean;
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L41-99)
```typescript
  @MurLock(15000, 'transaction.id')
  async executeTransaction(transaction: Transaction) {
    /* Gets the SDK transaction */
    const sdkTransaction = await this.getValidatedSDKTransaction(transaction);
    const result = await this._executeTransaction(transaction, sdkTransaction);
    if (result) {
      emitTransactionStatusUpdate(
        this.notificationsPublisher,
        [{
          entityId: transaction.id,
          additionalData: {
            network: transaction.mirrorNetwork,
            transactionId: sdkTransaction.transactionId,
            status: result.status,
          }
        }],
      );
    }
    return result;
  }

  @MurLock(15000, 'transactionGroup.id + "_group"')
  async executeTransactionGroup(transactionGroup: TransactionGroup) {
    this.logger.log('executing transactions');
    transactionGroup.groupItems = transactionGroup.groupItems.filter(
      tx => tx.transaction.status === TransactionStatus.WAITING_FOR_EXECUTION
    );
    const transactions: { sdkTransaction: SDKTransaction; transaction: Transaction }[] =
      [];
    // first we need to validate all the transactions, as they all need to be valid before we can execute any of them
    for (const groupItem of transactionGroup.groupItems) {
      const transaction = groupItem.transaction;
      try {
        const sdkTransaction = await this.getValidatedSDKTransaction(transaction);
        transactions.push({ sdkTransaction, transaction });
      } catch (error) {
        throw new Error(
          `Transaction Group cannot be submitted. Error validating transaction ${transaction.id}: ${error.message}`,
        );
      }
    }

    // Execute all transactions, collecting raw results (may contain nulls for pods that lost the race)
    const rawResults: (TransactionExecutedDto | null)[] = [];

    if (transactionGroup.sequential) {
      for (const { sdkTransaction, transaction } of transactions) {
        const delay = transaction.validStart.getTime() - Date.now();
        await sleep(delay);
        rawResults.push(await this._executeTransaction(transaction, sdkTransaction));
      }
    } else {
      const executionPromises = transactions.map(async ({ sdkTransaction, transaction }) => {
        const delay = transaction.validStart.getTime() - Date.now();
        await sleep(delay);
        return this._executeTransaction(transaction, sdkTransaction);
      });
      rawResults.push(...(await Promise.all(executionPromises)));
    }
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L168-185)
```typescript
      if (statusCode === Status.DuplicateTransaction._code) {
        isDuplicate = true;
        this.logger.debug(
          `Duplicate transaction ${transaction.id} (txId=${sdkTransaction.transactionId}, statusCode=${statusCode}) detected; assuming it was successfully executed by another pod and skipping updates.`,
        );
      } else {
        transactionStatus = TransactionStatus.FAILED;
        transactionStatusCode = statusCode;
        result.error = message;
        this.logger.error(
          `Error executing transaction ${transaction.id} (txId=${sdkTransaction.transactionId}, statusCode=${statusCode}): ${message}`,
        );
      }
    } finally {
      client.close();
    }

    if (isDuplicate) return null;
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L169-196)
```typescript
      if (waitingForExecution && this.isValidStartExecutable(transaction.validStart)) {
        if (transaction.groupItem && (transaction.groupItem.group.atomic || transaction.groupItem.group.sequential)) {
          if (!processedGroupIds.has(transaction.groupItem.groupId)) {
            processedGroupIds.add(transaction.groupItem.groupId);
            // Now that we are sure this transaction group needs to be processed together, get it
            // and being the processing
            const transactionGroup = await this.transactionGroupRepo.findOne({
              where: { id: transaction.groupItem.groupId },
              relations: {
                groupItems: {
                  transaction: true,
                },
              },
              order: {
                groupItems: {
                  transaction: {
                    validStart: 'ASC',
                  },
                },
              },
            });
            // All the transactions for the group are now pulled. If there is an issue validating for even one
            // transaction, the group will not be executed. This is handled in executeTransactionGroup
            this.collateGroupAndExecute(transactionGroup);
          }
        } else {
          this.collateAndExecute(transaction);
        }
```
