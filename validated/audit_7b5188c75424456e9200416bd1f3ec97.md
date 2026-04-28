All referenced code locations have been verified against the actual source. The claim is accurate.

---

# Audit Report

## Title
Atomic Transaction Group Integrity Broken by Direct Hedera Submission from Malicious Signer

## Summary
The `atomic` flag on `TransactionGroup` is stored in the database but enforced only at the application scheduler layer. A legitimate signer can extract fully-signed `transactionBytes` from the API and submit individual transactions in an atomic group directly to the Hedera network. The tool's `executeTransactionGroup` function then either silently skips the already-submitted transaction (via the `WAITING_FOR_EXECUTION` status filter or the `isDuplicate` branch), allowing the remaining transactions to execute, thereby violating the all-or-nothing guarantee.

## Finding Description

**Root Cause**

The `TransactionGroup` entity declares an `atomic` boolean column, but no on-chain atomicity mechanism exists. Each transaction in the group is an independent Hedera transaction with its own `transactionId` and `validStart`. [1](#0-0) 

The `atomic` flag is only used in `prepareTransactions` to route the group through `collateGroupAndExecute` → `addGroupExecutionTimeout` → `executeTransactionGroup`. It is never checked inside `executeTransactionGroup` itself, and it provides no enforcement once the signed bytes leave the tool. [2](#0-1) 

**Signed `transactionBytes` Are Accessible to Signers**

`getTransactionGroup` runs `getTransactionGroupItemsQuery`, which selects `t.transactionBytes AS tx_transaction_bytes` and maps it directly into the response. Access is gated only on the caller being a signer, creator, observer, or approver of the group — all legitimate roles. [3](#0-2) [4](#0-3) 

**Attack Path — Two Viable Scenarios**

*Scenario A (status already updated before group is loaded):*

The attacker submits TX₁ directly to Hedera. The chain service updates TX₁'s DB status to `EXECUTED`. When the scheduler later loads the group and calls `executeTransactionGroup`, the opening filter silently drops TX₁ because its in-memory status is now `EXECUTED`, not `WAITING_FOR_EXECUTION`. TX₂ and TX₃ proceed and execute normally. [5](#0-4) 

*Scenario B (race — DB not yet updated):*

The attacker submits TX₁ but the DB has not yet been updated. The scheduler loads the group (TX₁ still shows `WAITING_FOR_EXECUTION`), and `executeTransactionGroup` also submits TX₁. Hedera returns `DUPLICATE_TRANSACTION`. The `isDuplicate` branch sets `isDuplicate = true` and returns `null`, silently skipping TX₁. TX₂ and TX₃ execute normally. [6](#0-5) 

**Why Locks Do Not Prevent This**

`executeTransaction` holds a `MurLock` keyed on `transaction.id`; `executeTransactionGroup` holds a `MurLock` keyed on `transactionGroup.id + "_group"`. These are orthogonal namespaces and do not prevent an external Hedera submission from racing the group execution path. [7](#0-6) [8](#0-7) 

**Note on Scenario C (EXECUTED before validation):**

If TX₁ is marked `EXECUTED` in the DB *after* the group is loaded (so it passes the in-memory filter) but *before* `getValidatedSDKTransaction` runs its fresh DB read, `validateTransactionStatus` throws `"Transaction has already been executed."`, causing the entire group to fail. This scenario does not produce partial execution but does cause a denial-of-execution for the remaining transactions, which is also a violation of the atomicity guarantee. [9](#0-8) 

## Impact Explanation

An atomic group is intended to execute all-or-nothing. A malicious signer can cause partial execution: some transactions land on-chain while others do not. For groups representing coordinated financial operations (multi-account transfers, sequential file updates, account key rotations), partial execution can cause permanent state inconsistency on the Hedera ledger. The remaining transactions may expire before the group creator can reschedule, causing permanent loss of the intended operation.

## Likelihood Explanation

The attacker must be an authenticated signer — a role granted by the group creator as part of normal workflow. Once a signer has signed, they possess the `transactionBytes` returned by `GET /transaction-groups/:id`. No privileged keys, admin access, or cryptographic breaks are required. The Hedera network is public and permissionless for transaction submission via any SDK client.

## Recommendation

1. **Re-validate atomicity at execution time**: Before executing any transaction in the group, re-fetch all group item statuses from the DB in a single query. If any item is not `WAITING_FOR_EXECUTION`, abort the entire group and mark all remaining items as `FAILED` with an appropriate status code.
2. **Treat `DUPLICATE_TRANSACTION` as a group-level abort for atomic groups**: When `atomic === true` and a `DUPLICATE_TRANSACTION` response is received for any member, halt execution of the remaining members and mark them `FAILED`.
3. **Consider not exposing `transactionBytes` to signers who have not yet signed**: Restrict `transactionBytes` in the API response to the creator until the transaction reaches `WAITING_FOR_EXECUTION`, or omit it entirely from the group endpoint and only expose it through a dedicated signing endpoint.

## Proof of Concept

1. Create an atomic transaction group with two transactions (TX₁, TX₂) via `POST /transaction-groups` with `atomic: true`.
2. Sign both transactions as a legitimate signer. The group transitions to `WAITING_FOR_EXECUTION`.
3. Call `GET /transaction-groups/:id` and extract `groupItems[0].transaction.transactionBytes`.
4. Using the Hedera JavaScript SDK outside the tool:
   ```js
   const tx = Transaction.fromBytes(Buffer.from(transactionBytes, 'hex'));
   await tx.execute(client);
   ```
5. Observe that TX₁ lands on-chain.
6. Wait for the tool's scheduler to fire `executeTransactionGroup`.
7. Observe that TX₂ also executes (via Scenario A or B above).
8. The atomic group has partially executed: TX₁ was submitted by the attacker, TX₂ by the tool, with no all-or-nothing guarantee enforced.

### Citations

**File:** back-end/libs/common/src/database/entities/transaction-group.entity.ts (L12-13)
```typescript
  @Column({ default: false })
  atomic: boolean;
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L163-199)
```typescript
  async prepareTransactions(transactions: Transaction[]) {
    const processedGroupIds = new Set<number>();

    for (const transaction of transactions) {
      const waitingForExecution = transaction.status === TransactionStatus.WAITING_FOR_EXECUTION;

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
      }
    }
  }
```

**File:** back-end/libs/common/src/sql/queries/transaction.queries.ts (L378-378)
```typescript
      t.${sql.col(Transaction, 'transactionBytes')} AS tx_transaction_bytes,
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L108-116)
```typescript
      const transaction = this.dataSource.manager.create(Transaction, {
        id: row.tx_id,
        name: row.tx_name,
        type: row.tx_type,
        description: row.tx_description,
        transactionId: row.sdk_transaction_id,
        transactionHash: row.tx_transaction_hash,
        transactionBytes: row.tx_transaction_bytes,
        unsignedTransactionBytes: row.tx_unsigned_transaction_bytes,
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L41-42)
```typescript
  @MurLock(15000, 'transaction.id')
  async executeTransaction(transaction: Transaction) {
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L62-62)
```typescript
  @MurLock(15000, 'transactionGroup.id + "_group"')
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L65-67)
```typescript
    transactionGroup.groupItems = transactionGroup.groupItems.filter(
      tx => tx.transaction.status === TransactionStatus.WAITING_FOR_EXECUTION
    );
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

**File:** back-end/libs/common/src/execute/execute.service.ts (L226-248)
```typescript
  private async validateTransactionStatus(transaction: Transaction) {
    const { status } = await this.transactionsRepo.findOne({
      where: { id: transaction.id },
      select: ['status'],
    });

    switch (status) {
      case TransactionStatus.NEW:
        throw new Error('Transaction is new and has not been signed yet.');
      case TransactionStatus.FAILED:
        throw new Error('Transaction has already been executed, but failed.');
      case TransactionStatus.EXECUTED:
        throw new Error('Transaction has already been executed.');
      case TransactionStatus.REJECTED:
        throw new Error('Transaction has already been rejected.');
      case TransactionStatus.EXPIRED:
        throw new Error('Transaction has been expired.');
      case TransactionStatus.CANCELED:
        throw new Error('Transaction has been canceled.');
      case TransactionStatus.ARCHIVED:
        throw new Error('Transaction is archived.');
    }
  }
```
