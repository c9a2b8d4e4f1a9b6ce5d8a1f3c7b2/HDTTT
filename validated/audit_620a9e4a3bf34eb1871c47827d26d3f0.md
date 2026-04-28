### Title
Atomic Transaction Group Invariant Broken by Individual Transaction Cancellation

### Summary

The `TransactionGroup` entity exposes an `atomic` flag intended to guarantee all-or-nothing execution of grouped transactions. However, individual transactions within an atomic group can be canceled via `PATCH /transactions/cancel/:id` without any check for group membership. The scheduler then silently filters out the canceled transaction and executes the remaining group members alone, permanently breaking the atomicity guarantee and producing an inconsistent on-chain state.

### Finding Description

**Vulnerability class**: State transition — two operations that must be atomic can be executed separately.

**Root cause — missing group-membership check in `cancelTransactionWithOutcome`:**

`cancelTransactionWithOutcome` in `back-end/apps/api/src/transactions/transactions.service.ts` only verifies that the caller is the transaction creator and that the status is cancelable. It never checks whether the transaction belongs to an atomic group. [1](#0-0) 

The same omission exists in `archiveTransaction`: [2](#0-1) 

Both are reachable by any authenticated user who is the transaction creator, via: [3](#0-2) 

**Root cause — silent filter in `executeTransactionGroup` swallows the broken invariant:**

When the scheduler fires, `executeTransactionGroup` filters the group's items to only those still in `WAITING_FOR_EXECUTION`: [4](#0-3) 

There is no guard that aborts execution when the group is `atomic` and one or more members are missing from the filtered set. The remaining transactions are validated and submitted to the Hedera network as if the group were complete.

**Exploit path (step by step):**

1. Authenticated user (creator) submits an atomic `TransactionGroup` containing TX-A and TX-B via `POST /transaction-groups`. Both transactions are designed so that TX-A must precede TX-B (e.g., TX-A creates an account; TX-B transfers funds into it).
2. Both transactions accumulate signatures and transition to `WAITING_FOR_EXECUTION`.
3. Creator calls `PATCH /transactions/cancel/{TX-A-id}`. `cancelTransactionWithOutcome` succeeds — TX-A is now `CANCELED`.
4. The chain-service scheduler (`prepareTransactions`) finds TX-B still in `WAITING_FOR_EXECUTION` with a `groupItem` pointing to the atomic group, and routes it to `collateGroupAndExecute`. [5](#0-4) 

5. `collateGroupAndExecute` fetches the full group (TX-A: CANCELED, TX-B: WAITING_FOR_EXECUTION) and calls `executeTransactionGroup`.
6. The filter at line 65–67 silently drops TX-A. TX-B is validated and submitted to the Hedera network alone.
7. The atomic group is partially executed. TX-B either fails on-chain (because its prerequisite TX-A never ran) or, worse, succeeds in an unintended state.

### Impact Explanation

- **Broken atomicity**: Transactions declared atomic can execute partially. Any business logic that depends on the all-or-nothing guarantee is violated.
- **Irreversible on-chain state**: Hedera transactions are final. A TX-B that executes without TX-A cannot be rolled back.
- **Concrete example**: If TX-A is a payment and TX-B is a service-delivery transaction, canceling TX-A while TX-B executes means the service is delivered without payment. Conversely, if TX-A is an account-creation and TX-B transfers funds to that account, TX-B will fail on-chain and the funds transfer is lost, leaving the user in an unrecoverable state.

Severity: **High** — directly connected to irreversible fund/state flow on the Hedera network.

### Likelihood Explanation

- **Attacker profile**: Any authenticated organization user who is the creator of the transactions. No privileged keys or admin access required.
- **Entry point**: Standard REST API endpoint `PATCH /transactions/cancel/:id`, publicly documented and reachable by any logged-in user.
- **Preconditions**: The attacker must have created the atomic group (normal user action). The window is between both transactions reaching `WAITING_FOR_EXECUTION` and the scheduler firing — a window of up to several minutes depending on `validStart`.
- **Detectability**: The system emits no warning when an atomic group is partially executed; the UI shows individual transaction statuses without flagging the broken invariant.

Likelihood: **Medium** — requires the creator to act within a timing window, but the action (cancel one transaction) is a normal, exposed API call.

### Recommendation

1. **In `cancelTransactionWithOutcome` and `archiveTransaction`**: Before canceling or archiving a transaction, check if it belongs to an atomic group. If it does, either cancel/archive all sibling transactions atomically in the same operation, or reject the individual operation with a clear error (e.g., `"Cannot cancel a single transaction that belongs to an atomic group"`).

2. **In `executeTransactionGroup`**: When `transactionGroup.atomic === true`, verify that **all** original group members are still in `WAITING_FOR_EXECUTION` before proceeding. If any member is missing (canceled, archived, etc.), abort the entire group execution and mark remaining members as `FAILED` with an appropriate status code. [4](#0-3) 

### Proof of Concept

```
# 1. Create atomic group with two transactions
POST /transaction-groups
{
  "description": "Atomic pair",
  "atomic": true,
  "groupItems": [
    { "transactionId": <TX-A-id> },
    { "transactionId": <TX-B-id> }
  ]
}

# 2. Wait for both transactions to reach WAITING_FOR_EXECUTION
# (sign with required keys)

# 3. Cancel TX-A individually — no group check is performed
PATCH /transactions/cancel/<TX-A-id>
# Response: 200 OK

# 4. Observe: TX-B is still in WAITING_FOR_EXECUTION
# The scheduler fires, collateGroupAndExecute fetches the group,
# executeTransactionGroup filters out TX-A (CANCELED),
# and submits TX-B alone to the Hedera network.

# Expected (correct) behavior: TX-B should also be canceled or the
# group execution should be aborted.
# Actual behavior: TX-B executes on-chain without TX-A.
```

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L659-704)
```typescript
  async cancelTransactionWithOutcome(
    id: number,
    user: User,
  ): Promise<CancelTransactionOutcome> {
    const transaction = await this.getTransactionForCreator(id, user);

    if (transaction.status === TransactionStatus.CANCELED) {
      return CancelTransactionOutcome.ALREADY_CANCELED;
    }

    if (!this.cancelableStatuses.includes(transaction.status)) {
      throw new BadRequestException(ErrorCodes.OTIP);
    }

    const updateResult = await this.repo
      .createQueryBuilder()
      .update(Transaction)
      .set({ status: TransactionStatus.CANCELED })
      .where('id = :id', { id })
      .andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
      .execute();

    if (updateResult.affected && updateResult.affected > 0) {
      emitTransactionStatusUpdate(
        this.notificationsPublisher,
        [{
          entityId: id,
          additionalData: {
            transactionId: transaction.transactionId,
            network: transaction.mirrorNetwork,
          },
        }],
      );

      return CancelTransactionOutcome.CANCELED;
    }

    // Race-safe fallback: state changed between read and update, so re-check current status.
    const latestTransaction = await this.getTransactionForCreator(id, user);
    if (latestTransaction.status === TransactionStatus.CANCELED) {
      return CancelTransactionOutcome.ALREADY_CANCELED;
    }
    if (!this.cancelableStatuses.includes(latestTransaction.status)) {
      throw new BadRequestException(ErrorCodes.OTIP);
    }
    throw new ConflictException('Cancellation conflict');
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L707-733)
```typescript
  /* Archive the transaction if the transaction is sign only. */
  async archiveTransaction(id: number, user: User): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);

    if (
      ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
        transaction.status,
      ) &&
      !transaction.isManual
    ) {
      throw new BadRequestException(ErrorCodes.OMTIP);
    }

    await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
    emitTransactionStatusUpdate(
      this.notificationsPublisher,
      [{
        entityId: transaction.id,
        additionalData: {
          transactionId: transaction.transactionId,
          network: transaction.mirrorNetwork,
        },
      }],
    );

    return true;
  }
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L256-287)
```typescript
  @ApiOperation({
    summary: 'Archives a transaction',
    description: 'Archive a transaction that is marked as sign only',
  })
  @ApiResponse({
    status: 200,
    type: Boolean,
  })
  @Patch('/archive/:id')
  async archiveTransaction(
    @GetUser() user,
    @Param('id', ParseIntPipe) id: number,
  ): Promise<boolean> {
    return this.transactionsService.archiveTransaction(id, user);
  }

  @ApiOperation({
    summary: 'Send a transaction for execution',
    description: 'Send a manual transaction to the chain service that will execute it',
  })
  @ApiResponse({
    status: 200,
    type: Boolean,
  })
  @Patch('/execute/:id')
  async executeTransaction(
    @GetUser() user,
    @Param('id', ParseIntPipe) id: number,
  ): Promise<boolean> {
    return this.transactionsService.executeTransaction(id, user);
  }

```

**File:** back-end/libs/common/src/execute/execute.service.ts (L62-81)
```typescript
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
