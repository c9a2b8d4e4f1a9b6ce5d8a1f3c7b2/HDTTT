### Title
Single Transaction Validation Failure in `executeTransactionGroup` Permanently Blocks Entire Atomic/Sequential Group Execution

### Summary

`executeTransactionGroup()` in `back-end/libs/common/src/execute/execute.service.ts` validates every transaction in a group before executing any of them. If a single transaction fails validation — due to expiry, cancellation, or invalid signatures — the function throws an unhandled error and the entire group is permanently abandoned with no state update, no retry, and no notification. The transaction creator can deliberately trigger this by canceling their own transaction in a group that is already queued for execution, or the built-in expiry scheduler can race with the execution scheduler to produce the same outcome non-maliciously.

### Finding Description

**Root cause — all-or-nothing validation loop:**

In `executeTransactionGroup()`, the validation loop iterates over every group item and calls `getValidatedSDKTransaction()`. If any call throws, the error is re-thrown immediately, aborting the entire function:

```
back-end/libs/common/src/execute/execute.service.ts  lines 70-81
```

```typescript
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

The scheduler comment at line 190-191 explicitly acknowledges this design:

> "If there is an issue validating for even one transaction, the group will not be executed. This is handled in executeTransactionGroup" [1](#0-0) [2](#0-1) 

**`validateTransactionStatus()` re-fetches from DB and throws for terminal states:**

`getValidatedSDKTransaction()` calls `validateTransactionStatus()`, which re-fetches the transaction status from the database. It throws for `CANCELED`, `EXPIRED`, `FAILED`, `EXECUTED`, `REJECTED`, and `ARCHIVED` statuses: [3](#0-2) 

**Attack vector 1 — expiry scheduler races with execution scheduler:**

The expiry cron job runs every 10 seconds and marks `WAITING_FOR_EXECUTION` transactions as `EXPIRED` if their `validStart` is more than 3 minutes in the past: [4](#0-3) 

The execution timeout fires at `validStart + 5 seconds`: [5](#0-4) 

If the chain service restarts, is under load, or the execution timeout fires late, the expiry scheduler can mark a `WAITING_FOR_EXECUTION` transaction as `EXPIRED` before `executeTransactionGroup` runs. When validation then re-fetches the status, it throws `"Transaction has been expired."`, aborting the entire group.

**Attack vector 2 — transaction creator cancels their own transaction:**

The `PATCH /transactions/cancel/:id` endpoint allows the transaction creator to cancel their own transaction. The `cancelTransactionGroup` service explicitly lists `WAITING_FOR_EXECUTION` as a cancelable status: [6](#0-5) 

A malicious creator who is a member of a multi-party group can cancel their own transaction after the group reaches `WAITING_FOR_EXECUTION`, causing `validateTransactionStatus` to throw `"Transaction has been canceled."` and aborting the entire group.

**No recovery path:**

When `executeTransactionGroup` throws, the caller in `addGroupExecutionTimeout` catches the error silently and logs it. No transactions are marked as `FAILED`, no notifications are emitted, and no retry is scheduled. The group is permanently stuck: [7](#0-6) 

### Impact Explanation

All transactions in an atomic or sequential group are permanently blocked from execution with no state update. Users have no indication of what happened. For sequential groups, this means a coordinated multi-party workflow is silently abandoned. The group cannot be re-submitted because the transactions' `validStart` windows will have passed, making them expire. This is a permanent, unrecoverable loss of the group's execution.

### Likelihood Explanation

- **Expiry race**: Realistic under any server restart or transient load spike. The window between `validStart + 5s` (execution trigger) and `validStart + 3 minutes` (expiry threshold) is narrow. Any delay in the chain service processing the execution timeout causes the expiry scheduler to win the race.
- **Malicious cancel**: Any transaction creator who is part of a multi-party group can deliberately cancel their own transaction after the group is queued. This requires no privileged access — only a valid authenticated user account and creator ownership of one transaction in the group.

### Recommendation

1. **Do not throw on single-transaction validation failure.** Instead, collect failures and decide per group type: for atomic groups, mark all remaining transactions as `FAILED` with a descriptive status code and emit notifications; for sequential groups, skip the failed transaction and continue.
2. **Mark all group transactions as `FAILED` when the group cannot proceed**, so users receive notifications and the state is recoverable.
3. **Prevent cancellation of `WAITING_FOR_EXECUTION` transactions that belong to an atomic/sequential group** once the group has been queued for execution, or at minimum require all group members to consent.
4. **Add a grace period** to the expiry scheduler for transactions that are in `WAITING_FOR_EXECUTION` state, so the execution timeout has time to fire before expiry takes effect.

### Proof of Concept

**Expiry race (non-malicious):**
1. User creates an atomic transaction group with `validStart = T`.
2. All required signers sign; group transitions to `WAITING_FOR_EXECUTION`.
3. Chain service is restarted or delayed at time `T`.
4. At `T + 3 minutes + 10 seconds`, `handleExpiredTransactions` marks all group transactions as `EXPIRED`.
5. At `T + 5 seconds` (now overdue), `addGroupExecutionTimeout` fires and calls `executeTransactionGroup`.
6. `validateTransactionStatus` re-fetches from DB, finds `EXPIRED`, throws.
7. The catch block in `addGroupExecutionTimeout` logs the error silently. No transactions are updated. Group is permanently stuck.

**Malicious cancel (user-triggered):**
1. Attacker creates a transaction group with two transactions: one they own, one owned by another user.
2. Both transactions are signed; group reaches `WAITING_FOR_EXECUTION`.
3. Attacker calls `PATCH /transactions/cancel/<their_tx_id>` immediately before `validStart`.
4. `executeTransactionGroup` validates the group, hits the canceled transaction, throws.
5. The other user's transaction is never executed. Group is permanently abandoned with no notification. [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

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

**File:** back-end/libs/common/src/execute/execute.service.ts (L225-248)
```typescript
  /* Throws if the transaction is not in a valid state */
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

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L100-128)
```typescript
  @Cron(CronExpression.EVERY_10_SECONDS, {
    name: 'status_update_expired_transactions',
  })
  async handleExpiredTransactions() {
    const result = await this.transactionRepo
      .createQueryBuilder()
      .update(Transaction)
      .set({ status: TransactionStatus.EXPIRED })
      .where('status IN (:...statuses) AND validStart < :before', {
        statuses: [
          TransactionStatus.NEW,
          TransactionStatus.REJECTED,
          TransactionStatus.WAITING_FOR_EXECUTION,
          TransactionStatus.WAITING_FOR_SIGNATURES,
        ],
        before: this.getThreeMinutesBefore(),
      })
      .returning(['id'])
      .execute();

    if (result.raw.length > 0) {
      emitTransactionStatusUpdate(
        this.notificationsPublisher,
        result.raw.map(t => ({
          entityId: t.id,
        })),
      );
    }
  }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L190-192)
```typescript
            // All the transactions for the group are now pulled. If there is an issue validating for even one
            // transaction, the group will not be executed. This is handled in executeTransactionGroup
            this.collateGroupAndExecute(transactionGroup);
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L330-350)
```typescript
  addGroupExecutionTimeout(transactionGroup: TransactionGroup) {
    const name = `group_execution_timeout_${transactionGroup.id}`;

    if (this.schedulerRegistry.doesExist('timeout', name)) return;

    const timeToValidStart =
      transactionGroup.groupItems[0].transaction.validStart.getTime() - Date.now();

    const callback = async () => {
      try {
        await this.executeService.executeTransactionGroup(transactionGroup);
      } catch (error) {
        console.log(error);
      } finally {
        this.schedulerRegistry.deleteTimeout(name);
      }
    };

    const timeout = setTimeout(callback, timeToValidStart + 5 * 1_000);
    this.schedulerRegistry.addTimeout(name, timeout);
  }
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L214-218)
```typescript
    const cancelableStatuses = [
      TransactionStatus.NEW,
      TransactionStatus.WAITING_FOR_SIGNATURES,
      TransactionStatus.WAITING_FOR_EXECUTION,
    ];
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L248-254)
```typescript
  @Patch('/cancel/:id')
  async cancelTransaction(
    @GetUser() user,
    @Param('id', ParseIntPipe) id: number,
  ): Promise<boolean> {
    return this.transactionsService.cancelTransaction(id, user);
  }
```
