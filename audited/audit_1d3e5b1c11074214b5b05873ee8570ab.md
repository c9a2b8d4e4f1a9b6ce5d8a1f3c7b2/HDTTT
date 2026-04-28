### Title
`handleExpiredTransactions` Uses Hardcoded 3-Minute Window Instead of Actual `validDuration`, Causing Incorrect Transaction State

### Summary
The `handleExpiredTransactions` scheduler and `isValidStartExecutable` guard both use a hardcoded 3-minute cutoff (`getThreeMinutesBefore()`) to determine whether a Hedera transaction has expired. However, Hedera transactions carry their own `transactionValidDuration` field, which can be shorter than 3 minutes. This creates a window during which a transaction is already expired on the Hedera network but is still treated as active by the system — the direct analog of the external report's `block.timestamp` vs. `expiry` confusion.

### Finding Description
The `isExpired` utility correctly computes expiry as `validStart + validDuration`:

```typescript
// back-end/libs/common/src/utils/sdk/transaction.ts, lines 37-46
export const isExpired = (transaction: SDKTransaction) => {
  const validStart = transaction.transactionId.validStart.toDate();
  const duration = transaction.transactionValidDuration;
  return new Date().getTime() >= validStart.getTime() + duration * 1_000;
};
``` [1](#0-0) 

However, the scheduled expiry job ignores `validDuration` entirely and instead uses a hardcoded 3-minute constant:

```typescript
// back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts, lines 103-118
async handleExpiredTransactions() {
  const result = await this.transactionRepo
    .createQueryBuilder()
    .update(Transaction)
    .set({ status: TransactionStatus.EXPIRED })
    .where('status IN (:...statuses) AND validStart < :before', {
      statuses: [...],
      before: this.getThreeMinutesBefore(),   // ← always now - 180 s
    })
    .execute();
``` [2](#0-1) 

The same hardcoded window governs `isValidStartExecutable`, which decides whether the scheduler should attempt execution:

```typescript
isValidStartExecutable(validStart: Date) {
  const threeMinutesBefore = this.getThreeMinutesBefore().getTime();
  const now = Date.now();
  const time = validStart.getTime();
  return time >= threeMinutesBefore && time <= now;   // ← 3-min window, not validDuration
}
``` [3](#0-2) 

Hedera's default `transactionValidDuration` is **120 seconds** (2 minutes); the maximum is 180 seconds (3 minutes). A transaction created with `validDuration = 60 s` expires on the Hedera network at `validStart + 60 s`, but the system will not mark it `EXPIRED` until `validStart + 180 s` — a 2-minute gap. During that gap:

1. `isValidStartExecutable` returns `true` for the already-expired transaction.
2. `prepareTransactions` schedules it for execution via `collateAndExecute` / `addExecutionTimeout`.
3. The Hedera network rejects the submission with `TRANSACTION_EXPIRED`.
4. The transaction is recorded as **`FAILED`** (with status code 4) rather than **`EXPIRED`**. [4](#0-3) 

### Impact Explanation
- Transactions that have already expired on the Hedera network remain in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` state for up to 2 extra minutes.
- The scheduler submits these transactions to Hedera, which rejects them; the final recorded status is `FAILED` instead of `EXPIRED`, corrupting audit trails and notification logic that distinguishes the two terminal states.
- Any downstream logic that branches on `EXPIRED` vs. `FAILED` (e.g., retry policies, user-facing error messages, analytics) will receive incorrect data.

### Likelihood Explanation
Any authenticated user can create a transaction with a `transactionValidDuration` shorter than 180 seconds (the Hedera SDK allows values as low as 1 second). No privileged access is required. The cron job runs every 10 seconds, so the incorrect state is observable on every polling cycle during the gap window.

### Recommendation
Replace the hardcoded `getThreeMinutesBefore()` cutoff in `handleExpiredTransactions` with a per-row comparison that uses the actual stored `validDuration`. Store `validDuration` alongside `validStart` in the `Transaction` entity (it is already parsed from the SDK bytes during `validateAndPrepareTransaction`) and use a database expression such as:

```sql
WHERE status IN (...) AND (validStart + validDuration * interval '1 second') < NOW()
```

Similarly, update `isValidStartExecutable` to accept and use the transaction's `validDuration` rather than the hardcoded 3-minute constant, mirroring the correct logic already present in `isExpired`. [1](#0-0) 

### Proof of Concept
1. Create a Hedera transaction with `transactionValidDuration = 60` seconds and `validStart = T`.
2. Upload it to the API; it is stored with `status = WAITING_FOR_EXECUTION`.
3. At `T + 61 s` the transaction is expired on Hedera; `isExpired()` returns `true`.
4. At `T + 65 s` the 10-second cron (`handleTransactionsBetweenNowAndAfterThreeMinutes`) fires; `isValidStartExecutable` returns `true` because `validStart` is within the 3-minute window.
5. `collateAndExecute` schedules an execution timeout; the transaction is submitted to Hedera.
6. Hedera returns `TRANSACTION_EXPIRED`; the system sets `status = FAILED` with `statusCode = 4`.
7. At `T + 180 s` `handleExpiredTransactions` would have set `status = EXPIRED`, but the row is already `FAILED` — the correct terminal state is never reached. [5](#0-4) [6](#0-5)

### Citations

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L37-46)
```typescript
export const isExpired = (transaction: SDKTransaction) => {
  if (!transaction.transactionId?.validStart) {
    return true;
  }

  const validStart = transaction.transactionId.validStart.toDate();
  const duration = transaction.transactionValidDuration;

  return new Date().getTime() >= validStart.getTime() + duration * 1_000;
};
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L86-97)
```typescript
  /* For transactions with valid start between currently valid and 3 minutes */
  @Cron(CronExpression.EVERY_10_SECONDS, {
    name: 'status_update_between_now_and_three_minutes',
  })
  async handleTransactionsBetweenNowAndAfterThreeMinutes() {
    const transactions = await this.updateTransactions(
      this.getThreeMinutesBefore(),
      this.getThreeMinutesLater(),
    );

    await this.prepareTransactions(transactions);
  }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L103-118)
```typescript
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
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L163-198)
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
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L271-328)
```typescript
  collateAndExecute(transaction: Transaction) {
    const name = `smart_collate_timeout_${transaction.id}`;

    if (this.schedulerRegistry.doesExist('timeout', name)) return;

    const timeToValidStart = transaction.validStart.getTime() - Date.now();

    const callback = async () => {
      try {
        const requiredKeys = await this.transactionSignatureService.computeSignatureKey(transaction);

        const sdkTransaction = await smartCollate(transaction, requiredKeys);

        // If the transaction is still too large,
        // set it to failed with the TRANSACTION_OVERSIZE status code
        // update the transaction, emit the event, and delete the timeout
        if (sdkTransaction === null) {
          const result = await this.transactionRepo
            .createQueryBuilder()
            .update(Transaction)
            .set({
              status: TransactionStatus.FAILED,
              executedAt: new Date(),
              statusCode: Status.TransactionOversize._code,
            })
            .where('id = :id AND status = :currentStatus', {
              id: transaction.id,
              currentStatus: TransactionStatus.WAITING_FOR_EXECUTION,
            })
            .returning('id')
            .execute();

          if (result.raw.length > 0) {
            emitTransactionStatusUpdate(
              this.notificationsPublisher,
              result.raw.map(row => ({ entityId: row.id })),
            );
          }
          return;
        }

        // TODO then make sure that front end doesn't allow chunks larger than 2k'
        //NOTE: the transactionBytes are set here but are not to be saved. Otherwise,
        // any signatures that were removed in order to make the transaction fit
        // would be lost.
        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());

        this.addExecutionTimeout(transaction);
      } catch (error) {
        console.log(error);
      } finally {
        this.schedulerRegistry.deleteTimeout(name);
      }
    };

    const timeout = setTimeout(callback, timeToValidStart - 10 * 1_000);
    this.schedulerRegistry.addTimeout(name, timeout);
  }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L399-404)
```typescript
  isValidStartExecutable(validStart: Date) {
    const threeMinutesBefore = this.getThreeMinutesBefore().getTime();
    const now = Date.now();
    const time = validStart.getTime();
    return time >= threeMinutesBefore && time <= now;
  }
```
