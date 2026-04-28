All code references verified. The vulnerability is real and confirmed by the source.

---

Audit Report

## Title
TOCTOU Race Condition in `archiveTransaction` Allows Overwriting Terminal Transaction States

## Summary
`archiveTransaction` in `TransactionsService` performs a read-validate-write sequence without atomicity. The `UPDATE` at line 720 carries no status guard in its `WHERE` clause, so if the chain service's cron jobs transition the transaction to a terminal state (`EXPIRED`, `EXECUTED`, or `FAILED`) between the read and the write, the archive write silently overwrites that terminal state with `ARCHIVED`, permanently corrupting the audit record.

## Finding Description

**Root cause — unconditional UPDATE in `archiveTransaction`**

`archiveTransaction` follows a read-check-write pattern:

Step 1 — read and validate (lines 709–718):
```typescript
const transaction = await this.getTransactionForCreator(id, user);
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  ) && !transaction.isManual
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
``` [1](#0-0) 

Step 2 — unconditional write (line 720):
```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [2](#0-1) 

There is no `AND status IN (...)` guard in the `WHERE` clause. Whatever status is present at write time is overwritten.

**Contrast with the safe pattern used elsewhere**

`cancelTransactionWithOutcome` (lines 673–679) uses a status guard so the update is a no-op if the status changed concurrently:
```typescript
.andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
``` [3](#0-2) 

`_executeTransaction` (lines 187–196 of `execute.service.ts`) does the same:
```typescript
.where('id = :id AND status = :currentStatus', {
  id: transaction.id,
  currentStatus: TransactionStatus.WAITING_FOR_EXECUTION,
})
``` [4](#0-3) 

`archiveTransaction` has no equivalent guard.

**Concurrent state changers that create the race window**

`handleExpiredTransactions` runs every 10 seconds and bulk-sets `EXPIRED` for any transaction in `WAITING_FOR_SIGNATURES`, `WAITING_FOR_EXECUTION`, `NEW`, or `REJECTED` whose `validStart < now - 3 min`: [5](#0-4) 

`handleTransactionsBetweenNowAndAfterThreeMinutes` also runs every 10 seconds and calls `prepareTransactions` → `collateAndExecute` → `executeTransaction`, which can set `EXECUTED` or `FAILED`: [6](#0-5) 

Both cron jobs run in the `chain` microservice process. The `@MurLock` on `executeTransaction` coordinates only between multiple execution pods — it does not coordinate with the API service's `archiveTransaction`. [7](#0-6) 

## Impact Explanation

A transaction that was successfully executed on the Hedera network (status `EXECUTED`), expired (status `EXPIRED`), or failed (status `FAILED`) has its terminal state permanently overwritten with `ARCHIVED`. Consequences:

- **Audit trail corruption**: The organization loses the authoritative record that the transaction was executed on-chain. The `executedAt` timestamp and `statusCode` remain in the DB but the `status` field no longer reflects reality.
- **Operational confusion**: Users and downstream integrations that rely on `status = EXECUTED` to confirm on-chain settlement will instead see `ARCHIVED`, potentially triggering duplicate submission attempts.
- **Irreversibility**: There is no recovery path; the terminal state is gone.

## Likelihood Explanation

The race window is narrow but mechanically guaranteed to exist. The chain service cron jobs run every 10 seconds in a separate NestJS process with no distributed lock coordinating with the API service. Any transaction near its `validStart` boundary is at risk on every archive call. No attacker privilege beyond being the transaction creator is required — this is a normal authenticated API call. A transaction creator who routinely archives transactions near their execution window will eventually trigger this.

## Recommendation

Replace the unconditional `repo.update` in `archiveTransaction` with a guarded query builder update, mirroring the pattern already used in `cancelTransactionWithOutcome`:

```typescript
// back-end/apps/api/src/transactions/transactions.service.ts
const archivableStatuses = [
  TransactionStatus.WAITING_FOR_SIGNATURES,
  TransactionStatus.WAITING_FOR_EXECUTION,
];

const updateResult = await this.repo
  .createQueryBuilder()
  .update(Transaction)
  .set({ status: TransactionStatus.ARCHIVED })
  .where('id = :id', { id })
  .andWhere(
    new Brackets(qb =>
      qb
        .where('status IN (:...statuses)', { statuses: archivableStatuses })
        .orWhere('"isManual" = true'),
    ),
  )
  .execute();

if (!updateResult.affected || updateResult.affected === 0) {
  throw new ConflictException('Transaction state changed; archive aborted.');
}
```

This makes the write a no-op if the status was concurrently changed to a terminal state, eliminating the race window.

## Proof of Concept

1. Create transaction T with `validStart` set to `now + 10 seconds` and ensure it reaches `WAITING_FOR_EXECUTION` state.
2. Wait until `validStart` is approximately 2 minutes 55 seconds in the past (approaching the 3-minute expiry boundary).
3. As the transaction creator, call `PATCH /transactions/archive/:id`.
4. `getTransactionForCreator` returns `status = WAITING_FOR_EXECUTION` — the status check at lines 711–718 passes.
5. Within the same ~10-second cron window, `handleExpiredTransactions` fires and issues:
   ```sql
   UPDATE transactions SET status = 'EXPIRED'
   WHERE status IN ('NEW','REJECTED','WAITING_FOR_EXECUTION','WAITING_FOR_SIGNATURES')
     AND validStart < now() - interval '3 minutes'
   ```
   T's status is now `EXPIRED`.
6. `archiveTransaction` resumes and issues:
   ```sql
   UPDATE transactions SET status = 'ARCHIVED' WHERE id = :id
   ```
   No status guard — `EXPIRED` is overwritten with `ARCHIVED`.
7. Query the DB: `status = ARCHIVED`, but the transaction expired on-chain. The terminal state is permanently lost.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L673-679)
```typescript
    const updateResult = await this.repo
      .createQueryBuilder()
      .update(Transaction)
      .set({ status: TransactionStatus.CANCELED })
      .where('id = :id', { id })
      .andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
      .execute();
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L708-720)
```typescript
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
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L41-42)
```typescript
  @MurLock(15000, 'transaction.id')
  async executeTransaction(transaction: Transaction) {
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L187-196)
```typescript
    const updateResult = await this.transactionsRepo
      .createQueryBuilder()
      .update(Transaction)
      .set({ status: transactionStatus, executedAt, statusCode: transactionStatusCode })
      .where('id = :id AND status = :currentStatus', {
        id: transaction.id,
        currentStatus: TransactionStatus.WAITING_FOR_EXECUTION,
      })
      .returning('id')
      .execute();
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L87-97)
```typescript
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
