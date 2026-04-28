### Title
TOCTOU Race Condition in `archiveTransaction` Allows Overwriting `EXECUTED` Status with `ARCHIVED`

### Summary
`archiveTransaction` in `back-end/apps/api/src/transactions/transactions.service.ts` reads the transaction status, validates it, then issues an unconditional `UPDATE` without re-asserting the old status in the `WHERE` clause. Between the read and the write, the chain service can concurrently execute the transaction and set its status to `EXECUTED`. The archive `UPDATE` then blindly overwrites `EXECUTED` with `ARCHIVED`, corrupting the transaction's recorded state while the on-chain execution has already occurred.

### Finding Description

**Root cause — missing status guard in the UPDATE:**

In `archiveTransaction` (line 708–733), the flow is:

1. `getTransactionForCreator` reads the row and checks `status ∈ {WAITING_FOR_SIGNATURES, WAITING_FOR_EXECUTION}` (or `isManual`).
2. If the check passes, `this.repo.update({ id }, { status: TransactionStatus.ARCHIVED })` is issued — with **no** `AND status = :oldStatus` predicate. [1](#0-0) 

**Contrast with the correctly-guarded `cancelTransactionWithOutcome`:**

```typescript
.andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
``` [2](#0-1) 

The cancel path uses an atomic conditional update; the archive path does not.

**Concurrent chain-service execution path:**

The chain service's `_executeTransaction` correctly guards its own update:

```typescript
.where('id = :id AND status = :currentStatus', {
  id: transaction.id,
  currentStatus: TransactionStatus.WAITING_FOR_EXECUTION,
})
``` [3](#0-2) 

This means the chain service wins the race if it runs first (its update succeeds, status → `EXECUTED`). The archive `UPDATE` then runs second and overwrites `EXECUTED` → `ARCHIVED` with no guard to stop it.

**Exposed HTTP endpoint:**

```
PATCH /transactions/archive/:id
``` [4](#0-3) 

Any authenticated transaction creator can reach this path.

### Impact Explanation

A transaction that was successfully executed on the Hedera network ends up recorded as `ARCHIVED` in the database. The `executedAt` and `statusCode` columns retain their values from the chain service's earlier write, but the `status` field is wrong. Downstream consumers (notification service, front-end, audit logs) observe `ARCHIVED` and never surface the execution result to the user. The user believes the transaction was archived (i.e., abandoned), while it was actually submitted and settled on-chain. This is a persistent state-integrity failure: the database record is permanently inconsistent with the on-chain reality.

### Likelihood Explanation

The race window is the latency between the chain service's execution update and the API's archive update. A transaction in `WAITING_FOR_EXECUTION` is scheduled to execute at its `validStart` time; the chain service fires a timeout callback 10 seconds before `validStart`. A user who clicks "Archive" in the UI in that 10-second window — or who sends the API request programmatically — can trigger the race. No special privileges are required beyond being the transaction creator. The front-end exposes the archive button for transactions in `WAITING_FOR_EXECUTION` state, making accidental triggering realistic. [5](#0-4) 

### Recommendation

Replace the unconditional `repo.update` with a conditional query builder update that asserts the expected old status, mirroring the pattern used in `cancelTransactionWithOutcome`:

```typescript
const archivableStatuses = [
  TransactionStatus.WAITING_FOR_SIGNATURES,
  TransactionStatus.WAITING_FOR_EXECUTION,
];

const result = await this.repo
  .createQueryBuilder()
  .update(Transaction)
  .set({ status: TransactionStatus.ARCHIVED })
  .where('id = :id', { id })
  .andWhere('(status IN (:...statuses) OR "isManual" = true)', {
    statuses: archivableStatuses,
  })
  .execute();

if (!result.affected || result.affected === 0) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

This makes the check-and-set atomic at the database level, eliminating the TOCTOU window.

### Proof of Concept

1. Create a transaction with `isManual: false` that has sufficient signatures → status transitions to `WAITING_FOR_EXECUTION`.
2. The chain service schedules execution ~10 s before `validStart`.
3. At `validStart − 9s`, send `PATCH /transactions/archive/:id` as the creator.
4. The chain service's execution update fires concurrently, setting `status = EXECUTED`, `executedAt = now`, `statusCode = 22` (OK).
5. The archive `UPDATE` (no status guard) runs immediately after and sets `status = ARCHIVED`.
6. Query the database: `status = ARCHIVED`, `executedAt` is set, `statusCode = 22` — the record is inconsistent. The front-end shows the transaction as archived; the Hedera network shows it as executed. [6](#0-5) [7](#0-6)

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

**File:** back-end/libs/common/src/execute/execute.service.ts (L187-198)
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

    if (updateResult.raw.length === 0) return null;
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L264-270)
```typescript
  @Patch('/archive/:id')
  async archiveTransaction(
    @GetUser() user,
    @Param('id', ParseIntPipe) id: number,
  ): Promise<boolean> {
    return this.transactionsService.archiveTransaction(id, user);
  }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L326-327)
```typescript
    const timeout = setTimeout(callback, timeToValidStart - 10 * 1_000);
    this.schedulerRegistry.addTimeout(name, timeout);
```
