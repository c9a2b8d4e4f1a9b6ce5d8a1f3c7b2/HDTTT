All code references verified. The vulnerability is real and confirmed.

---

# Audit Report

## Title
TOCTOU Race Condition in `archiveTransaction` Allows Overwriting `EXECUTED` Status with `ARCHIVED`

## Summary
`archiveTransaction` in `back-end/apps/api/src/transactions/transactions.service.ts` performs a status check followed by an unconditional `UPDATE` with no status predicate in the `WHERE` clause. The chain service's `_executeTransaction` can concurrently win the race and set status to `EXECUTED`; the archive `UPDATE` then blindly overwrites `EXECUTED` → `ARCHIVED`, permanently corrupting the transaction's recorded state.

## Finding Description

**Root cause — unconditional UPDATE in `archiveTransaction`:**

The function reads the row, validates the status, then issues:

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [1](#0-0) 

The `WHERE` clause contains only `id = :id` — no `AND status IN (...)` guard. Any status present at read-time can be overwritten at write-time.

**Contrast with the correctly-guarded `cancelTransactionWithOutcome`:**

```typescript
.andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
``` [2](#0-1) 

The cancel path uses an atomic conditional update and checks `affected > 0` to detect a lost race. The archive path has neither.

**Chain service uses a guarded update AND a distributed lock:**

`_executeTransaction` guards its own write:

```typescript
.where('id = :id AND status = :currentStatus', {
  id: transaction.id,
  currentStatus: TransactionStatus.WAITING_FOR_EXECUTION,
})
``` [3](#0-2) 

`executeTransaction` is also decorated with `@MurLock(15000, 'transaction.id')`: [4](#0-3) 

`archiveTransaction` acquires no lock and holds no status predicate, so it is entirely outside the chain service's mutual-exclusion boundary.

**Exposed HTTP endpoint:**

```
PATCH /transactions/archive/:id
``` [5](#0-4) 

## Impact Explanation

A transaction that was successfully executed on the Hedera network ends up recorded as `ARCHIVED` in the database. The `executedAt` and `statusCode` columns retain the values written by the chain service, but the `status` field is wrong. Downstream consumers — the notification service, front-end, and audit logs — observe `ARCHIVED` and never surface the execution result to the user. The user believes the transaction was abandoned, while it was actually submitted and settled on-chain. This is a persistent state-integrity failure: the database record is permanently inconsistent with on-chain reality, and there is no self-healing path.

## Likelihood Explanation

The race window is the latency between the chain service's execution update and the API's archive update. The chain service fires a timeout callback 10 seconds before `validStart`; a transaction in `WAITING_FOR_EXECUTION` is therefore in the vulnerable window for up to ~10 seconds. A user who clicks "Archive" in the UI during that window — or who sends the API request programmatically — triggers the race. No special privileges are required beyond being the transaction creator. The front-end exposes the archive button for transactions in `WAITING_FOR_EXECUTION` state, making accidental triggering realistic without any adversarial intent.

## Recommendation

Apply the same atomic conditional-update pattern used in `cancelTransactionWithOutcome`. Replace the unconditional `repo.update` call with a query-builder update that includes a status predicate, and treat zero affected rows as a conflict:

```typescript
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
    '(status IN (:...statuses) OR "isManual" = true)',
    { statuses: archivableStatuses },
  )
  .execute();

if (!updateResult.affected || updateResult.affected === 0) {
  // Re-read to return a meaningful error
  const latest = await this.getTransactionForCreator(id, user);
  throw new BadRequestException(/* appropriate error code */);
}
```

This makes the read-check and the write atomic at the database level, eliminating the TOCTOU window entirely.

## Proof of Concept

1. Create a transaction; let it reach `WAITING_FOR_EXECUTION` status.
2. At `T=0` (within the 10-second pre-`validStart` window), the chain service begins executing: it calls `sdkTransaction.execute(client)` and awaits the receipt — this takes non-zero time.
3. At `T=1ms`, the transaction creator sends `PATCH /transactions/archive/:id`.
4. `archiveTransaction` calls `getTransactionForCreator` — reads `status = WAITING_FOR_EXECUTION` — check passes.
5. At `T=500ms`, the chain service's `_executeTransaction` completes and issues its guarded UPDATE: `status → EXECUTED`. Row is now `EXECUTED`.
6. At `T=501ms`, `archiveTransaction` issues `repo.update({ id }, { status: ARCHIVED })` — no guard — row becomes `ARCHIVED`.
7. Database now shows `status = ARCHIVED`, `executedAt = <real timestamp>`, `statusCode = <success code>` — permanently inconsistent with on-chain reality.

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
