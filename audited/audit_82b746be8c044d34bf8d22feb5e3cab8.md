### Title
TOCTOU Race Condition in `archiveTransaction` Allows Overwriting Terminal Transaction Status

### Summary
`archiveTransaction` in `TransactionsService` reads the transaction status, validates it, then issues an unconditional `UPDATE` with no `WHERE` guard on the current status. A concurrent scheduler execution that transitions the transaction to `EXECUTED` (or `FAILED`/`EXPIRED`) between the read and the write will have its terminal status silently overwritten with `ARCHIVED`, corrupting the audit trail and suppressing execution notifications.

### Finding Description
In `back-end/apps/api/src/transactions/transactions.service.ts`, `archiveTransaction` follows a classic check-then-act pattern without an atomic guard:

```typescript
// Step 1 – read
const transaction = await this.getTransactionForCreator(id, user);

// Step 2 – validate (on stale snapshot)
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION]
    .includes(transaction.status) &&
  !transaction.isManual
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}

// Step 3 – unconditional write (no WHERE on current status)
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [1](#0-0) 

The `repo.update({ id }, ...)` call at line 720 uses only the primary key as the predicate. It will succeed and overwrite whatever status the row currently holds — including `EXECUTED`, `FAILED`, or `EXPIRED` — with `ARCHIVED`.

The sibling method `cancelTransactionWithOutcome` was written with explicit race-safety: it adds `AND status IN (:...statuses)` to the `UPDATE` and even carries a comment *"Race-safe fallback: state changed between read and update"*:

```typescript
const updateResult = await this.repo
  .createQueryBuilder()
  .update(Transaction)
  .set({ status: TransactionStatus.CANCELED })
  .where('id = :id', { id })
  .andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
  .execute();
``` [2](#0-1) 

`archiveTransaction` received no equivalent protection.

The scheduler executes transactions automatically via `addExecutionTimeout` → `executeService.executeTransaction`, which fires at `validStart + 5 s`. The window between the status read in `archiveTransaction` and the unconditional write is wide enough for the scheduler to complete execution and set the status to `EXECUTED` before the archive write lands. [3](#0-2) 

### Impact Explanation
- The `EXECUTED` (or `FAILED`/`EXPIRED`) status is overwritten with `ARCHIVED`. The Hedera network has already processed the transaction, but the back-end database no longer reflects that fact.
- `emitTransactionStatusUpdate` is called with the archive event, so downstream consumers (notifications service, WebSocket clients) receive an `ARCHIVED` signal instead of an `EXECUTED` one — suppressing execution receipts and status-change emails.
- The transaction disappears from the "history" view (which filters on terminal statuses like `EXECUTED`/`FAILED`) and reappears only as an archived record, breaking the audit trail.
- A creator can exploit this deliberately: submit a transaction, wait for it to reach `WAITING_FOR_EXECUTION`, then race `archiveTransaction` against the scheduler to hide the on-chain result.

### Likelihood Explanation
The race window is bounded by the time between the `getTransactionForCreator` DB read and the `repo.update` write — typically tens of milliseconds. The scheduler fires at a predictable time (`validStart + 5 s`), so a creator who knows the `validStart` can time the API call deliberately. In a multi-pod deployment the window is wider because the scheduler pod and the API pod operate independently. The condition is therefore realistic and intentionally triggerable.

### Recommendation
Mirror the pattern already used in `cancelTransactionWithOutcome`: add a `WHERE status IN (...)` guard to the `UPDATE` so the write is a no-op if the status has already transitioned:

```typescript
const result = await this.repo
  .createQueryBuilder()
  .update(Transaction)
  .set({ status: TransactionStatus.ARCHIVED })
  .where('id = :id', { id })
  .andWhere('status IN (:...archivableStatuses)', {
    archivableStatuses: [
      TransactionStatus.WAITING_FOR_SIGNATURES,
      TransactionStatus.WAITING_FOR_EXECUTION,
    ],
  })
  .returning('id')
  .execute();

if (!result.raw.length) {
  throw new BadRequestException(ErrorCodes.OMTIP); // status changed concurrently
}
```

For `isManual` transactions the allowed-status list should be expanded accordingly, but the guard must still be present.

### Proof of Concept

1. Creator submits a non-manual transaction with `validStart = T`.
2. Scheduler transitions it to `WAITING_FOR_EXECUTION` at `T − 3 min`.
3. At `T − ε` the creator calls `PATCH /transactions/:id/archive`.
4. `getTransactionForCreator` returns status `WAITING_FOR_EXECUTION` → validation passes.
5. At `T + 5 s` the scheduler calls `executeService.executeTransaction`; the Hedera network accepts the transaction; `_executeTransaction` issues `UPDATE … SET status = 'EXECUTED' WHERE id = :id AND status = 'WAITING_FOR_EXECUTION'` — this succeeds first.
6. Milliseconds later, `archiveTransaction`'s `repo.update({ id }, { status: 'ARCHIVED' })` lands — no status guard — and overwrites `EXECUTED` with `ARCHIVED`.
7. The `emitTransactionStatusUpdate` call broadcasts `ARCHIVED`, suppressing the execution receipt notification. The DB row now shows `ARCHIVED` while the Hedera ledger shows the transaction as executed. [4](#0-3) [5](#0-4)

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

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L352-373)
```typescript
  addExecutionTimeout(transaction: Transaction) {
    const name = `execution_timeout_${transaction.id}`;

    if (this.schedulerRegistry.doesExist('timeout', name)) return;

    if (transaction.isManual) return;

    const timeToValidStart = transaction.validStart.getTime() - Date.now();

    const callback = async () => {
      try {
        await this.executeService.executeTransaction(transaction);
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
