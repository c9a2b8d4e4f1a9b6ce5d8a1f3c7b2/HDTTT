I have all the code I need. Let me analyze the claim against the actual implementation.

Audit Report

## Title
TOCTOU Race Condition in `archiveTransaction` Allows Overwriting Terminal Execution State

## Summary
`archiveTransaction` in `transactions.service.ts` performs a read-check-write sequence where the `UPDATE` at line 720 uses only `{ id }` as the filter, with no re-assertion of the transaction status in the `WHERE` clause. Between the status read and the unconditional write, the chain service can execute the transaction on the Hedera network and set the status to `EXECUTED`. The subsequent unconditional update then overwrites `EXECUTED` with `ARCHIVED`, permanently corrupting the database record while the transaction has already settled on-chain.

## Finding Description

**Root cause — `archiveTransaction`:** [1](#0-0) 

The function reads the transaction status at line 709, validates it at lines 711–718, then issues an unconditional `repo.update({ id }, { status: ARCHIVED })` at line 720. The `WHERE` clause contains only the primary key — it will match the row regardless of what status it currently holds at write time.

Every other status-mutating path in the codebase guards against this with an atomic conditional `WHERE`:

- `cancelTransactionWithOutcome` — `.andWhere('status IN (:...statuses)', ...)` [2](#0-1) 
- `_executeTransaction` — `.where('id = :id AND status = :currentStatus', ...)` [3](#0-2) 
- `collateAndExecute` (oversize failure path) — `.where('id = :id AND status = :currentStatus', ...)` [4](#0-3) 

`archiveTransaction` is the only status-mutating path that omits this guard.

**Concurrent execution path:**

The chain service schedules execution via `collateAndExecute` → `addExecutionTimeout` → `executeService.executeTransaction`. `addExecutionTimeout` fires at `validStart + 5 seconds`. [5](#0-4) 

`executeTransaction` in `execute.service.ts` first calls `getValidatedSDKTransaction` (which re-reads status via `validateTransactionStatus`), then submits to the Hedera SDK, then performs the conditional `WHERE status = WAITING_FOR_EXECUTION` update. [6](#0-5) 

The `@MurLock` on `executeTransaction` only serializes concurrent calls to `executeTransaction` itself — it does not prevent `archiveTransaction` from running concurrently, since `archiveTransaction` acquires no lock.

**Two exploitable interleavings:**

1. **Archive wins the race first:** `archiveTransaction` writes `ARCHIVED` → `validateTransactionStatus` in `executeTransaction` re-reads the DB, sees `ARCHIVED`, and throws (line 246 of `execute.service.ts`). The SDK transaction is never submitted. DB correctly shows `ARCHIVED`. This direction is self-correcting. [7](#0-6) 

2. **Execute wins the race first (the damaging case):** `_executeTransaction` submits the SDK transaction to Hedera and writes `EXECUTED` (with `executedAt`, `statusCode`, `receiptBytes`) via the conditional WHERE. Then `archiveTransaction`'s unconditional `repo.update({ id }, { status: ARCHIVED })` fires and overwrites `EXECUTED` with `ARCHIVED`, erasing all execution metadata. The on-chain effect is permanent; the DB record is corrupted. [8](#0-7) 

## Impact Explanation

1. **State corruption / loss of execution record:** A transaction that settled on the Hedera ledger is permanently recorded as `ARCHIVED`. `executedAt`, `statusCode`, and `receiptBytes` are lost — they are written by `_executeTransaction` only when the conditional WHERE succeeds, and then immediately overwritten by the unconditional archive update.
2. **Integrity divergence:** The system's view of the transaction lifecycle permanently diverges from the actual Hedera network state. Observers, approvers, and auditors see `ARCHIVED` for a transaction that moved real assets or created accounts on-chain.
3. **Unrecoverable:** The system has no automated reconciliation path to re-query Hedera and correct the record once the row is overwritten.

## Likelihood Explanation

**Attacker preconditions:**
- Must be the authenticated creator of the transaction (a normal registered user — no elevated privilege required).
- Must call `PATCH /transactions/archive/{id}` within the execution window around `validStart + 5 seconds`.

The window is deterministic: `addExecutionTimeout` schedules execution at exactly `validStart + 5 seconds` via `setTimeout`. The `validStart` value is returned in the API response for the transaction. A creator who knows their own transaction's `validStart` can time the archive call precisely. No brute-force or guessing is needed. The race window spans the duration of the Hedera network round-trip (typically hundreds of milliseconds to a few seconds), which is wide enough to be reliably exploitable with a scripted client.

## Recommendation

Replace the unconditional `repo.update` in `archiveTransaction` with an atomic conditional query builder update that re-asserts the expected status in the `WHERE` clause, consistent with the pattern already used in `cancelTransactionWithOutcome` and `_executeTransaction`:

```typescript
const updateResult = await this.repo
  .createQueryBuilder()
  .update(Transaction)
  .set({ status: TransactionStatus.ARCHIVED })
  .where('id = :id', { id })
  .andWhere('status IN (:...statuses)', {
    statuses: [
      TransactionStatus.WAITING_FOR_SIGNATURES,
      TransactionStatus.WAITING_FOR_EXECUTION,
    ],
  })
  .execute();

if (!updateResult.affected || updateResult.affected === 0) {
  throw new ConflictException('Transaction status changed before archive could complete');
}
```

This ensures the update is a no-op if the status has already transitioned to `EXECUTED` (or any other terminal state) between the read and the write.

## Proof of Concept

```
1. Creator creates a non-manual transaction with validStart = T.
2. Chain service schedules execution at T + 5s via addExecutionTimeout.
3. At T + 5s - ε, creator sends PATCH /transactions/archive/{id}.
   - archiveTransaction reads status = WAITING_FOR_EXECUTION ✓
   - archiveTransaction passes the status check
   - [async gap — network I/O, DB round-trip]
4. At T + 5s, addExecutionTimeout fires:
   - executeTransaction → getValidatedSDKTransaction → validateTransactionStatus
     reads status = WAITING_FOR_EXECUTION ✓ (archive update not yet committed)
   - sdkTransaction.execute(client) submits to Hedera — on-chain effect is real
   - _executeTransaction writes: UPDATE ... SET status=EXECUTED, executedAt=...,
     statusCode=..., receiptBytes=... WHERE id=X AND status=WAITING_FOR_EXECUTION
     → 1 row affected
5. archiveTransaction resumes:
   - repo.update({ id: X }, { status: ARCHIVED })
     → WHERE id=X only — matches the row regardless of current status
     → overwrites EXECUTED with ARCHIVED
     → executedAt, statusCode, receiptBytes are lost
6. DB record: status=ARCHIVED, executedAt=null, statusCode=null, receiptBytes=null
   Hedera ledger: transaction executed and finalized
```

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

**File:** back-end/libs/common/src/execute/execute.service.ts (L41-60)
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

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L288-301)
```typescript
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
