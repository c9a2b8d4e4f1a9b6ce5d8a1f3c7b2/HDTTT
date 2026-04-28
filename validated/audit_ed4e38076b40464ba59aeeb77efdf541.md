Audit Report

## Title
TOCTOU in `uploadSignatureMaps`: Stale Status Read Allows `transactionBytes` Mutation on Terminal-State Transactions

## Summary
`SignersService.uploadSignatureMaps` reads transaction status, validates it, then writes updated `transactionBytes` and inserts `TransactionSigner` records as separate, non-atomic steps with no status guard in the final SQL `UPDATE`. A concurrent state transition (execution, cancellation) between the status check and the DB write causes `bulkUpdateTransactions` to unconditionally overwrite `transactionBytes` of a transaction that is now in a terminal state, corrupting the audit record.

## Finding Description

**Root cause — non-atomic read-validate-write in `uploadSignatureMaps`:**

`loadTransactionData` performs a plain `find` with no row-level locking:

```typescript
// signers.service.ts:131-133
const transactions = await this.dataSource.manager.find(Transaction, {
  where: { id: In(transactionIds) },
});
``` [1](#0-0) 

`validateTransactionStatus` checks the stale snapshot:

```typescript
// signers.service.ts:201-207
if (
  transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
  transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
) {
  return ErrorCodes.TNRS;
}
``` [2](#0-1) 

Then `bulkUpdateTransactions` writes unconditionally — **no status guard in the WHERE clause**:

```typescript
// signers.service.ts:365-371
await manager.query(
  `UPDATE transaction
   SET "transactionBytes" = CASE id ${whenClauses} END,
       "updatedAt" = NOW()
   WHERE id = ANY($${bytes.length + 1})`,
  [...bytes, ids]
);
``` [3](#0-2) 

Although `persistSignatureChanges` wraps the DB writes in a `dataSource.transaction(...)` block, the status validation occurs entirely **outside** that transaction (in `validateAndProcessSignatures`, called before `persistSignatureChanges`), so the database transaction provides no protection against the race. [4](#0-3) 

Compare this to the correctly guarded update in `_executeTransaction`:

```typescript
// execute.service.ts:187-196
.where('id = :id AND status = :currentStatus', {
  id: transaction.id,
  currentStatus: TransactionStatus.WAITING_FOR_EXECUTION,
})
``` [5](#0-4) 

And `cancelTransactionWithOutcome`:

```typescript
// transactions.service.ts:673-679
.where('id = :id', { id })
.andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
``` [6](#0-5) 

Additionally, `executeTransaction` is protected by a distributed `@MurLock(15000, 'transaction.id')`, but `uploadSignatureMaps` acquires no such lock, so it can race freely against the execution path. [7](#0-6) 

## Impact Explanation

The `transactionBytes` column of an `EXECUTED` transaction is the canonical record of what was submitted to Hedera. Overwriting it post-execution means the stored bytes diverge from on-chain reality, breaking any downstream verification, receipt reconciliation, or forensic audit that relies on this field. `TransactionSigner` records inserted for a terminal-state transaction also corrupt the signing history. This does not directly cause financial loss (the on-chain transaction is already settled), but it permanently corrupts the integrity of the organization's transaction records.

**Impact: Medium**

## Likelihood Explanation

The TOCTOU window exists in any multi-user organization scenario where:
- Multiple signers are uploading signatures concurrently, or
- The chain service's scheduler (`handleTransactionsBetweenNowAndAfterThreeMinutes`, running every 10 seconds) executes a transaction at the same moment a signer uploads.

No privileged access is required. Any authenticated user with a valid signing key for the transaction can trigger this path. The scheduler runs continuously, making the race window realistic under normal production load.

**Likelihood: Medium**

## Recommendation

Add a status guard to the `WHERE` clause of `bulkUpdateTransactions` so the update is a no-op if the transaction has already transitioned to a terminal state:

```sql
UPDATE transaction
SET "transactionBytes" = CASE id ${whenClauses} END,
    "updatedAt" = NOW()
WHERE id = ANY($${bytes.length + 1})
  AND status IN ('WAITING_FOR_SIGNATURES', 'WAITING_FOR_EXECUTION')
```

Additionally, move the status read inside the same database transaction as the write and use `SELECT ... FOR UPDATE` (pessimistic locking) to eliminate the TOCTOU window entirely:

```typescript
await this.dataSource.transaction(async manager => {
  const transactions = await manager.find(Transaction, {
    where: { id: In(ids) },
    lock: { mode: 'pessimistic_write' },
  });
  // validate status here, then write
});
```

This mirrors the pattern already correctly used in `_executeTransaction` and `cancelTransactionWithOutcome`.

## Proof of Concept

1. Transaction T is in `WAITING_FOR_EXECUTION` (fully signed, queued for submission).
2. Authenticated user U calls `POST /transactions/signers` → `uploadSignatureMaps([{id: T, signatureMap: ...}])`.
3. `loadTransactionData` snapshots `status = WAITING_FOR_EXECUTION`; `validateTransactionStatus` passes.
4. Concurrently, the chain service scheduler fires; `executeTransaction` acquires its `MurLock`, submits T to Hedera, and sets `status = EXECUTED` via the guarded update at `execute.service.ts:187-196`.
5. `persistSignatureChanges` → `bulkUpdateTransactions` fires: the raw SQL `UPDATE ... WHERE id = ANY(...)` has no status guard and overwrites `transactionBytes` of the now-`EXECUTED` transaction with the signature-augmented bytes.
6. `bulkInsertSigners` inserts a `TransactionSigner` row for the already-executed transaction.

**Result:** The `transactionBytes` column of the executed transaction no longer matches the bytes actually submitted to Hedera. The audit record is permanently corrupted. A second scenario replaces step 4 with the creator calling `cancelTransaction`, producing the same outcome for a `CANCELED` transaction.

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L131-133)
```typescript
    const transactions = await this.dataSource.manager.find(Transaction, {
      where: { id: In(transactionIds) },
    });
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L201-207)
```typescript
  private validateTransactionStatus(transaction: Transaction): string | null {
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    ) {
      return ErrorCodes.TNRS;
    }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L315-341)
```typescript
    // Execute in single transaction
    try {
      await this.dataSource.transaction(async manager => {
        // Bulk update transactions
        if (transactionsToUpdate.length > 0) {
          await this.bulkUpdateTransactions(manager, transactionsToUpdate);
        }

        // Bulk update notifications
        if (notificationsToUpdate.length > 0) {
          const updatedNotificationReceivers = await this.bulkUpdateNotificationReceivers(manager, notificationsToUpdate);

          // To maintain backwards compatibility and multi-machine support, we send off a dismiss event.
          emitDismissedNotifications(
            this.notificationsPublisher,
            updatedNotificationReceivers,
          );

          notificationsToDismiss = updatedNotificationReceivers.map(nr => nr.id);
        }

        // Bulk insert signers
        if (signersToInsert.length > 0) {
          const results = await this.bulkInsertSigners(manager, signersToInsert);
          results.forEach(signer => signers.add(signer));
        }
      });
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L365-371)
```typescript
    await manager.query(
      `UPDATE transaction
     SET "transactionBytes" = CASE id ${whenClauses} END,
         "updatedAt" = NOW()
     WHERE id = ANY($${bytes.length + 1})`,
      [...bytes, ids]
    );
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
