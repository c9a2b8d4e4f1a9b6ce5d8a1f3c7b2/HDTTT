### Title
`archiveTransaction` Allows Unchecked State Transition to `ARCHIVED` for Manual Transactions

### Summary
The `archiveTransaction` function in `transactions.service.ts` contains a logically flawed guard condition that completely bypasses status validation for manual transactions (`isManual = true`). This allows a transaction creator to force any manual transaction — including those already in terminal states such as `EXECUTED`, `FAILED`, `EXPIRED`, or `CANCELED` — into the `ARCHIVED` state, corrupting the audit trail.

### Finding Description

In `archiveTransaction`, the guard is:

```typescript
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  ) &&
  !transaction.isManual
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
``` [1](#0-0) 

Because the two sub-expressions are joined with `&&`, when `transaction.isManual === true` the right-hand operand (`!transaction.isManual`) is `false`, making the entire condition `false` regardless of the transaction's current status. No exception is ever thrown for manual transactions.

The subsequent database write has no status guard in its `WHERE` clause either:

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [2](#0-1) 

This unconditionally overwrites whatever status the transaction currently holds.

The intended valid states for archiving are `WAITING_FOR_SIGNATURES` and `WAITING_FOR_EXECUTION`, as defined by the status collections: [3](#0-2) 

The terminal states that should never be overwritten are: [4](#0-3) 

### Impact Explanation

A transaction creator can call the archive endpoint on a manual transaction that has already reached `EXECUTED`, `FAILED`, `EXPIRED`, or `CANCELED`. The status column is overwritten to `ARCHIVED`, which:

- Erases the `EXECUTED` or `FAILED` outcome from the transaction record, corrupting the on-chain audit trail visible to all organization members.
- Breaks any downstream logic or reporting that distinguishes `EXECUTED` from `ARCHIVED`.
- Allows a creator to retroactively hide a failed or executed transaction by relabeling it as merely "archived."

### Likelihood Explanation

The attacker must be the creator of a manual transaction — a legitimate, non-privileged role available to any organization member. No special permissions beyond transaction creation are required. The archive endpoint is a standard REST call, and the condition is triggered simply by having `isManual = true` on the transaction record.

### Recommendation

Remove the `isManual` short-circuit from the status guard so that the allowed-status check applies to all transactions:

```typescript
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  )
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

Additionally, add a status guard to the `WHERE` clause of the database update to prevent a TOCTOU race between the read and the write:

```typescript
await this.repo
  .createQueryBuilder()
  .update(Transaction)
  .set({ status: TransactionStatus.ARCHIVED })
  .where('id = :id', { id })
  .andWhere('status IN (:...statuses)', {
    statuses: [TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION],
  })
  .execute();
```

### Proof of Concept

1. Organization member creates a **manual** transaction (sets `isManual = true`).
2. The transaction is signed, scheduled, and executed on-chain — status becomes `EXECUTED`.
3. The creator immediately calls the archive endpoint for that transaction ID.
4. Inside `archiveTransaction`:
   - `getTransactionForCreator` succeeds (caller is the creator).
   - Guard condition: `(status NOT IN [...]) && !isManual` → `true && false` → `false` → **no exception thrown**.
   - `this.repo.update({ id }, { status: TransactionStatus.ARCHIVED })` executes unconditionally.
5. The transaction's status is now `ARCHIVED` instead of `EXECUTED`, hiding the execution outcome from all organization members. [5](#0-4)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L708-733)
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

**File:** back-end/apps/api/src/transactions/nodes/transaction-node-collections.constants.ts (L3-22)
```typescript
export const TRANSACTION_STATUS_COLLECTIONS: Record<string, TransactionStatus[]> = {
  READY_FOR_REVIEW: [TransactionStatus.WAITING_FOR_SIGNATURES],

  READY_TO_SIGN: [
    TransactionStatus.WAITING_FOR_SIGNATURES,
    TransactionStatus.WAITING_FOR_EXECUTION,
  ],

  READY_FOR_EXECUTION: [TransactionStatus.WAITING_FOR_EXECUTION],

  IN_PROGRESS: [TransactionStatus.WAITING_FOR_SIGNATURES],

  // Terminal states - transactions that are "done"
  HISTORY: [
    TransactionStatus.EXECUTED,
    TransactionStatus.FAILED,
    TransactionStatus.EXPIRED,
    TransactionStatus.CANCELED,
    TransactionStatus.ARCHIVED,
  ],
```

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L46-56)
```typescript
export enum TransactionStatus {
  NEW = 'NEW', // unused
  CANCELED = 'CANCELED',
  REJECTED = 'REJECTED',
  WAITING_FOR_SIGNATURES = 'WAITING FOR SIGNATURES',
  WAITING_FOR_EXECUTION = 'WAITING FOR EXECUTION',
  EXECUTED = 'EXECUTED',
  FAILED = 'FAILED',
  EXPIRED = 'EXPIRED',
  ARCHIVED = 'ARCHIVED',
}
```
