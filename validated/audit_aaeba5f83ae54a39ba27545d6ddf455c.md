### Title
`archiveTransaction` Guard Condition Allows Archiving of Terminal-State Manual Transactions, Corrupting Audit Trail

### Summary

In `back-end/apps/api/src/transactions/transactions.service.ts`, the `archiveTransaction` function contains a flawed guard condition that uses `isManual` as an unconditional bypass of the status check. Any transaction with `isManual = true` can be archived regardless of its current status — including terminal states such as `EXECUTED`, `FAILED`, `CANCELED`, `EXPIRED`, and `REJECTED`. This allows a transaction creator to overwrite a terminal status with `ARCHIVED`, permanently corrupting the transaction audit trail.

### Finding Description

The guard in `archiveTransaction` is:

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

The condition throws only when **both** sub-conditions are true: status is outside `[WAITING_FOR_SIGNATURES, WAITING_FOR_EXECUTION]` **AND** `isManual` is `false`. For any transaction where `isManual = true`, the second operand is always `false`, so the entire AND is `false` — the guard never throws, regardless of status.

The subsequent update is unconditional on the current DB status:

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [2](#0-1) 

Compare this to `cancelTransactionWithOutcome`, which uses an atomic conditional update:

```typescript
.andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
``` [3](#0-2) 

**Exploit path:**

1. Creator submits a manual transaction (`isManual: true`) via `POST /transactions`.
2. The chain service or the creator calls `PATCH /execute/:id`, which calls `executeService.executeTransaction(transaction)`. The transaction status transitions to `EXECUTED`. The `isManual` flag is **not cleared** in this code path. [4](#0-3) 
3. The creator calls `PATCH /archive/:id`. `getTransactionForCreator` confirms ownership. The guard evaluates: `(status NOT IN [WFS, WFE]) AND (!isManual)` → `(true) AND (false)` → `false` → no throw.
4. `repo.update({ id }, { status: ARCHIVED })` overwrites `EXECUTED` with `ARCHIVED`.

The same path applies to `FAILED`, `CANCELED`, `EXPIRED`, and `REJECTED` manual transactions.

The endpoint is reachable by any authenticated, verified user who is the creator of a manual transaction:

```typescript
@Patch('/archive/:id')
async archiveTransaction(@GetUser() user, @Param('id', ParseIntPipe) id: number)
``` [5](#0-4) 

### Impact Explanation

A transaction creator can permanently overwrite a terminal status (`EXECUTED`, `FAILED`, `CANCELED`, `EXPIRED`, `REJECTED`) with `ARCHIVED` on any manual transaction they own. This:

- Corrupts the immutable audit trail of executed Hedera transactions — an `EXECUTED` record disappears from execution views and is replaced by an `ARCHIVED` record.
- Breaks downstream notification logic: the `processTransactionStatusUpdateNotifications` handler maps status to notification type; an `ARCHIVED` notification is sent instead of the correct terminal-state notification. [6](#0-5) 
- In organization mode, approvers and observers lose visibility into the true outcome of a transaction they participated in.

**Impact: Medium** — no direct asset theft, but permanent, user-triggered corruption of transaction state and audit integrity.

### Likelihood Explanation

**Likelihood: High.** The precondition is simply: be the creator of a manual transaction that has reached a terminal state. No privileged access, no race condition, and no special timing is required. The `PATCH /archive/:id` endpoint is a standard authenticated REST call. Any user operating in organization mode who creates manual transactions can trigger this deterministically.

### Recommendation

Replace the flawed OR-bypass guard with an explicit allowlist of archiveable statuses that applies unconditionally, and make the DB update atomic by including a status guard in the `WHERE` clause:

```typescript
async archiveTransaction(id: number, user: User): Promise<boolean> {
  const archivableStatuses = [
    TransactionStatus.WAITING_FOR_SIGNATURES,
    TransactionStatus.WAITING_FOR_EXECUTION,
  ];

  const transaction = await this.getTransactionForCreator(id, user);

  if (!archivableStatuses.includes(transaction.status)) {
    throw new BadRequestException(ErrorCodes.OMTIP);
  }

  const result = await this.repo
    .createQueryBuilder()
    .update(Transaction)
    .set({ status: TransactionStatus.ARCHIVED })
    .where('id = :id', { id })
    .andWhere('status IN (:...statuses)', { statuses: archivableStatuses })
    .execute();

  if (!result.affected || result.affected === 0) {
    throw new ConflictException('Transaction state changed during archival. Please retry.');
  }
  // emit notification...
  return true;
}
```

This mirrors the pattern already used correctly in `cancelTransactionWithOutcome`.

### Proof of Concept

1. Authenticate as a normal user (no admin role required).
2. Create a manual transaction: `POST /transactions` with a valid body and `isManual: true` (or equivalent flag that results in `isManual = true` in the DB).
3. Trigger execution: `PATCH /execute/:id`. Confirm via `GET /transactions/:id` that status is now `EXECUTED`.
4. Call `PATCH /archive/:id`.
5. Observe: HTTP 200 returned. `GET /transactions/:id` now shows `status: ARCHIVED` instead of `EXECUTED`.

Expected (correct) behavior: step 4 should return HTTP 400 with `OMTIP` error because the transaction is already in a terminal state.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L677-679)
```typescript
      .where('id = :id', { id })
      .andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
      .execute();
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L711-718)
```typescript
    if (
      ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
        transaction.status,
      ) &&
      !transaction.isManual
    ) {
      throw new BadRequestException(ErrorCodes.OMTIP);
    }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L720-720)
```typescript
    await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L746-748)
```typescript
    } else {
      await this.executeService.executeTransaction(transaction);
    }
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

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L1049-1050)
```typescript
      const syncType = this.getInAppNotificationType(transaction.status);
      const emailType = this.getEmailNotificationType(transaction.status);
```
