The code is confirmed. The vulnerability is real and all claims check out against the actual source.

---

Audit Report

## Title
`archiveTransaction()` Status Guard Bypassed via `isManual` Flag, Enabling State Corruption of Terminal Transactions

## Summary
`archiveTransaction()` in `back-end/apps/api/src/transactions/transactions.service.ts` contains a flawed guard condition that uses a logical AND with `!transaction.isManual`. Any manual transaction (`isManual: true`) bypasses the status check entirely, allowing a transaction creator to overwrite the status of an already-`EXECUTED`, `FAILED`, `CANCELED`, `EXPIRED`, or `REJECTED` manual transaction to `ARCHIVED` via a single authenticated HTTP request.

## Finding Description

The guard at lines 711–718 of `transactions.service.ts` is:

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

The exception is thrown only when **both** sub-conditions are true simultaneously. When `transaction.isManual` is `true`, `!transaction.isManual` evaluates to `false`, short-circuiting the entire AND expression to `false` regardless of `transaction.status`. Execution falls through unconditionally to:

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [2](#0-1) 

A manual transaction retains `isManual: true` after on-chain execution when `validStart <= Date.now()` at the time `executeTransaction()` is called, because the `isManual: false` update only occurs in the future-validStart branch:

```typescript
if (transaction.validStart.getTime() > Date.now()) {
  await this.repo.update({ id }, { isManual: false });
} else {
  await this.executeService.executeTransaction(transaction);
}
``` [3](#0-2) 

The endpoint requires only that the caller is the authenticated transaction creator — no elevated role is needed: [4](#0-3) 

The front-end does gate the archive button behind `transactionIsInProgress.value`:

```typescript
const canArchive = computed(() => {
  const isManual = props.organizationTransaction?.isManual;
  return isManual && isCreator.value && transactionIsInProgress.value;
});
``` [5](#0-4) 

This is a client-side control only and is trivially bypassed by calling the API directly.

The existing unit test for the "should throw" path uses a transaction with `isManual` unset (defaults to `false`/`undefined`), so the guard fires correctly in the test but does not cover the `isManual: true` + terminal-status scenario: [6](#0-5) 

## Impact Explanation

A transaction creator can overwrite the status of any manual transaction from any terminal state (`EXECUTED`, `FAILED`, `CANCELED`, `EXPIRED`, `REJECTED`) to `ARCHIVED`. Concrete consequences:

- **Audit trail corruption**: An `EXECUTED` transaction is made to appear `ARCHIVED`, hiding on-chain execution from signers, observers, and approvers who rely on the `status` field.
- **State inconsistency for co-participants**: All other users (signers, observers, approvers) see the transaction as `ARCHIVED` rather than its true terminal state.
- **Notification pollution**: `emitTransactionStatusUpdate` is called with the corrupted state, propagating the false status to all connected clients via WebSocket. [7](#0-6) 

## Likelihood Explanation

- **Attacker preconditions**: Any authenticated organization member who is the creator of a manual transaction. No admin or privileged role required.
- **Trigger**: A single `PATCH /transactions/archive/:id` HTTP request sent directly to the API after the transaction reaches a terminal state.
- **Reachability**: The endpoint is publicly reachable by any authenticated user. Creating a manual transaction is a standard, documented workflow. The front-end guard is client-side only and provides no server-side protection.

## Recommendation

Fix the guard logic so that the status check applies unconditionally, regardless of `isManual`. The corrected condition should be:

```typescript
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  )
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

If manual transactions are intended to have a different set of archiveable statuses, define that set explicitly and check it separately — do not use `isManual` as a bypass of the status guard. Additionally, add unit and e2e test cases covering a manual transaction in each terminal state (`EXECUTED`, `FAILED`, `CANCELED`, `EXPIRED`, `REJECTED`) to ensure the guard fires correctly.

## Proof of Concept

1. Authenticate as any organization member (user A).
2. Create a manual transaction (`isManual: true`) via `POST /transactions`.
3. Execute the transaction immediately (with `validStart <= now`) via `PATCH /transactions/execute/:id`. The transaction transitions to `EXECUTED` and retains `isManual: true` because the `isManual: false` update branch is not taken.
4. Send `PATCH /transactions/archive/:id` directly to the API (bypassing the front-end UI guard).
5. The guard evaluates: `status NOT IN [WAITING_FOR_SIGNATURES, WAITING_FOR_EXECUTION]` → `true`; `!isManual` → `false`; `true && false` → `false` — no exception is thrown.
6. `repo.update({ id }, { status: ARCHIVED })` executes, overwriting the `EXECUTED` status.
7. All co-participants and WebSocket subscribers now observe the transaction as `ARCHIVED` instead of `EXECUTED`.

### Citations

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L721-730)
```typescript
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
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L743-748)
```typescript
    if (transaction.validStart.getTime() > Date.now()) {
      await this.repo.update({ id }, { isManual: false });
      emitTransactionUpdate(this.notificationsPublisher, [{ entityId: transaction.id }]);
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

**File:** front-end/src/renderer/pages/TransactionDetails/components/TransactionDetailsHeader.vue (L189-193)
```vue
const canArchive = computed(() => {
  const isManual = props.organizationTransaction?.isManual;

  return isManual && isCreator.value && transactionIsInProgress.value;
});
```

**File:** back-end/apps/api/src/transactions/transactions.service.spec.ts (L1836-1848)
```typescript
    it('should throw if transaction status is not archiveable', async () => {
      const transaction = {
        creatorKey: { userId: 1 },
        status: TransactionStatus.CANCELED,
      };

      jest
        .spyOn(service, 'getTransactionForCreator')
        .mockResolvedValueOnce(transaction as Transaction);

      await expect(service.archiveTransaction(123, { id: 1 } as User)).rejects.toThrow(
        ErrorCodes.OMTIP,
      );
```
