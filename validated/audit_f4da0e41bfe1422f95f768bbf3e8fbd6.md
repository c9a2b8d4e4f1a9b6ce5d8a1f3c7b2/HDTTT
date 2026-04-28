### Title
`archiveTransaction()` Status Guard Bypassed via `isManual` Flag, Enabling State Corruption of Terminal Transactions

### Summary
`archiveTransaction()` in `back-end/apps/api/src/transactions/transactions.service.ts` is intended to only archive transactions in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` states. However, the guard condition uses a logical AND with `!transaction.isManual`, meaning any manual transaction (`isManual: true`) bypasses the status check entirely. A transaction creator can archive a manual transaction that is already `EXECUTED`, `FAILED`, `CANCELED`, `EXPIRED`, or `REJECTED`, corrupting the audit trail and observable state for all other participants.

### Finding Description

The guard in `archiveTransaction()` is:

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

The condition throws only when **both** sub-conditions are true: status is not in the allowed set **AND** `isManual` is `false`. When `isManual` is `true`, the entire guard short-circuits to `false` regardless of status, and execution falls through unconditionally to:

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [2](#0-1) 

A manual transaction retains `isManual: true` after execution when `validStart <= Date.now()` at the time `executeTransaction()` is called (the `isManual: false` update only happens in the future-validStart branch):

```typescript
if (transaction.validStart.getTime() > Date.now()) {
  await this.repo.update({ id }, { isManual: false });
} else {
  await this.executeService.executeTransaction(transaction);
}
``` [3](#0-2) 

The endpoint is authenticated but requires only that the caller is the transaction creator:

```typescript
@Patch('/archive/:id')
async archiveTransaction(@GetUser() user, @Param('id', ParseIntPipe) id: number)
``` [4](#0-3) 

The existing e2e test only validates the non-manual case and does not cover a manual transaction in a terminal state:

```typescript
it("(PATCH) should not archive a transaction if it's already executed", async () => {
  // uses a non-manual transaction — isManual is false, so guard fires correctly
  await repo.update({ id: transaction.id }, { status: TransactionStatus.EXECUTED });
``` [5](#0-4) 

### Impact Explanation

A transaction creator can overwrite the status of a manual transaction from any terminal state (`EXECUTED`, `FAILED`, `CANCELED`, `EXPIRED`, `REJECTED`) to `ARCHIVED`. Concrete consequences:

- **Audit trail corruption**: An `EXECUTED` transaction is made to appear `ARCHIVED`, hiding on-chain execution from signers, observers, and approvers who rely on the status field.
- **State inconsistency for co-participants**: All other users (signers, observers, approvers) see the transaction as `ARCHIVED` rather than its true terminal state, breaking their ability to reason about what happened.
- **Notification pollution**: `emitTransactionStatusUpdate` is called with the corrupted state, propagating the false status to all connected clients via WebSocket. [6](#0-5) 

### Likelihood Explanation

- **Attacker preconditions**: Authenticated user who is the creator of any manual transaction. No admin or privileged role required.
- **Trigger**: A single `PATCH /transactions/archive/:id` HTTP request after the transaction reaches a terminal state.
- **Reachability**: The endpoint is publicly reachable by any authenticated organization member who creates a manual transaction, which is a standard workflow.

### Recommendation

Fix the guard to check status independently of `isManual`. The allowed statuses for archiving should be enforced unconditionally:

```typescript
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  )
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

If manual transactions in additional states should be archiveable, those states must be explicitly enumerated in the allowlist rather than bypassing the check entirely via the `isManual` flag.

### Proof of Concept

1. Authenticate as a regular user and create a manual transaction (`isManual: true`) with `validStart` in the past.
2. Add the required signature so the transaction reaches `WAITING_FOR_EXECUTION`.
3. Call `PATCH /transactions/execute/:id` — the transaction is submitted to Hedera and status becomes `EXECUTED`. Because `validStart <= Date.now()`, `isManual` remains `true` in the database.
4. Call `PATCH /transactions/archive/:id`.
5. The guard evaluates: `status NOT IN [WFS, WFE]` → `true`; `!isManual` → `false`; `true AND false` → `false` → no exception thrown.
6. `repo.update({ id }, { status: ARCHIVED })` executes unconditionally.
7. Query the transaction — status is now `ARCHIVED` despite having been `EXECUTED` on-chain. [7](#0-6)

### Citations

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

**File:** back-end/apps/api/test/spec/transaction.e2e-spec.ts (L884-897)
```typescript
    it("(PATCH) should not archive a transaction if it's already executed", async () => {
      const transaction = addedTransactions.userTransactions[0];
      const oldStatus = transaction.status;
      await repo.update({ id: transaction.id }, { status: TransactionStatus.EXECUTED });

      const { status } = await endpoint.patch(null, transaction.id.toString(), userAuthToken);

      const transactionFromDb = await repo.findOne({ where: { id: transaction.id } });

      expect(status).toEqual(400);
      expect(transactionFromDb?.status).not.toEqual(TransactionStatus.ARCHIVED);

      await repo.update({ id: transaction.id }, { status: oldStatus });
    });
```
