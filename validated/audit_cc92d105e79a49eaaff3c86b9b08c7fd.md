Audit Report

## Title
Manual Transaction `archiveTransaction` Bypasses Terminal-State Guard, Allowing Unauthorized State Transition

## Summary
`archiveTransaction` in `transactions.service.ts` contains a logically flawed guard that is entirely bypassed when `transaction.isManual === true`. This allows the transaction creator to overwrite any terminal status (`EXECUTED`, `FAILED`, `CANCELED`, `EXPIRED`, `REJECTED`) with `ARCHIVED` via a single authenticated API call, corrupting the authoritative state record.

## Finding Description

**Root cause — flawed boolean conjunction:**

The guard at lines 711–718 of `back-end/apps/api/src/transactions/transactions.service.ts`:

```typescript
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  ) &&
  !transaction.isManual          // ← false when isManual=true
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
``` [1](#0-0) 

The guard is a conjunction (`A && B`). When `isManual === true`, `B` (`!transaction.isManual`) evaluates to `false`, making the entire expression `false` regardless of `A` (the status check). The exception is never thrown, and execution falls through unconditionally to:

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [2](#0-1) 

The codebase explicitly defines `terminalStatuses` as a closed set including `EXECUTED`, `FAILED`, `CANCELED`, `EXPIRED`, `ARCHIVED`, and `REJECTED`: [3](#0-2) 

Transitioning from one terminal state to another (`EXECUTED → ARCHIVED`, `FAILED → ARCHIVED`, etc.) is never intended and has no guard anywhere else in the pipeline.

**The endpoint is publicly reachable:**

`PATCH /transactions/archive/:id` is protected only by JWT authentication and user verification — no role restriction: [4](#0-3) 

**Existing tests do not cover the vulnerable path:**

The e2e test "should not archive a transaction if it's already executed" uses `addedTransactions.userTransactions[0]`, which is created without `isManual: true` (defaults to `false`), so the bypass is never exercised: [5](#0-4) 

The unit test for the non-archiveable case also omits `isManual: true`: [6](#0-5) 

**Contrast with correct patterns elsewhere:**

`cancelTransactionWithOutcome` correctly checks `cancelableStatuses` and throws `OTIP` for terminal states: [7](#0-6) 

`archiveTransaction` is the only state-mutating function that omits this pattern for manual transactions.

## Impact Explanation

A transaction creator can permanently overwrite the status of any manual transaction — including one already `EXECUTED` on the Hedera network — with `ARCHIVED`. This constitutes:

- **Unauthorized state change**: A terminal, immutable state (`EXECUTED`, `FAILED`) is silently replaced, violating the invariant that terminal states are final. The `terminalStatuses` array confirms these states are intended to be closed.
- **Audit-trail corruption**: The system's record of whether a transaction succeeded or failed is destroyed. Downstream consumers (notifications, history views, compliance logs) will see `ARCHIVED` instead of the true outcome.
- **Irreversibility**: There is no un-archive operation; the original terminal status cannot be recovered from the database.

## Likelihood Explanation

- **Attacker profile**: Any authenticated, verified organization user who is the creator of a manual transaction. No privileged access is required.
- **Precondition**: The attacker must own the transaction (`getTransactionForCreator` enforces creator-only access). This is a normal, reachable condition for any user who creates transactions.
- **Trigger**: A single authenticated `PATCH /transactions/archive/:id` call with a valid transaction ID.
- **Detection difficulty**: The operation emits a `TransactionStatusUpdate` notification, but the notification payload does not expose the previous status, so the overwrite is not self-evidently anomalous to observers.

## Recommendation

Replace the flawed conjunction with a correct guard that enforces the status check independently of `isManual`. The intended semantics — "manual transactions may be archived from any non-terminal state" — should be expressed as:

```typescript
const archivableStatuses = [
  TransactionStatus.WAITING_FOR_SIGNATURES,
  TransactionStatus.WAITING_FOR_EXECUTION,
];

if (!archivableStatuses.includes(transaction.status)) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

This ensures that no transaction — manual or not — can be archived from a terminal state. Add a corresponding unit test with `isManual: true` and `status: TransactionStatus.EXECUTED` (and other terminal statuses) to prevent regression.

## Proof of Concept

1. Authenticated user creates a manual transaction (`isManual: true`) via `POST /transactions`.
2. The transaction is executed on the Hedera network; its status becomes `EXECUTED`.
3. User calls `PATCH /transactions/archive/:id` with the transaction's ID.
4. In `archiveTransaction`, `transaction.isManual === true` causes `!transaction.isManual` to be `false`.
5. The entire guard condition evaluates to `false`; no exception is thrown.
6. `this.repo.update({ id }, { status: TransactionStatus.ARCHIVED })` executes unconditionally.
7. The DB record now shows `status = ARCHIVED`, permanently overwriting the `EXECUTED` record.

The same path applies to `FAILED`, `CANCELED`, `EXPIRED`, and `REJECTED` manual transactions.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L98-105)
```typescript
  private readonly terminalStatuses = [
    TransactionStatus.EXECUTED,
    TransactionStatus.EXPIRED,
    TransactionStatus.FAILED,
    TransactionStatus.CANCELED,
    TransactionStatus.ARCHIVED,
    TransactionStatus.REJECTED,
  ];
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L669-671)
```typescript
    if (!this.cancelableStatuses.includes(transaction.status)) {
      throw new BadRequestException(ErrorCodes.OTIP);
    }
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

**File:** back-end/apps/api/src/transactions/transactions.service.spec.ts (L1836-1849)
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
    });
```
