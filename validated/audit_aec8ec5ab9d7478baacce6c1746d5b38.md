Audit Report

## Title
Incorrect Boolean Logic in `archiveTransaction` Allows Creators to Archive Transactions in Terminal States

## Summary
A logical operator error in `archiveTransaction` (`&&` instead of `||`) means the guard condition is only enforced when **both** sub-conditions are true simultaneously. As a result, any `isManual = true` transaction — regardless of its current status — bypasses the guard and can be archived, including transactions already in terminal states such as `EXECUTED`, `FAILED`, `CANCELED`, `REJECTED`, or `EXPIRED`.

## Finding Description

**File:** `back-end/apps/api/src/transactions/transactions.service.ts`, lines 711–718

The guard condition is:

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

The exception is thrown only when **both** of the following are true:
- `status` is NOT in `[WAITING_FOR_SIGNATURES, WAITING_FOR_EXECUTION]`
- AND `isManual` is `false`

By De Morgan's law, archiving is **allowed** when **either**:
1. `status` IS in `[WAITING_FOR_SIGNATURES, WAITING_FOR_EXECUTION]` (regardless of `isManual`), or
2. `isManual` is `true` — **regardless of status**

Branch 2 is the defect. A manual transaction with status `EXECUTED`, `FAILED`, `CANCELED`, `REJECTED`, `EXPIRED`, or even `ARCHIVED` passes the guard and gets its status overwritten to `ARCHIVED`.

The `terminalStatuses` list explicitly defines these as final states:

```typescript
private readonly terminalStatuses = [
  TransactionStatus.EXECUTED,
  TransactionStatus.EXPIRED,
  TransactionStatus.FAILED,
  TransactionStatus.CANCELED,
  TransactionStatus.ARCHIVED,
  TransactionStatus.REJECTED,
];
``` [2](#0-1) 

The existing e2e test only covers a **non-manual** transaction with `EXECUTED` status, so it passes even with the bug present: [3](#0-2) 

A manual transaction with `EXECUTED` status is not tested and would incorrectly succeed.

`getTransactionForCreator` correctly enforces creator-only access:

```typescript
if (transaction.creatorKey?.userId !== user?.id) {
  throw new UnauthorizedException('Only the creator has access to this transaction');
}
``` [4](#0-3) 

So the issue is not unauthorized access — it is an incorrect state-transition guard that allows the creator to move their own transaction out of a terminal state.

## Impact Explanation
A transaction creator can send `PATCH /transactions/archive/:id` for any of their own manual transactions that are in a terminal state. The most significant case is `EXECUTED → ARCHIVED`: the on-chain execution already occurred, but the database record is overwritten to `ARCHIVED`, corrupting the audit trail. Additionally, `emitTransactionStatusUpdate` fires with the new `ARCHIVED` status, sending misleading notifications to all observers and signers. [5](#0-4) 

## Likelihood Explanation
The endpoint is authenticated and restricted to the transaction creator via `getTransactionForCreator`. Exploitation requires no special tooling — a creator simply calls the archive endpoint on one of their own already-executed manual transactions. Any creator who is aware of the API can trigger this intentionally or accidentally.

## Recommendation
Change the logical operator from `&&` to `||` so that the guard blocks archiving unless **both** the status is valid **and** the transaction is manual:

```typescript
// Corrected: throw if status is not archiveable OR transaction is not manual
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  ) ||
  !transaction.isManual
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

Also add an e2e test covering a **manual** transaction in `EXECUTED` status to prevent regression.

## Proof of Concept

1. Creator creates a transaction with `isManual: true` — it is submitted, executed on-chain, and its status becomes `EXECUTED`.
2. Creator calls `PATCH /transactions/archive/<id>` with their auth token.
3. `getTransactionForCreator` passes (creator matches).
4. Guard evaluation: `status NOT IN allowed` = `true` (EXECUTED is not in the list); `!isManual` = `false` (it is manual). `true && false` = `false` → **no exception thrown**.
5. `repo.update({ id }, { status: TransactionStatus.ARCHIVED })` executes.
6. The transaction record now shows `ARCHIVED` despite having been executed on-chain. `emitTransactionStatusUpdate` fires with the incorrect status. [6](#0-5)

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L886-888)
```typescript
    if (transaction.creatorKey?.userId !== user?.id) {
      throw new UnauthorizedException('Only the creator has access to this transaction');
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
