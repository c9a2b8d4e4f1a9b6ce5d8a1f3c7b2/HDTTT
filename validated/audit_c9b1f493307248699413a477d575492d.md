The code is confirmed. All claims check out against the actual source. Here is the audit report:

---

Audit Report

## Title
Incorrect Boolean Guard in `archiveTransaction` Allows Creator to Overwrite Terminal Transaction States on Manual Transactions

## Summary
`archiveTransaction` in `transactions.service.ts` uses a logically flawed `&&` guard that completely bypasses the status check whenever `isManual` is `true`. As a result, the creator of any manual transaction can archive it regardless of its current status — including terminal states such as `EXECUTED`, `FAILED`, `EXPIRED`, and `CANCELED` — overwriting the authoritative on-chain outcome with `ARCHIVED` and corrupting the audit trail.

## Finding Description

**Root cause — incorrect boolean guard:**

The guard at lines 711–718 of `transactions.service.ts`:

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

The guard throws only when **both** sub-expressions are `true`. When `transaction.isManual === true`, `!transaction.isManual` evaluates to `false`, making the entire `&&` expression `false` regardless of the status. The guard never fires for any manual transaction, regardless of whether its status is `EXECUTED`, `FAILED`, `EXPIRED`, or `CANCELED`.

| `status NOT IN [WFS, WFE]` | `!isManual` | throws? |
|---|---|---|
| true | true | yes (non-manual, wrong status) |
| true | **false** | **no — isManual bypasses status check entirely** |
| false | true | no (correct status) |
| false | false | no (correct status) |

The unconditional write that immediately follows overwrites whatever terminal state the transaction holds:

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [2](#0-1) 

**Entry point — authenticated HTTP endpoint, no privilege required:**

The endpoint is `PATCH /transactions/archive/:id`: [3](#0-2) 

The only access control is `getTransactionForCreator`, which verifies the caller is the transaction's creator — a normal user role: [4](#0-3) 

**Terminal states that can be overwritten:**

`TransactionStatus` defines `EXECUTED`, `FAILED`, `EXPIRED`, and `CANCELED` as final states: [5](#0-4) 

The service itself recognizes these as `terminalStatuses`: [6](#0-5) 

**Test gap — the existing e2e test uses a non-manual transaction:**

The e2e test for "should not archive a transaction if it's already executed" uses `addedTransactions.userTransactions[0]`, which does not have `isManual: true`, so the `!isManual` branch is never exercised with a terminal status: [7](#0-6) 

The unit test similarly omits `isManual: true` in the "should throw if transaction status is not archiveable" case: [8](#0-7) 

## Impact Explanation

A transaction creator can overwrite any terminal state (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`) with `ARCHIVED` on any manual transaction they own. Concretely:

- An `EXECUTED` transaction — one already submitted to and confirmed by the Hedera network — can be relabeled `ARCHIVED`, hiding the on-chain execution from the organization's audit trail and notification history.
- A `FAILED` transaction can be silently buried as `ARCHIVED`, preventing operators from investigating the failure.
- The notification system will emit a spurious `STATUS_UPDATE` event for a transaction already in a terminal state, potentially confusing downstream consumers. [9](#0-8) 

## Likelihood Explanation

- **Attacker preconditions**: authenticated user, creator of at least one manual transaction. No admin or privileged key required.
- **Trigger**: a single `PATCH /transactions/archive/:id` HTTP request after the transaction reaches a terminal state.
- **Discoverability**: the `isManual` flag is set by the creator at creation time and is visible in the transaction response body, so the creator knows exactly which transactions are eligible.
- Manual transactions are an explicitly supported workflow, as confirmed by the e2e test that creates and archives a manual transaction: [10](#0-9) 

Any user who creates a manual transaction and then executes it is in the exact position to trigger this bug.

## Recommendation

Replace the `&&` compound guard with a status-only check that applies uniformly to all transactions, regardless of `isManual`:

```typescript
// Before (flawed):
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  ) &&
  !transaction.isManual
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}

// After (correct):
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  )
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

If manual transactions are intentionally permitted to be archived from additional statuses, enumerate those statuses explicitly rather than bypassing the check entirely. Add unit and e2e test cases covering `isManual: true` transactions in each terminal state (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`) to ensure the guard is exercised.

## Proof of Concept

1. Authenticate as a normal user (no admin role required).
2. Create a manual transaction: `POST /transactions` with `isManual: true`. Note the returned `id`.
3. Execute the transaction via `PATCH /transactions/execute/:id`. The transaction transitions to `EXECUTED` (or `FAILED`).
4. Send `PATCH /transactions/archive/:id` as the same creator user.
5. Observe: the response returns HTTP 200 and the transaction's status in the database is now `ARCHIVED`, overwriting the terminal `EXECUTED`/`FAILED` state. A spurious `STATUS_UPDATE` notification is also emitted.

The guard at line 715 (`!transaction.isManual`) evaluates to `false` for any manual transaction, short-circuiting the `&&` and preventing the `BadRequestException` from being thrown, regardless of the transaction's current status. [1](#0-0)

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L879-891)
```typescript
  async getTransactionForCreator(id: number, user: User) {
    const transaction = await this.getTransactionById(id);

    if (!transaction) {
      throw new BadRequestException(ErrorCodes.TNF);
    }

    if (transaction.creatorKey?.userId !== user?.id) {
      throw new UnauthorizedException('Only the creator has access to this transaction');
    }

    return transaction;
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

**File:** back-end/apps/api/test/spec/transaction.e2e-spec.ts (L852-864)
```typescript
    it('(PATCH) should archive a transaction if creator', async () => {
      const transaction = await createTransaction(user, localnet1003);
      const { body: newTransaction } = await new Endpoint(server, '/transactions')
        .post({ ...transaction, isManual: true }, null, userAuthToken)
        .expect(201);

      const { status } = await endpoint.patch(null, newTransaction.id.toString(), userAuthToken);

      const transactionFromDb = await repo.findOne({ where: { id: newTransaction.id } });

      expect(status).toEqual(200);
      expect(transactionFromDb?.status).toEqual(TransactionStatus.ARCHIVED);
    });
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
