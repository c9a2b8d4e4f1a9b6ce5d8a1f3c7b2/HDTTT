All code references have been verified against the actual source. The vulnerability is confirmed.

---

Audit Report

## Title

`isManual` Flag Bypasses Status Guard in `archiveTransaction`, Allowing Creators to Overwrite Terminal Transaction State with `ARCHIVED`

## Summary

The `archiveTransaction` function in `back-end/apps/api/src/transactions/transactions.service.ts` contains a logical flaw in its status guard. When `transaction.isManual === true`, the status check is entirely skipped, allowing the transaction creator to archive a manual transaction regardless of its current status — including `EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, and `REJECTED` — permanently overwriting the terminal state with `ARCHIVED` and corrupting the shared audit trail for all organization members.

## Finding Description

The guard in `archiveTransaction` is structured as follows:

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

The throw condition is: `status NOT IN [WAITING_FOR_SIGNATURES, WAITING_FOR_EXECUTION] AND isManual === false`. By De Morgan's law, the condition for **not** throwing is: `status IN [WAITING_FOR_SIGNATURES, WAITING_FOR_EXECUTION] OR isManual === true`. When `isManual === true`, the status check is completely skipped.

The subsequent update is unconditional — no status guard in the `WHERE` clause:

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [2](#0-1) 

By contrast, `cancelTransactionWithOutcome` correctly uses a status-guarded `WHERE` clause to prevent race conditions and invalid state transitions:

```typescript
.andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
``` [3](#0-2) 

The endpoint is exposed at `PATCH /transactions/archive/:id` with no additional authorization beyond creator identity: [4](#0-3) 

The existing e2e test that asserts archiving an `EXECUTED` transaction fails only tests a **non-manual** transaction (`addedTransactions.userTransactions[0]`, created without `isManual: true`): [5](#0-4) 

The test that does use `isManual: true` only tests a freshly created transaction (in `WAITING_FOR_SIGNATURES` state), never a terminal-state manual transaction: [6](#0-5) 

The `TransactionStatus` enum confirms `ARCHIVED` is a distinct terminal state separate from `EXECUTED`: [7](#0-6) 

The service itself defines `terminalStatuses` including both `EXECUTED` and `ARCHIVED`, confirming they are mutually exclusive states: [8](#0-7) 

## Impact Explanation

A malicious transaction creator can:

1. Create a manual transaction (`isManual: true`).
2. Allow other organization members to sign it; the chain service executes it on Hedera (status → `EXECUTED`).
3. Call `PATCH /transactions/archive/:id` with their JWT.
4. The `isManual` bypass causes the guard to pass; the status is unconditionally overwritten to `ARCHIVED`.

The on-chain execution is permanent, but the organization's shared database record now shows the transaction as `ARCHIVED` instead of `EXECUTED`. All observers, signers, and approvers lose accurate audit visibility. In a compliance or financial context this constitutes falsification of the audit trail — an unrecoverable corruption of organizational state. The same bypass applies to `FAILED`, `EXPIRED`, `CANCELED`, and `REJECTED` manual transactions.

## Likelihood Explanation

- The attacker is the transaction creator — a normal authenticated user with no privileged access.
- The attack requires a single authenticated `PATCH` request; no race condition or timing is needed.
- Any user who creates a manual transaction and whose transaction reaches `EXECUTED` (or any other terminal state) can trigger this deterministically.
- The `isManual` flag is a standard user-controlled field set at transaction creation time.

## Recommendation

The guard should be restructured to explicitly enumerate the archiveable statuses regardless of `isManual`. The `isManual` flag should only gate whether the archive action is *available* (as the frontend already does via `canArchive`), not bypass the status validity check. The corrected guard should be:

```typescript
const archiveableStatuses = [
  TransactionStatus.WAITING_FOR_SIGNATURES,
  TransactionStatus.WAITING_FOR_EXECUTION,
];

if (!archiveableStatuses.includes(transaction.status)) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}

if (!transaction.isManual) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

Additionally, the update should include a status guard in the `WHERE` clause (as `cancelTransactionWithOutcome` does) to be race-safe:

```typescript
await this.repo
  .createQueryBuilder()
  .update(Transaction)
  .set({ status: TransactionStatus.ARCHIVED })
  .where('id = :id', { id })
  .andWhere('status IN (:...statuses)', { statuses: archiveableStatuses })
  .execute();
```

A new e2e test should be added that creates a manual transaction, forces its status to `EXECUTED`, and asserts that `PATCH /transactions/archive/:id` returns `400`.

## Proof of Concept

```
# 1. Authenticate as a normal user and create a manual transaction
POST /transactions
Authorization: Bearer <user_jwt>
{ ..., "isManual": true }
→ 201 { "id": 42, "status": "WAITING FOR SIGNATURES" }

# 2. (Out of band) Other members sign; chain service executes it
# DB: transactions.status = 'EXECUTED' for id=42

# 3. Creator calls archive endpoint directly (bypassing UI canArchive guard)
PATCH /transactions/archive/42
Authorization: Bearer <user_jwt>
→ 200 true

# 4. Verify DB corruption
SELECT status FROM transactions WHERE id = 42;
→ 'ARCHIVED'   ← was 'EXECUTED'; on-chain execution is permanent but record is falsified
```

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
