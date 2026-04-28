The code is confirmed. The vulnerability is real. Here is the audit report:

---

Audit Report

## Title
`isManual` Flag Bypasses Status Guard in `archiveTransaction`, Allowing Creators to Corrupt Executed Transaction State

## Summary
The `archiveTransaction` function in `transactions.service.ts` contains a logical flaw: when `transaction.isManual === true`, the status guard is entirely bypassed. This allows the creator of any manual transaction to archive it regardless of its current status — including `EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, or `REJECTED` — permanently overwriting the terminal state with `ARCHIVED` and corrupting the shared audit trail for all organization members.

## Finding Description

In `back-end/apps/api/src/transactions/transactions.service.ts`, `archiveTransaction` applies this guard:

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

The throw condition is:
```
status NOT IN [WAITING_FOR_SIGNATURES, WAITING_FOR_EXECUTION]  AND  isManual === false
```

By De Morgan's law, the **pass** condition (no throw) is:
```
status IN [WAITING_FOR_SIGNATURES, WAITING_FOR_EXECUTION]  OR  isManual === true
```

When `isManual === true`, the status check is completely short-circuited. The subsequent update is unconditional — there is no status guard in the `WHERE` clause:

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [2](#0-1) 

By contrast, `cancelTransactionWithOutcome` correctly uses a race-safe `andWhere` clause to prevent overwriting terminal states:

```typescript
.andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
``` [3](#0-2) 

The endpoint is exposed at `PATCH /transactions/archive/:id`: [4](#0-3) 

The existing e2e test that asserts archiving an `EXECUTED` transaction fails only tests a **non-manual** transaction (`addedTransactions.userTransactions[0]`, created without `isManual: true`), leaving the bypass undetected: [5](#0-4) 

## Impact Explanation

A malicious transaction creator can:
1. Create a manual transaction (`isManual: true`).
2. Allow other organization members to sign it; the chain service executes it on Hedera (status → `EXECUTED`).
3. Call `PATCH /transactions/archive/:id` with their JWT.
4. The `isManual` bypass causes the guard to pass; the status is unconditionally overwritten to `ARCHIVED`.

The on-chain execution is permanent, but the organization's shared record now shows the transaction as `ARCHIVED` instead of `EXECUTED`. All observers, signers, and approvers lose accurate audit visibility. In a compliance or financial context this constitutes falsification of the audit trail — an unrecoverable corruption of organizational state. The same bypass applies to `FAILED`, `EXPIRED`, `CANCELED`, and `REJECTED` manual transactions.

## Likelihood Explanation

- The attacker is the transaction creator — a normal authenticated user with no privileged access.
- The attack requires a single authenticated `PATCH` request; no race condition or timing is needed.
- Any user who creates a manual transaction and whose transaction reaches `EXECUTED` can trigger this deterministically.
- The `isManual` flag is a standard user-controlled field set at transaction creation time.

## Recommendation

Fix the guard logic so that `isManual` does not bypass the status check. The intended semantics appear to be: manual transactions may be archived only when in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`. The corrected guard should be:

```typescript
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  )
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

Additionally, mirror the pattern used in `cancelTransactionWithOutcome` and add a status guard to the `WHERE` clause of the `update` call to make it race-safe:

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

Add an e2e test that creates a **manual** transaction, forces its status to `EXECUTED`, and asserts that `PATCH /transactions/archive/:id` returns `400` and does not overwrite the status.

## Proof of Concept

```
# 1. Authenticate as a normal user and create a manual transaction
POST /transactions
Authorization: Bearer <user_jwt>
{ ..., "isManual": true }
→ 201 { "id": 42, "status": "WAITING_FOR_SIGNATURES" }

# 2. (Out-of-band) Transaction is signed and executed on Hedera
#    DB status is now EXECUTED

# 3. Archive the executed manual transaction
PATCH /transactions/archive/42
Authorization: Bearer <user_jwt>
→ 200 true

# 4. Verify the status has been corrupted
GET /transactions/42
→ { "id": 42, "status": "ARCHIVED" }   ← was EXECUTED
```

The guard at lines 711–718 passes because `transaction.isManual === true` short-circuits the `&&`, and the unconditional `repo.update` at line 720 overwrites `EXECUTED` with `ARCHIVED`.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L678-678)
```typescript
      .andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
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
