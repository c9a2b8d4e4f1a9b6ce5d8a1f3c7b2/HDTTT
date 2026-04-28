Audit Report

## Title
Stale Approval State Persists After Approver Replacement Due to TypeORM `undefined` Skip Behavior

## Summary
In `updateTransactionApprover`, when the transaction creator replaces an approver's `userId`, the code passes `undefined` for `userKeyId`, `signature`, and `approved` in a TypeORM `EntityManager.update()` call. TypeORM silently omits `undefined`-valued fields from the generated SQL `SET` clause, so only `userId` is written to the database. The previous approver's signature, key reference, and approval status remain persisted under the new user's identity, breaking the multi-signature approval guarantee.

## Finding Description

In `back-end/apps/api/src/transactions/approvers/approvers.service.ts`, the `updateTransactionApprover` function constructs the following update payload when replacing an approver:

```typescript
const data: DeepPartial<TransactionApprover> = {
  userId: dto.userId,
  userKeyId: undefined,   // TypeORM SKIPS this
  signature: undefined,   // TypeORM SKIPS this
  approved: undefined,    // TypeORM SKIPS this
};
await transactionalEntityManager.update(TransactionApprover, approver.id, data);
``` [1](#0-0) 

TypeORM's `EntityManager.update()` builds the SQL `SET` clause by iterating over the provided object's keys and **excluding any key whose value is `undefined`**. The resulting SQL is:

```sql
UPDATE transaction_approver SET "userId" = $1 WHERE "id" = $2
```

The columns `userKeyId`, `signature`, and `approved` are never touched. All three are declared as `nullable: true` in the entity, meaning `NULL` is a valid and intended cleared state — but `undefined` does not produce `NULL` in TypeORM's update path. [2](#0-1) 

The in-memory `approver` object is mutated to `undefined` for these fields, but this object is discarded after the function returns. All subsequent reads come from the database, which still holds the old approval state.

The unit test for this path confirms the bug is present and untested for correctness — it asserts that `update` is called with `undefined` values but does not verify the database outcome: [3](#0-2) 

**Exploit flow:**

1. Creator configures a 2-of-2 approval requirement with User A and User B.
2. User A calls `approveTransaction` — their row is updated: `approved = true`, `signature = <A's sig>`, `userKeyId = <A's key>`.
3. Creator calls `PATCH /transactions/:id/approvers/:approverId` with `{ userId: C }` to replace User A with User C.
4. TypeORM executes only `UPDATE transaction_approver SET "userId" = C WHERE id = <row>`.
5. The database row now reads: `userId = C`, `approved = true`, `signature = <A's sig>`, `userKeyId = <A's key>`.

**Consequence 1 — User C is locked out from approving.** `approveTransaction` checks:

```typescript
if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
```

User C's row has a non-null `signature`, so this guard fires and rejects User C's approval attempt. [4](#0-3) 

**Consequence 2 — Phantom approval counted toward threshold.** The stale `approved = true` is read by the status computation, counting User C as having approved. The transaction may advance to execution with only 1 genuine approval (User B) instead of the required 2.

**Consequence 3 — `getVerifiedApproversByTransactionId` grants User C access** based on `approvers.some(a => a.userId === user.id)`, but the approval record shown is fraudulent (User A's signature under User C's identity). [5](#0-4) 

## Impact Explanation
A transaction can reach execution status with fewer genuine approvals than the configured threshold requires. The replaced approver (User C) inherits a phantom "approved" state and is simultaneously blocked from providing their real approval. This directly breaks the core multi-signature security guarantee: that a configurable minimum number of distinct, consenting users must approve before a transaction executes. The stale signature is never re-verified against User C's key after the `userId` swap.

## Likelihood Explanation
This is triggered by a normal, documented workflow: the transaction creator replaces an approver after that approver has already voted. This is a realistic operational scenario (e.g., an approver is unavailable or their key is compromised and must be rotated). The creator role is not a privileged-admin bypass — it is a standard user role. No special privileges beyond being the transaction creator are required to trigger this.

## Recommendation
Replace `undefined` with `null` for the fields that must be explicitly cleared. TypeORM includes `null` values in the SQL `SET` clause, producing `SET "userId" = C, "userKeyId" = NULL, "signature" = NULL, "approved" = NULL`:

```typescript
const data: DeepPartial<TransactionApprover> = {
  userId: dto.userId,
  userKeyId: null,
  signature: null,
  approved: null,
};
``` [6](#0-5) 

Update the corresponding unit test to assert `null` (not `undefined`) and add an integration-level test that verifies the database row is actually cleared after an approver replacement.

## Proof of Concept

1. Create a transaction with a 2-of-2 approver group (User A, User B).
2. As User A, call `POST /transactions/:id/approvers/approve` with a valid signature → row: `userId=A, approved=true, signature=<A_sig>`.
3. As the creator, call `PATCH /transactions/:id/approvers/:approverId` with body `{ "userId": C }`.
4. Query the database: `SELECT "userId","approved","signature","userKeyId" FROM transaction_approver WHERE id = <approverId>`.
   - Expected (correct): `userId=C, approved=NULL, signature=NULL, userKeyId=NULL`
   - Actual (buggy): `userId=C, approved=true, signature=<A_sig>, userKeyId=<A_key_id>`
5. As User C, attempt `POST /transactions/:id/approvers/approve` → receives `400 BadRequest: TAP` (already approved), despite never having approved.
6. Observe that the transaction status computation counts User C as approved, potentially satisfying the 2-of-2 threshold with only User B's genuine approval.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L143-149)
```typescript
      userKeysToSign.length === 0 &&
      transaction.creatorKey?.userId !== user.id &&
      !transaction.observers.some(o => o.userId === user.id) &&
      !transaction.signers.some(s => s.userKey?.userId === user.id) &&
      !approvers.some(a => a.userId === user.id)
    )
      throw new UnauthorizedException("You don't have permission to view this transaction");
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L500-512)
```typescript
          if (approver.userId !== dto.userId) {
            const data: DeepPartial<TransactionApprover> = {
              userId: dto.userId,
              userKeyId: undefined,
              signature: undefined,
              approved: undefined,
            };

            approver.userKeyId = undefined;
            approver.signature = undefined;
            approver.approved = undefined;

            await transactionalEntityManager.update(TransactionApprover, approver.id, data);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L563-563)
```typescript
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
```

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L50-64)
```typescript
  @Column({ nullable: true })
  userKeyId?: number;

  @Column({ type: 'bytea', nullable: true })
  signature?: Buffer;

  @ManyToOne(() => User, user => user.approvableTransactions, { nullable: true })
  @JoinColumn({ name: 'userId' })
  user?: User;

  @Column({ nullable: true })
  userId?: number;

  @Column({ nullable: true })
  approved?: boolean;
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.spec.ts (L808-813)
```typescript
      expect(dataSource.manager.update).toHaveBeenCalledWith(TransactionApprover, 1, {
        userId: 12,
        userKeyId: undefined,
        signature: undefined,
        approved: undefined,
      });
```
