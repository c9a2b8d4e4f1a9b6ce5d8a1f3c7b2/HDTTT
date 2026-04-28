### Title
Stale Approval State Persists After Approver Replacement Due to TypeORM `undefined` Skip Behavior

### Summary
In `approvers.service.ts`, the `updateTransactionApprover` function attempts to clear the approval state (`signature`, `userKeyId`, `approved`) when replacing an approver's `userId`. However, it passes `undefined` for these fields in the TypeORM `update` call. TypeORM silently skips `undefined` values in `update` operations, meaning the old approver's signature and approval status remain in the database under the new user's ID. This is a direct analog to the Celo MultiSig `isOwner`/`owners` desynchronization: two representations of the same state (who approved, and who is the approver) become inconsistent.

---

### Finding Description

In `back-end/apps/api/src/transactions/approvers/approvers.service.ts`, the `updateTransactionApprover` function handles the case where the transaction creator replaces one approver user with another: [1](#0-0) 

```typescript
if (approver.userId !== dto.userId) {
  const data: DeepPartial<TransactionApprover> = {
    userId: dto.userId,
    userKeyId: undefined,   // ← TypeORM SKIPS this
    signature: undefined,   // ← TypeORM SKIPS this
    approved: undefined,    // ← TypeORM SKIPS this
  };

  approver.userKeyId = undefined;   // in-memory only
  approver.signature = undefined;   // in-memory only
  approver.approved = undefined;    // in-memory only

  await transactionalEntityManager.update(TransactionApprover, approver.id, data);
  approver.userId = dto.userId;
  ...
}
```

TypeORM's `EntityManager.update()` internally builds a SQL `SET` clause by iterating over the provided object's keys. **Fields with value `undefined` are excluded from the generated SQL entirely.** Only `userId` is written to the database. The `signature`, `userKeyId`, and `approved` columns retain whatever values they held for the previous user.

The in-memory `approver` object is updated to reflect `undefined`, but this object is returned to the caller and discarded. All subsequent reads come from the database, which still holds the old approval state.

**Attack scenario (step-by-step):**

1. Transaction creator sets up a 2-of-2 approver requirement with User A and User B.
2. User A calls `approveTransaction` — their `TransactionApprover` row is updated: `approved = true`, `signature = <A's sig>`, `userKeyId = <A's key>`.
3. Creator calls `PATCH /transactions/:id/approvers/:approverId` with `{ userId: C }` to replace User A with User C.
4. TypeORM executes: `UPDATE transaction_approver SET "userId" = C WHERE id = <row>` — `signature`, `userKeyId`, `approved` are **not touched**.
5. The database row now reads: `userId = C`, `approved = true`, `signature = <A's sig>`.
6. User C's approver record shows them as having already approved with User A's key and signature.

**Consequences:**

- **User C is blocked from approving.** `approveTransaction` checks `if (userApprovers.every(a => a.signature)) throw BadRequestException(ErrorCodes.TAP)` — User C's record has a signature, so the call is rejected. [2](#0-1) 

- **Transaction threshold may be incorrectly satisfied.** The status computation reads `approved = true` for User C, counting a phantom approval toward the required threshold, potentially allowing the transaction to advance to execution without User C's actual consent.

- **`getVerifiedApproversByTransactionId` grants User C access** to view the transaction because `approvers.some(a => a.userId === user.id)` is true, but the approval shown is fraudulent. [3](#0-2) 

- **Signature verification is bypassed.** The stale `signature` is User A's bytes over User A's key. The system never re-verifies it against User C's key after the userId swap.

---

### Impact Explanation

A transaction can reach execution status with fewer genuine approvals than the configured threshold requires. A replaced approver (User C) inherits a phantom "approved" state and is simultaneously locked out from providing their real approval. This breaks the core multi-signature security guarantee of the system: that a configurable minimum number of distinct, consenting users must approve before a transaction executes.

---

### Likelihood Explanation

This is triggered by a normal, documented workflow: the transaction creator replaces an approver after that approver has already voted. This is a realistic operational scenario (e.g., an approver is unavailable or their key is compromised and must be rotated). The creator role is not a trusted-admin bypass — it is a standard user role in the system. No special privileges beyond being the transaction creator are required.

---

### Recommendation

Replace `undefined` with `null` for the fields that must be cleared, so TypeORM includes them in the SQL `SET` clause:

```typescript
const data: DeepPartial<TransactionApprover> = {
  userId: dto.userId,
  userKeyId: null,    // explicitly NULL in DB
  signature: null,    // explicitly NULL in DB
  approved: null,     // explicitly NULL in DB
};
```

Alternatively, use a raw query builder:

```typescript
await transactionalEntityManager
  .createQueryBuilder()
  .update(TransactionApprover)
  .set({ userId: dto.userId, userKeyId: null, signature: null, approved: null })
  .where('id = :id', { id: approver.id })
  .execute();
```

Add a regression test that: (1) creates an approver, (2) has that user approve, (3) replaces the approver userId, (4) asserts the new user's `approved`, `signature`, and `userKeyId` are all `null` in the database.

---

### Proof of Concept

```
POST /transactions/:txId/approvers
Body: { approversArray: [{ userId: A }, { userId: B }] }
→ Creates two approver rows, threshold = 2

POST /transactions/:txId/approvers/:txId/approve  (as User A)
Body: { userKeyId: 1, signature: "0xAAA...", approved: true }
→ DB: row for User A: approved=true, signature="0xAAA...", userKeyId=1

PATCH /transactions/:txId/approvers/:approverRowId  (as creator)
Body: { userId: C }
→ TypeORM SQL: UPDATE transaction_approver SET "userId"=C WHERE id=<row>
→ DB: row now: userId=C, approved=true, signature="0xAAA...", userKeyId=1

POST /transactions/:txId/approvers/:txId/approve  (as User C)
→ userApprovers = [{ userId: C, signature: "0xAAA...", approved: true }]
→ every(a => a.signature) = true  →  throws TAP ("Transaction Already Processed")
→ User C cannot approve

GET /transactions/:txId/status
→ Threshold evaluation counts User C as approved
→ Transaction may advance to WAITING_FOR_EXECUTION with only 1 real approval
``` [4](#0-3) [5](#0-4)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L499-517)
```typescript
          /* Update the user */
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
            approver.userId = dto.userId;
            updated = true;

            return approver;
          }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L562-563)
```typescript
    /* Check if the user has already approved the transaction */
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L598-610)
```typescript
    /* Update the approver with the signature */
    await this.dataSource.transaction(async transactionalEntityManager => {
      await transactionalEntityManager
        .createQueryBuilder()
        .update(TransactionApprover)
        .set({
          userKeyId: dto.userKeyId,
          signature: dto.signature,
          approved: dto.approved,
        })
        .whereInIds(userApprovers.map(a => a.id))
        .execute();
    });
```
