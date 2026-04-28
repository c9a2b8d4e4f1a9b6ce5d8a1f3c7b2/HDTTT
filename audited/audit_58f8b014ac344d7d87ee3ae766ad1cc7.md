### Title
TOCTOU in `approveTransaction` Allows Approvers to Overwrite Their Own Approval Decision

### Summary
The `approveTransaction` function in `approvers.service.ts` performs a "user has already approved" check using a snapshot of approver records fetched at the start of the function, then executes an unconditional `UPDATE` several async operations later. Because the update carries no `WHERE signature IS NULL` guard, two concurrent requests from the same approver can both pass the check and both commit — allowing the second write to silently overwrite the first. This lets a malicious approver flip their recorded approval/rejection after it has already been persisted, undermining the integrity of the multi-signature approval workflow.

### Finding Description

**Time of Check** — `approvers.service.ts` line 553 fetches the approver snapshot and line 563 enforces the "already approved" guard:

```typescript
const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);
const userApprovers = approvers.filter(a => a.userId === user.id);
if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
``` [1](#0-0) 

**Async gap** — three awaited operations follow before the write: `attachKeys`, a `findOne` for the transaction, and `verifyTransactionBodyWithoutNodeAccountIdSignature`. Each introduces a scheduling point where the Node.js event loop can interleave a second concurrent request. [2](#0-1) 

**Time of Use** — the update at lines 599–610 uses `whereInIds` with no `signature IS NULL` predicate, so it unconditionally overwrites whatever is currently in the database:

```typescript
await this.dataSource.transaction(async transactionalEntityManager => {
  await transactionalEntityManager
    .createQueryBuilder()
    .update(TransactionApprover)
    .set({ userKeyId: dto.userKeyId, signature: dto.signature, approved: dto.approved })
    .whereInIds(userApprovers.map(a => a.id))
    .execute();
});
``` [3](#0-2) 

The check and the write are never made atomic. There is no database-level guard equivalent to `WHERE signature IS NULL` that would cause the second concurrent write to be a no-op.

### Impact Explanation

A malicious approver can:

1. Send **Request A** (`approved=true`, `signature=sigA`) and **Request B** (`approved=false`, `signature=sigB`) simultaneously.
2. Both requests read the approver snapshot before either write completes — both pass the `every(a => a.signature)` guard.
3. Request A commits `approved=true`.
4. Request B commits `approved=false`, silently overwriting Request A.

The final persisted state is `approved=false` even though the approver "approved" first. This breaks the integrity of the multi-signature approval workflow: an approver can effectively reverse a decision that the system is designed to make irrevocable once submitted (`ErrorCodes.TAP`). In a threshold-approval scenario this can block or force-approve a transaction contrary to the intended governance outcome.

### Likelihood Explanation

The attacker is a **normal authenticated user** who is already listed as an approver — no privileged access is required. The exploit requires only two concurrent HTTP requests to `POST /approvers/:transactionId/approve`, which any HTTP client can issue. The async gap spans multiple `await` points, making the race window wide enough to be reliably triggered without any special timing.

### Recommendation

Add a `WHERE signature IS NULL` (or equivalent) predicate to the update query so that the write is a no-op if a signature has already been recorded:

```typescript
.update(TransactionApprover)
.set({ userKeyId: dto.userKeyId, signature: dto.signature, approved: dto.approved })
.whereInIds(userApprovers.map(a => a.id))
.andWhere('signature IS NULL')   // ← atomic guard
.execute();
```

Alternatively, wrap the entire read-check-write sequence in a serializable database transaction with a `SELECT … FOR UPDATE` on the approver rows, making the check and the write atomic at the database level.

### Proof of Concept

**Preconditions**: Transaction T exists in `WAITING_FOR_SIGNATURES` status; User U is a listed approver with no prior signature.

**Steps**:

1. User U sends two concurrent HTTP requests to `PATCH /approvers/{transactionId}/approve`:
   - Request A: `{ userKeyId: k, signature: sigA, approved: true }`
   - Request B: `{ userKeyId: k, signature: sigB, approved: false }`

2. Both requests execute `getVerifiedApproversByTransactionId` before either write completes. Both see `signature = null` on the approver row and pass the `every(a => a.signature)` check at line 563.

3. Request A writes `approved=true, signature=sigA`.

4. Request B writes `approved=false, signature=sigB`, overwriting Request A.

5. Query the `transaction_approver` table: the row shows `approved=false` — the approver has effectively rejected a transaction they approved, bypassing `ErrorCodes.TAP`.

**Expected result without fix**: Both requests return HTTP 200 and the second write wins.
**Expected result with fix**: The second write matches 0 rows (signature already set) and the first decision is preserved.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L553-563)
```typescript
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);

    /* If user is approver, filter the records that belongs to the user */
    const userApprovers = approvers.filter(a => a.userId === user.id);

    /* Check if the user is an approver */
    if (userApprovers.length === 0)
      throw new UnauthorizedException('You are not an approver of this transaction');

    /* Check if the user has already approved the transaction */
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L565-596)
```typescript
    /* Ensures the user keys are passed */
    await attachKeys(user, this.dataSource.manager);
    if (user.keys.length === 0) return false;

    const signatureKey = user.keys.find(key => key.id === dto.userKeyId);

    /* Gets the public key that the signature belongs to */
    const publicKey = PublicKey.fromString(signatureKey?.publicKey);

    /* Get the transaction body */
    const transaction = await this.dataSource.manager.findOne(Transaction, {
      where: { id: transactionId },
      relations: { creatorKey: true, observers: true },
    });

    /* Check if the transaction exists */
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    /* Checks if the transaction is requires approval */
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    /* Verify the signature matches the transaction */
    if (
      !verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTransaction, dto.signature, publicKey)
    )
      throw new BadRequestException(ErrorCodes.SNMP);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L599-610)
```typescript
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
