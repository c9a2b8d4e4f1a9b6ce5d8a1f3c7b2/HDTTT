Audit Report

## Title
TOCTOU in `approveTransaction` Allows Approvers to Overwrite Their Own Approval Decision

## Summary
The `approveTransaction` function in `approvers.service.ts` performs an "already approved" check against a DB snapshot, then executes an unconditional `UPDATE` several async scheduling points later — with no database-level guard to prevent a concurrent second write from overwriting the first. This allows a malicious approver to silently reverse a persisted approval or rejection, undermining the integrity of the multi-signature workflow.

## Finding Description

**Time of Check** — `approveTransaction` fetches the approver snapshot at line 553 and enforces the duplicate-approval guard at line 563:

```typescript
const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);
const userApprovers = approvers.filter(a => a.userId === user.id);
if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
``` [1](#0-0) 

**Async gap** — two awaited I/O operations follow before the write: `attachKeys` (line 566) and a `findOne` for the transaction (line 575). Each is a Node.js event-loop scheduling point where a second concurrent request can interleave. [2](#0-1) 

**Time of Use** — the update at lines 599–610 uses `.whereInIds(...)` with no `signature IS NULL` predicate, unconditionally overwriting whatever is currently in the database:

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

The check and the write are never made atomic. There is no `WHERE signature IS NULL` guard that would cause the second concurrent write to be a no-op.

## Impact Explanation
A malicious approver can flip their recorded decision after it has already been persisted. In a threshold-approval scenario, this can block or force-approve a transaction contrary to the intended governance outcome, directly breaking the integrity guarantee that `ErrorCodes.TAP` is meant to enforce.

## Likelihood Explanation
The attacker is a normal authenticated user already listed as an approver — no elevated privileges are required. The exploit requires only two concurrent HTTP `POST /approvers/:transactionId/approve` requests, which any HTTP client can issue. The race window spans two `await` points (`attachKeys` and `findOne`), making it wide enough to be reliably triggered.

## Recommendation
Move the "already approved" check **inside** the same database transaction as the write, and add a `WHERE signature IS NULL` predicate to the `UPDATE` so the write is a no-op if a signature already exists:

```typescript
await this.dataSource.transaction(async transactionalEntityManager => {
  // Re-read under lock
  const locked = await transactionalEntityManager
    .createQueryBuilder(TransactionApprover, 'a')
    .setLock('pessimistic_write')
    .whereInIds(userApprovers.map(a => a.id))
    .getMany();

  if (locked.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);

  await transactionalEntityManager
    .createQueryBuilder()
    .update(TransactionApprover)
    .set({ userKeyId: dto.userKeyId, signature: dto.signature, approved: dto.approved })
    .whereInIds(locked.filter(a => !a.signature).map(a => a.id))
    // or add: .andWhere('signature IS NULL')
    .execute();
});
```

This makes the check-and-write atomic at the database level, eliminating the race window.

## Proof of Concept

```bash
# Send two concurrent requests with opposite approved values
curl -s -X POST https://host/api/transactions/42/approvers/approve \
  -H "Cookie: session=<approver_session>" \
  -d '{"userKeyId":1,"signature":"<sigA>","approved":true}' &

curl -s -X POST https://host/api/transactions/42/approvers/approve \
  -H "Cookie: session=<approver_session>" \
  -d '{"userKeyId":1,"signature":"<sigB>","approved":false}' &

wait
# Query the DB: approved=false is persisted even though approved=true was submitted first
```

Both requests read the approver snapshot before either write completes, both pass the `every(a => a.signature)` guard, and the second write silently overwrites the first.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L566-578)
```typescript
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
