The code has been verified. Here is the audit report:

---

Audit Report

## Title
TOCTOU Race Condition in `approveTransaction` Allows Approver to Overwrite Their Own Approval Decision

## Summary
`ApproversService.approveTransaction()` in `back-end/apps/api/src/transactions/approvers/approvers.service.ts` performs a non-atomic check-then-act sequence. The duplicate-approval guard reads approver state from the database and checks it before the write, but the subsequent `UPDATE` carries no conditional clause (`WHERE signature IS NULL`). Two concurrent HTTP requests from the same approver both pass the guard on a stale snapshot and both execute the `UPDATE`, with the last write winning. This allows a malicious approver to flip their recorded vote after it has already been committed, corrupting the approval state of a transaction.

## Finding Description

**Root cause — non-atomic check-then-act**

`approveTransaction` follows this sequence:

1. **Read** all approvers for the transaction at line 553. [1](#0-0) 

2. **Check** whether the caller has already approved at line 563 — `if (userApprovers.every(a => a.signature))`. [2](#0-1) 

3. Perform several sequential `await` calls that widen the race window: `attachKeys` (line 566), `findOne` for the transaction (line 575), and `verifyTransactionBodyWithoutNodeAccountIdSignature` (line 593). [3](#0-2) 

4. **Write** the approval unconditionally — `UPDATE TransactionApprover SET … WHERE id IN (…)` with no `AND signature IS NULL` predicate. [4](#0-3) 

The guard at step 2 is evaluated against a snapshot that is already stale by the time step 4 executes. Because the `UPDATE` at step 4 contains no conditional predicate to make the write idempotent, a second concurrent request that passed the guard on the same stale snapshot will unconditionally overwrite the first write.

Additionally, the notification branch at lines 614–618 reads `userApprovers.every(a => a.approved)` from the pre-race stale snapshot, so the downstream status event emitted is also incorrect. [5](#0-4) 

## Impact Explanation

The approval workflow is a trust-enforcement mechanism: a transaction cannot proceed to execution unless the required threshold of approvers have set `approved=true`. By racing two concurrent requests, a malicious approver can:

- **Flip their vote** from `approved=true` to `approved=false` after the fact, blocking a transaction that had already satisfied the approval threshold.
- **Corrupt the recorded key/signature** (`userKeyId`, `signature`) associated with their approval, breaking audit integrity.
- **Emit a misleading status event** to the notification bus because the notification branch reads the pre-race stale `userApprovers` array.

This is an unauthorized state change that violates the core invariant: once an approver has submitted their decision, it must be immutable.

## Likelihood Explanation

The attacker is a legitimate approver — a role reachable by any registered user who was added to a transaction's approver list. No privileged credentials are required. Triggering the race requires only two near-simultaneous HTTP requests, achievable with any scripting tool (`curl`, `axios`, `fetch`). The race window is wide because `approveTransaction` performs multiple sequential `await` calls between the guard read and the final write (`attachKeys`, `findOne`, `verifyTransactionBodyWithoutNodeAccountIdSignature`), giving ample time for a second request to pass the guard before the first write commits.

## Recommendation

Make the write conditional by adding a `AND signature IS NULL` predicate to the `UPDATE` query, so that the write is a no-op if a signature has already been recorded:

```ts
await transactionalEntityManager
  .createQueryBuilder()
  .update(TransactionApprover)
  .set({
    userKeyId: dto.userKeyId,
    signature: dto.signature,
    approved: dto.approved,
  })
  .whereInIds(userApprovers.map(a => a.id))
  .andWhere('signature IS NULL')   // <-- add this
  .execute();
```

Alternatively, move the entire check-then-act sequence (guard read + write) inside a single database transaction with a `SELECT … FOR UPDATE` (pessimistic row lock) so that concurrent requests are serialized at the database level. After the write, re-fetch the updated rows from the database before constructing the notification event, rather than relying on the pre-race `userApprovers` snapshot.

## Proof of Concept

```
Attacker (legitimate approver) sends two concurrent POST requests:
  Request A → { approved: true,  userKeyId: X, signature: sigA }
  Request B → { approved: false, userKeyId: Y, signature: sigB }

Timeline:
  A reads approvers  → signature = null  → passes guard (line 563)
  B reads approvers  → signature = null  → passes guard (line 563)
  A executes awaits  (attachKeys, findOne, verify)
  B executes awaits  (attachKeys, findOne, verify)
  A writes DB        → approved=true,  signature=sigA  (lines 599–610)
  B writes DB        → approved=false, signature=sigB  ← overwrites A (lines 599–610)

Final DB state: approved=false, signature=sigB
Even though the approver had already committed approved=true.
``` [6](#0-5)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L547-621)
```typescript
  async approveTransaction(
    dto: ApproverChoiceDto,
    transactionId: number,
    user: User,
  ): Promise<boolean> {
    /* Get all the approvers */
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);

    /* If user is approver, filter the records that belongs to the user */
    const userApprovers = approvers.filter(a => a.userId === user.id);

    /* Check if the user is an approver */
    if (userApprovers.length === 0)
      throw new UnauthorizedException('You are not an approver of this transaction');

    /* Check if the user has already approved the transaction */
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);

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

    const notificationEvent = [{ entityId: transaction.id }];

    if (!dto.approved || userApprovers.every(a => a.approved)) {
      emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
    } else {
      emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
    }

    return true;
  }
```
