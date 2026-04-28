### Title
TOCTOU Race Condition in `approveTransaction` Allows Approval State Corruption

### Summary
The `approveTransaction` function in `ApproversService` performs a non-atomic check-then-write sequence: it reads the current approval state, checks whether the user has already approved, and then writes the new approval in a separate database operation. Two concurrent requests from the same user can both pass the "already approved" guard before either write completes, allowing a user to overwrite their own approval decision — including flipping `approved: true` to `approved: false` after the threshold has already been met.

### Finding Description

In `back-end/apps/api/src/transactions/approvers/approvers.service.ts`, the `approveTransaction` function follows this sequence:

**Step 1 — Read approvers (check state):** [1](#0-0) 

```typescript
const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);
const userApprovers = approvers.filter(a => a.userId === user.id);
if (userApprovers.length === 0)
  throw new UnauthorizedException('You are not an approver of this transaction');
if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
```

**Step 2 — Multiple async operations (gap window):** [2](#0-1) 

`attachKeys`, a second `findOne` for the transaction, signature verification — all async, all outside any lock.

**Step 3 — Write approval using the stale `userApprovers` snapshot:** [3](#0-2) 

```typescript
await this.dataSource.transaction(async transactionalEntityManager => {
  await transactionalEntityManager
    .createQueryBuilder()
    .update(TransactionApprover)
    .set({ userKeyId: dto.userKeyId, signature: dto.signature, approved: dto.approved })
    .whereInIds(userApprovers.map(a => a.id))
    .execute();
});
```

The `whereInIds` clause contains **no condition on the current signature/approved state**. It unconditionally overwrites whatever is in the database. Two concurrent requests that both read `signature = null` at Step 1 will both pass the guard at Step 2 and both execute the write at Step 3.

By contrast, the `cancelTransactionWithOutcome` function in `transactions.service.ts` correctly uses a conditional update to make the check-and-write atomic: [4](#0-3) 

```typescript
.where('id = :id', { id })
.andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
```

No such guard exists in the approval write path. The `@MurLock` distributed lock used in `ExecuteService` is also absent here: [5](#0-4) 

### Impact Explanation

A malicious authenticated user who is a designated approver can:

1. Send two concurrent `POST /approvers/:transactionId/approve` requests — one with `approved: true` and one with `approved: false`.
2. Both requests read `signature = null`, both pass the `every(a => a.signature)` guard.
3. Both writes execute. The last write wins, potentially flipping a committed approval to a rejection (or vice versa) after the approval threshold was already satisfied.
4. This corrupts the approval state of the transaction: a threshold that was legitimately met can be undermined, or a rejection can be silently overwritten with an approval.

The `approved` field directly controls whether the transaction proceeds to execution. Corrupting it can either block a legitimately approved transaction or force through a transaction that should have been rejected.

### Likelihood Explanation

The attacker is a normal authenticated user with no elevated privileges — only the approver role on a transaction, which is a standard product role. The exploit requires only two concurrent HTTP requests, trivially achievable with any HTTP client (`Promise.all`, `curl` with `&`, etc.). No cryptographic break or privileged access is needed. The race window spans multiple async database calls and is wide enough to be reliably hit.

### Recommendation

Make the check and write atomic by adding a `WHERE signature IS NULL` condition to the update query, so the write only succeeds if the approval has not yet been recorded:

```typescript
await transactionalEntityManager
  .createQueryBuilder()
  .update(TransactionApprover)
  .set({ userKeyId: dto.userKeyId, signature: dto.signature, approved: dto.approved })
  .whereInIds(userApprovers.map(a => a.id))
  .andWhere('signature IS NULL')   // <-- atomic guard
  .execute();
```

Then check `updateResult.affected` and throw `ErrorCodes.TAP` if zero rows were updated (meaning another concurrent request already wrote the approval). This mirrors the pattern already used correctly in `cancelTransactionWithOutcome`. [6](#0-5) 

Alternatively, apply a `@MurLock` keyed on `transactionId + userId` to serialize concurrent approval requests for the same user on the same transaction, consistent with the locking pattern already used in `ExecuteService`. [5](#0-4) 

### Proof of Concept

**Preconditions:**
- Transaction `T` exists with status `WAITING_FOR_SIGNATURES`.
- User `U` is a designated approver of `T`.
- `U` has not yet approved.

**Steps:**
```javascript
// Attacker sends two concurrent requests with opposite approval decisions
const [r1, r2] = await Promise.all([
  fetch(`/api/transactions/${T}/approve`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify({ userKeyId: keyId, signature: sig, approved: true }),
  }),
  fetch(`/api/transactions/${T}/approve`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify({ userKeyId: keyId, signature: sig, approved: false }),
  }),
]);
```

**Expected outcome (correct):** One request succeeds; the second is rejected with `ErrorCodes.TAP` (already approved).

**Actual outcome (vulnerable):** Both requests return success. The final `approved` value in the database is whichever write completed last — non-deterministically `true` or `false` — regardless of which request the user intended to be authoritative. If the approval threshold was met by the first write, the second write can silently undo it.

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L673-704)
```typescript
    const updateResult = await this.repo
      .createQueryBuilder()
      .update(Transaction)
      .set({ status: TransactionStatus.CANCELED })
      .where('id = :id', { id })
      .andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
      .execute();

    if (updateResult.affected && updateResult.affected > 0) {
      emitTransactionStatusUpdate(
        this.notificationsPublisher,
        [{
          entityId: id,
          additionalData: {
            transactionId: transaction.transactionId,
            network: transaction.mirrorNetwork,
          },
        }],
      );

      return CancelTransactionOutcome.CANCELED;
    }

    // Race-safe fallback: state changed between read and update, so re-check current status.
    const latestTransaction = await this.getTransactionForCreator(id, user);
    if (latestTransaction.status === TransactionStatus.CANCELED) {
      return CancelTransactionOutcome.ALREADY_CANCELED;
    }
    if (!this.cancelableStatuses.includes(latestTransaction.status)) {
      throw new BadRequestException(ErrorCodes.OTIP);
    }
    throw new ConflictException('Cancellation conflict');
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L41-42)
```typescript
  @MurLock(15000, 'transaction.id')
  async executeTransaction(transaction: Transaction) {
```
