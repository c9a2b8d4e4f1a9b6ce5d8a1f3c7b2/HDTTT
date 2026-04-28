### Title
Dead Code in `approveTransaction` Due to Stale In-Memory Data Check — `emitTransactionStatusUpdate` Never Reached on Approval

### Summary
In `back-end/apps/api/src/transactions/approvers/approvers.service.ts`, the `approveTransaction` method updates approver records in the database but then evaluates `userApprovers.every(a => a.approved)` against the stale pre-update in-memory objects. Because those objects still carry `approved = null`, the condition is always `false` when `dto.approved = true`, making the `emitTransactionStatusUpdate` branch unreachable in the approval path — a structural analog to the external report's "comparison against wrong constant" dead-code class.

### Finding Description
In `approveTransaction` (lines 599–618 of `approvers.service.ts`):

```typescript
// Lines 599-610: database is updated; in-memory userApprovers NOT refreshed
await this.dataSource.transaction(async transactionalEntityManager => {
  await transactionalEntityManager
    .createQueryBuilder()
    .update(TransactionApprover)
    .set({ userKeyId: dto.userKeyId, signature: dto.signature, approved: dto.approved })
    .whereInIds(userApprovers.map(a => a.id))
    .execute();
});

// Line 614: stale in-memory check
if (!dto.approved || userApprovers.every(a => a.approved)) {
  emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
} else {
  emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
}
```

`userApprovers` is populated at line 556 from the database **before** the update. After the `createQueryBuilder().update()` call, the in-memory array objects still hold `approved = null`. Therefore:

- When `dto.approved = true`: `!dto.approved` → `false`; `userApprovers.every(a => a.approved)` → `false` (null is falsy). Combined: `false || false` → **always `false`**.
- `emitTransactionStatusUpdate` is **never called** when a user approves.
- `emitTransactionUpdate` is **always called** instead.

The `emitTransactionStatusUpdate` branch is dead code for every approval action. [1](#0-0) [2](#0-1) 

### Impact Explanation
`emitTransactionStatusUpdate` is the event that downstream consumers (chain service, notification service) use to re-evaluate a transaction's status — e.g., to detect that all approvers have approved and transition the transaction from `WAITING_FOR_SIGNATURES` to `WAITING_FOR_EXECUTION`. Because this event is never emitted on approval, the transaction may never automatically advance to the execution stage, effectively freezing it in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` indefinitely unless a separate scheduler independently polls and corrects the state. The approval data is written to the database correctly, but the downstream trigger that acts on it is silently suppressed. [3](#0-2) 

### Likelihood Explanation
This is a deterministic, always-triggered bug. Every call to `approveTransaction` with `dto.approved = true` hits this path. No special attacker preconditions are required — any legitimate approver exercising the normal approval workflow triggers it. The bug is reachable via the standard `POST /transactions/:id/approve` endpoint available to any verified user who is an approver on a transaction. [4](#0-3) 

### Recommendation
After the `createQueryBuilder().update()` call, update the in-memory `userApprovers` objects to reflect the written values before evaluating the condition:

```typescript
// After the DB update, sync in-memory state:
userApprovers.forEach(a => { a.approved = dto.approved; });

if (!dto.approved || userApprovers.every(a => a.approved)) {
  emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
} else {
  emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
}
```

Alternatively, re-fetch the approver records from the database after the update to ensure the condition reflects the actual persisted state. Long-term, avoid evaluating post-write conditions against pre-write in-memory snapshots; use named constants or re-queries to make the intent explicit.

### Proof of Concept
1. Create a transaction with a single approver (User A).
2. User A calls `POST /transactions/:id/approve` with `{ approved: true, userKeyId: ..., signature: ... }`.
3. The database row for User A's approver record is updated: `approved = true`.
4. In memory, `userApprovers[0].approved` is still `null` (stale).
5. Condition: `!true || [{ approved: null }].every(a => a.approved)` → `false || false` → `false`.
6. `emitTransactionUpdate` fires; `emitTransactionStatusUpdate` does **not** fire.
7. The chain service never receives the status-update event signaling that all approvals are complete.
8. The transaction remains stuck in its current status; no automatic progression to `WAITING_FOR_EXECUTION` or execution occurs via the event path. [5](#0-4)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L546-621)
```typescript
  /* Approves a transaction */
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
