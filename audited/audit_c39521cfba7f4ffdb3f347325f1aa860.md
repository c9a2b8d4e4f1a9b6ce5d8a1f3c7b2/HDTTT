### Title
Stale In-Memory State After DB Write Causes `emitTransactionStatusUpdate` to Never Fire on Approval

### Summary
In `approveTransaction` within `approvers.service.ts`, the `userApprovers` array is loaded from the database before the approval DB write. After the write, the in-memory objects are never refreshed. A post-write guard condition that decides whether to emit a status-update event (`emitTransactionStatusUpdate`) or a plain update event (`emitTransactionUpdate`) reads the stale in-memory `approved` field. Because the stale value is always `null/undefined` for a first-time approval, the condition evaluates to `false` and `emitTransactionStatusUpdate` is never emitted on the approval path. This is the TypeScript/TypeORM analog of the Solidity memory-vs-storage bug: state is correctly written to the database but the in-memory copy is not refreshed, causing downstream logic that depends on the updated value to silently misbehave.

### Finding Description

**Root cause — stale in-memory read after DB write**

`approveTransaction` loads the user's approver records into memory:

```typescript
const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);
const userApprovers = approvers.filter(a => a.userId === user.id);
``` [1](#0-0) 

It then writes the new approval state to the database:

```typescript
await transactionalEntityManager
  .createQueryBuilder()
  .update(TransactionApprover)
  .set({ userKeyId: dto.userKeyId, signature: dto.signature, approved: dto.approved })
  .whereInIds(userApprovers.map(a => a.id))
  .execute();
``` [2](#0-1) 

Immediately after the write, the code decides which notification to emit using the **same stale in-memory array**:

```typescript
if (!dto.approved || userApprovers.every(a => a.approved)) {
  emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
} else {
  emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
}
``` [3](#0-2) 

The in-memory `userApprovers[i].approved` values were loaded before the write and are still `null/undefined`. `userApprovers.every(a => a.approved)` therefore always evaluates to `false` on the approval path (`dto.approved = true`). The short-circuit `!dto.approved` is also `false` when approving. The combined condition is always `false`, so `emitTransactionUpdate` is always called instead of `emitTransactionStatusUpdate`.

**The only path that correctly fires `emitTransactionStatusUpdate` is rejection** (`dto.approved = false`), because `!dto.approved` short-circuits to `true`.

**Comparison with the external report**

| External (Solidity) | This codebase (TypeScript) |
|---|---|
| `RedeemRequest memory request = $.redeemRequests[msg.sender]` — copy loaded into memory | `userApprovers` loaded from DB before write |
| `request.assets -= …` — mutation on copy, not storage | `approved` written to DB but in-memory copy not refreshed |
| `$.redeemRequests[msg.sender]` never updated | `userApprovers[i].approved` never updated after DB write |
| Downstream check reads stale copy | `userApprovers.every(a => a.approved)` reads stale copy |

### Impact Explanation

`emitTransactionStatusUpdate` is the event that triggers the chain service to re-evaluate whether a transaction can advance (e.g., from `WAITING_FOR_SIGNATURES` → `WAITING_FOR_EXECUTION`). Because it is never emitted on the approval path, a transaction that has received all required approvals will not automatically advance to execution. The transaction is stuck in its current status until an external trigger (e.g., a signing event, a separate polling cycle, or a manual action) causes a status re-evaluation. In the worst case — where no other trigger fires — the transaction is permanently frozen in the approval state despite all approvers having signed off. [4](#0-3) 

### Likelihood Explanation

This code path is exercised every time any user approves a transaction. The stale-read condition is deterministic: for any first-time approval, `userApprovers[i].approved` is `null/undefined` before the write, so the guard always misfires. No special attacker setup is required; any normal user performing a normal approval triggers the bug.

### Recommendation

After the DB write, update the in-memory `userApprovers` objects to reflect the persisted state before evaluating the notification condition:

```typescript
// After the DB write:
userApprovers.forEach(a => { a.approved = dto.approved; });

if (!dto.approved || userApprovers.every(a => a.approved)) {
  emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
} else {
  emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
}
```

Alternatively, re-query the approver records from the database after the write to obtain fresh state before making the notification decision.

### Proof of Concept

1. Create a transaction that requires a single approver (User A).
2. User A calls `POST /transactions/:id/approvers/approve` with `approved: true` and a valid signature.
3. The DB row for User A's `TransactionApprover` is correctly updated: `approved = true`, `signature = <bytes>`, `userKeyId = <id>`.
4. In memory, `userApprovers[0].approved` is still `null` (the value before the write).
5. `userApprovers.every(a => a.approved)` → `every(a => null)` → `false`.
6. `!dto.approved` → `!true` → `false`.
7. Combined: `false || false` → `false` → `emitTransactionUpdate` is called, NOT `emitTransactionStatusUpdate`.
8. The chain service receives no status-update event and does not re-evaluate the transaction.
9. The transaction remains in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` indefinitely, even though all required approvals are present in the database. [5](#0-4)

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
