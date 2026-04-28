All code references verified against the actual source. The vulnerability is real and confirmed.

---

Audit Report

## Title
Missing Transaction Ownership Cross-Check in `removeTransactionApprover` Allows Deletion of Approvers Belonging to Other Transactions

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller owns the transaction at `:transactionId`, but never verifies that the approver at `:id` belongs to that same transaction. Any authenticated user who owns at least one transaction can delete approvers from any other transaction in the system.

## Finding Description
In `approvers.controller.ts`, the delete handler performs two sequential calls:

```typescript
await this.approversService.getCreatorsTransaction(transactionId, user);
await this.approversService.removeTransactionApprover(id);
``` [1](#0-0) 

`getCreatorsTransaction(transactionId, user)` confirms the caller created the transaction identified by `:transactionId`. However, `removeTransactionApprover(id)` then deletes the approver row by `:id` alone — no `transactionId` parameter is passed, and no cross-reference check is performed:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);
    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(...);
    return result;
}
``` [2](#0-1) 

By contrast, `updateTransactionApprover` in the same service correctly performs this guard:

```typescript
const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);
if (rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
``` [3](#0-2) 

The delete path is missing the equivalent guard that the update path has. The root cause is that `removeTransactionApprover` accepts only `id` and never resolves the approver's root node to verify `rootNode.transactionId === transactionId`.

## Impact Explanation
An attacker who is the creator of any transaction (even a trivial one they created themselves) can delete approvers from any other transaction in the system. Removing required approvers can:
- Cause a transaction to bypass its intended approval threshold.
- Silently eliminate a required signer from the approval tree, allowing a transaction to proceed without the intended authorization.
- Disrupt the approval workflow of victim transactions without the victim's knowledge.

## Likelihood Explanation
Any registered, verified user can create a transaction, satisfying the ownership check on their own transaction. Approver IDs are auto-incremented sequential integers (standard TypeORM/PostgreSQL behavior), making enumeration trivial. No special privilege is required beyond a valid account. The attack requires only two pieces of information: the attacker's own `transactionId` and a target `approverId` from another transaction.

## Recommendation
In `removeTransactionApprover` in `approvers.service.ts`, add the same cross-check that `updateTransactionApprover` already performs: resolve the root node from the approver and verify `rootNode.transactionId === transactionId` before proceeding with deletion. The service method signature should be updated to accept `transactionId` as a parameter, and the controller should pass it through.

Concretely, mirror the pattern at lines 386–394 of `approvers.service.ts`:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const rootNode = await this.getRootNodeFromNode(approver.id);
    if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);
    if (rootNode.transactionId !== transactionId)
        throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
    return result;
}
```

And update the controller call accordingly:

```typescript
await this.approversService.removeTransactionApprover(id, transactionId);
```

## Proof of Concept

1. Attacker (user A) creates their own transaction → receives `attackerTransactionId = 1`.
2. Attacker enumerates approver IDs (sequential integers) and identifies `victimApproverId = 42`, which belongs to a different transaction owned by user B.
3. Attacker sends:
   ```
   DELETE /transactions/1/approvers/42
   Authorization: Bearer <attacker_jwt>
   ```
4. The server calls `getCreatorsTransaction(1, userA)` → passes (attacker owns transaction 1).
5. The server calls `removeTransactionApprover(42)` → deletes approver 42 with no cross-check.
6. Approver 42, belonging to user B's transaction, is now soft-deleted. User B's transaction approval workflow is disrupted. [4](#0-3) [2](#0-1)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L102-113)
```typescript
  @Delete('/:id')
  async removeTransactionApprover(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Param('id', ParseIntPipe) id: number,
  ) {
    await this.approversService.getCreatorsTransaction(transactionId, user);
    await this.approversService.removeTransactionApprover(id);
    // await this.approversService.emitSyncIndicators(transactionId);

    return true;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L386-394)
```typescript
        const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
        if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

        /* Verifies that the root transaction is the same as the param */
        if (rootNode.transactionId !== transactionId)
          throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

        /* Verifies that the user is the creator of the transaction */
        await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L534-544)
```typescript
  async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);

    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const result = await this.removeNode(approver.id);

    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);

    return result;
  }
```
