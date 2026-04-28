### Title
Missing Approver-to-Transaction Ownership Validation in `removeTransactionApprover`

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the calling user is the creator of the transaction identified by `:transactionId`, but then removes the approver identified by `:id` without checking that the approver actually belongs to that transaction. Any authenticated user who is the creator of at least one transaction can delete approvers from any other transaction in the system.

### Finding Description
In `approvers.controller.ts`, the `removeTransactionApprover` handler performs two independent operations:

1. `getCreatorsTransaction(transactionId, user)` — verifies the caller owns the transaction in the URL path parameter.
2. `removeTransactionApprover(id)` — removes the approver by its own primary key `id`, with no cross-check against `transactionId`. [1](#0-0) 

Inside `ApproversService.removeTransactionApprover`, the service fetches the approver by `id` and immediately deletes it. There is no assertion that `approver.transactionId === transactionId` (or that the approver's root transaction matches the URL-supplied `transactionId`). [2](#0-1) 

This is the direct analog of the external report's "missing parent bond validation": the function processes an entity (approver) without verifying it belongs to the specified parent (transaction).

Compare with `updateTransactionApprover`, which correctly validates `rootNode.transactionId !== transactionId` before proceeding: [3](#0-2) 

The delete path has no equivalent guard.

### Impact Explanation
An attacker who is the creator of any transaction (even a trivial one they created themselves) can delete approvers from any other transaction in the system. This disrupts the approval workflow — removing required approvers from transactions they do not own — and can allow transactions to bypass intended approval thresholds, undermining the multi-signature governance model of the organization.

### Likelihood Explanation
Any authenticated, verified organization member who has ever created a transaction satisfies the precondition. The approver `id` values are sequential integers, making enumeration trivial. No elevated privileges are required.

### Recommendation
Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver being deleted belongs to the transaction the caller is authorized for:

```typescript
// In the controller, after getCreatorsTransaction:
const approver = await this.approversService.getTransactionApproverById(id);
if (!approver) throw new BadRequestException(ErrorCodes.ANF);

// Walk to root and confirm ownership
const root = await this.approversService.getRootNodeFromNode(approver.id);
if (root?.transactionId !== transactionId) {
  throw new UnauthorizedException('Approver does not belong to this transaction');
}

await this.approversService.removeTransactionApprover(id);
```

Alternatively, add the cross-check inside `removeTransactionApprover` by accepting `transactionId` as a required parameter and asserting the relationship before deletion.

### Proof of Concept

1. Attacker (User A) creates Transaction A — they are now its creator.
2. Victim (User B) creates Transaction B and adds Approver X (approver ID = 42) to it.
3. Attacker calls:
   ```
   DELETE /transactions/{A_id}/approvers/42
   Authorization: Bearer <User A's token>
   ```
4. `getCreatorsTransaction(A_id, userA)` passes — User A owns Transaction A.
5. `removeTransactionApprover(42)` executes — Approver 42 (belonging to Transaction B) is deleted with no ownership check.
6. Transaction B's approval structure is now corrupted without User B's knowledge or consent. [1](#0-0) [2](#0-1)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L389-391)
```typescript
        /* Verifies that the root transaction is the same as the param */
        if (rootNode.transactionId !== transactionId)
          throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L533-544)
```typescript
  /* Removes the transaction approver by id */
  async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);

    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const result = await this.removeNode(approver.id);

    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);

    return result;
  }
```
