### Title
`removeTransactionApprover` Does Not Adjust Parent Threshold After Child Removal, Permanently Breaking Approval Consensus

### Summary
When a child approver is removed from a threshold tree via `removeTransactionApprover`, the parent node's stored `threshold` value is never updated. If the remaining child count drops below the stored threshold, the approval condition becomes permanently unsatisfiable, locking the transaction in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` indefinitely. This is the direct analog of the StaderOracle strict-equality consensus deadlock: a count of eligible participants decreases while the required threshold stays fixed.

### Finding Description

**Root cause — missing threshold adjustment in `removeTransactionApprover`:**

`removeTransactionApprover` in `back-end/apps/api/src/transactions/approvers/approvers.service.ts` (lines 533–544) simply calls `removeNode(approver.id)`, which soft-deletes the target node and its entire subtree via a recursive SQL `UPDATE`. It performs no check on whether the removed node is a child of a threshold node, and it never reads or updates the parent's `threshold` column. [1](#0-0) 

**Contrast with the correct path — `updateTransactionApprover` with `dto.listId = null`:**

When a child is *detached* (moved to root) via `updateTransactionApprover`, the code explicitly fetches the parent, computes `newParentApproversLength = parent.approvers.length - 1`, and either soft-deletes the parent (if no children remain) or reduces its threshold to `newParentApproversLength` (if the threshold would exceed the new child count). [2](#0-1) 

This protective logic is entirely absent from `removeTransactionApprover`.

**How approval is evaluated — `isApproved`:**

The frontend (and any downstream status check) evaluates approval using:

```typescript
const approvals = approver.approvers.filter(approver => isApproved(approver) === true);
if (approvals.length >= (approver.threshold || approvals.length)) {
  return true;
}
``` [3](#0-2) 

If `threshold = 2` but only 1 child remains after removal, `approvals.length` is at most 1, and `1 >= 2` is permanently false. The transaction can never reach an approved state through that subtree.

**Controller access — who can trigger this:**

The `DELETE /:id` endpoint calls `getCreatorsTransaction` before `removeTransactionApprover`, so only the transaction creator (a normal authenticated user) can invoke this path. [4](#0-3) 

**`removeNode` removes the entire subtree silently:** [5](#0-4) 

If the removed child itself had nested children (a nested threshold group), all of them are deleted, making the parent's threshold violation even more likely.

### Impact Explanation

A transaction whose threshold tree has been left in an impossible state (`threshold > remaining children`) is permanently stuck in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`. No combination of approvals from the remaining approvers can satisfy the stored threshold. The transaction cannot be executed, and the approval integrity of the organization workflow is permanently broken for that transaction. This constitutes an unrecoverable corruption of transaction state reachable through a normal user action.

### Likelihood Explanation

The trigger requires only that the transaction creator removes a child approver from a threshold group where the remaining child count would fall below the threshold (e.g., threshold=2, 2 children, remove 1 → 1 child remains, threshold=2 is unsatisfiable). This is a routine administrative action (reorganizing approvers) that any transaction creator can perform without any elevated privilege. The bug is latent in every threshold tree with `threshold > 1`.

### Recommendation

In `removeTransactionApprover`, after calling `removeNode`, fetch the parent of the removed approver (if any) and apply the same threshold-adjustment logic already present in `updateTransactionApprover`:

1. If `newParentApproversLength === 0`, soft-delete the parent.
2. If `newParentApproversLength < parent.threshold`, update `parent.threshold = newParentApproversLength`.

Alternatively, refactor the shared adjustment logic into a private helper and call it from both `removeTransactionApprover` and `updateTransactionApprover`.

### Proof of Concept

1. Creator creates a transaction with a threshold approver tree: parent node with `threshold = 2`, children = [UserA, UserB].
2. Creator calls `DELETE /transactions/:txId/approvers/:userAId` (the `removeTransactionApprover` endpoint).
3. `removeNode(userAId)` soft-deletes UserA. Parent node still has `threshold = 2`, but now has only 1 child (UserB).
4. UserB submits approval. `isApproved` evaluates: `approvals.length (1) >= threshold (2)` → `false`.
5. No further approver can be added to satisfy the threshold (the parent already has its maximum remaining child). The transaction is permanently stuck in `WAITING_FOR_SIGNATURES`.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L204-231)
```typescript
  /* Soft deletes approvers' tree */
  async removeNode(listId: number): Promise<void> {
    if (!listId || typeof listId !== 'number') return null;

    await this.repo.query(
      `
      with recursive approversToDelete AS
        (
          select "id", "listId", "deletedAt"
          from transaction_approver
          where "id" = $1
  
            union all
              select transaction_approver."id", transaction_approver."listId", transaction_approver."deletedAt"
              from transaction_approver, approversToDelete     
              where approversToDelete."id" = transaction_approver."listId"
      
        )
      update transaction_approver
      set "deletedAt" = now()
      from approversToDelete
      where approversToDelete."id" = transaction_approver."listId" or transaction_approver."id" = $1;
    `,
      [listId],
    );

    // notifyTransactionAction(this.notificationsService);
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L417-428)
```typescript
            if (parent) {
              const newParentApproversLength = parent.approvers.length - 1;

              /* Soft delete the parent if there are no more children */
              if (newParentApproversLength === 0) {
                await transactionalEntityManager.softRemove(TransactionApprover, parent);
              } else if (newParentApproversLength < parent.threshold) {
                /* Update the parent threshold if the current one is more than the children */
                await transactionalEntityManager.update(TransactionApprover, parent.id, {
                  threshold: newParentApproversLength,
                });
              }
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

**File:** front-end/src/renderer/utils/sdk/index.ts (L351-357)
```typescript
  if (approver.approvers) {
    const approvals = approver.approvers.filter(approver => isApproved(approver) === true);
    const rejections = approver.approvers.filter(approver => isApproved(approver) === false);
    if (approvals.length >= (approver.threshold || approvals.length)) {
      return true;
    }
    return rejections.length >= (approver.threshold || rejections.length) ? false : null;
```

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
