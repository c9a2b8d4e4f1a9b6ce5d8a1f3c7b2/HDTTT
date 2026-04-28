### Title
`removeTransactionApprover` Does Not Update Parent Threshold When a Child Approver Is Deleted, Permanently Blocking Transaction Approval

### Summary

When a child node in a threshold-based approver tree is deleted via `removeTransactionApprover`, the parent node's `threshold` value is not decremented. If the remaining child count falls below the stored threshold, the approval condition becomes mathematically impossible to satisfy, permanently locking the transaction in a non-executable state. This is the direct analog of the Derby M-39 vulnerability: a removal operation zeroes out a member's contribution but does not update the aggregate counter used for downstream calculations.

### Finding Description

**Vulnerability class:** Accounting / state-transition invariant violation.

**Root cause — `removeNode` does not touch the parent's `threshold`:**

`removeTransactionApprover` fetches any approver by id (root or child) and delegates to `removeNode`: [1](#0-0) 

`removeNode` executes a recursive SQL soft-delete that removes the target node and all its descendants, but never touches the parent row: [2](#0-1) 

The SQL `WHERE` clause only matches `transaction_approver."id" = $1` (the target) and `approversToDelete."id" = transaction_approver."listId"` (descendants). The parent row — whose `listId` points to the deleted child — is never updated.

**Contrast with `updateTransactionApprover` (the correct path):**

When a child is *detached* (not deleted) via `PATCH`, the code explicitly adjusts the parent: [3](#0-2) 

This guard is entirely absent in the `DELETE` path.

**Secondary compounding bug — status update emitted with `null` entity ID:**

For child nodes, `transactionId` is stored as `null` (only root nodes carry the `transactionId` FK). After deletion, the notification is fired as: [4](#0-3) 

`approver.transactionId` is `null` for any child node, so the status-update event is emitted with `entityId: null` — the transaction's status is never re-evaluated after the deletion.

**Approval evaluation uses the stale `threshold`:**

The `isApproved` helper (and the backend equivalent) reads the stored `threshold` field directly: [5](#0-4) 

If `threshold=2` but only 1 child remains, `approvals.length >= 2` can never be true → the tree node is permanently unapproved.

**Exploit path (no privilege beyond being the transaction creator):**

1. Creator sets up a threshold approver tree: parent `threshold=2`, children = [User A, User B].
2. Creator calls `DELETE /transactions/:txId/approvers/:childAId` (the id of User A's approver row).
3. `removeNode` soft-deletes User A's row; parent row still has `threshold=2`, `approvers=[User B]`.
4. User B approves → `approvals.length = 1 < threshold = 2` → approval never satisfies.
5. Transaction is permanently stuck in `WAITING_FOR_SIGNATURES`; it can never reach `WAITING_FOR_EXECUTION` or `EXECUTED`.

The controller performs no check that the supplied `id` is a root node: [6](#0-5) 

### Impact Explanation

A transaction creator (normal authenticated user, no admin role required) can permanently freeze any of their own transactions in a non-executable state. Once the threshold exceeds the remaining approver count, no combination of approvals can satisfy it, and there is no self-healing mechanism. The transaction will eventually expire, causing loss of the intended on-chain operation. In an organization context where transactions represent time-sensitive Hedera operations (account updates, file changes, token transfers), this is a permanent, unrecoverable denial of the transaction's purpose.

### Likelihood Explanation

The trigger is a normal product workflow: a creator removes one approver from a threshold group intending to replace them. The `DELETE` endpoint is documented and reachable by any authenticated transaction creator. No special timing, race condition, or privileged access is required. The bug fires deterministically on every deletion of a child approver when `threshold > (children - 1)`.

### Recommendation

In `removeTransactionApprover`, before calling `removeNode`, fetch the parent of the target approver (if any) and apply the same threshold-adjustment logic already present in `updateTransactionApprover`:

1. If `parent.approvers.length - 1 === 0` → soft-delete the parent as well (no children left).
2. If `parent.threshold > parent.approvers.length - 1` → update `parent.threshold` to `parent.approvers.length - 1`.

Additionally, resolve the `null` `transactionId` issue by traversing to the root node (via `getRootNodeFromNode`) before emitting the status-update event, so the correct `transactionId` is always used.

### Proof of Concept

```
# Setup: transaction T1, creator = User C
POST /transactions/1/approvers
Body: { approversArray: [{ threshold: 2, approvers: [{ userId: 10 }, { userId: 11 }] }] }
# DB state: parent(id=5, threshold=2, listId=null, transactionId=1)
#            child1(id=6, userId=10, listId=5, transactionId=null)
#            child2(id=7, userId=11, listId=5, transactionId=null)

# Attacker (= creator) deletes child1
DELETE /transactions/1/approvers/6
# removeNode(6) soft-deletes row id=6 only.
# parent row id=5 still has threshold=2, but approvers=[child2] (length=1).
# emitTransactionStatusUpdate called with entityId=null → no status re-evaluation.

# User 11 approves
POST /transactions/1/approvers/approve  (as User 11)
# isApproved: approvals.length=1 < threshold=2 → returns null (not approved)
# Transaction stays WAITING_FOR_SIGNATURES forever.
# No further approver can be added to the deleted child's slot without
# also fixing the threshold, which requires a separate PATCH call that
# the creator may not know is needed.
```

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L417-429)
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

**File:** front-end/src/renderer/utils/sdk/index.ts (L342-361)
```typescript
export const isApproved = (approver: ITransactionApprover): boolean | null => {
  if (approver.approved === false) {
    return false;
  }

  if (approver.approved === true) {
    return true;
  }

  if (approver.approvers) {
    const approvals = approver.approvers.filter(approver => isApproved(approver) === true);
    const rejections = approver.approvers.filter(approver => isApproved(approver) === false);
    if (approvals.length >= (approver.threshold || approvals.length)) {
      return true;
    }
    return rejections.length >= (approver.threshold || rejections.length) ? false : null;
  }

  return null;
};
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
