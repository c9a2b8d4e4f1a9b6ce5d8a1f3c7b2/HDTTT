### Title
`removeTransactionApprover` Fails to Update Parent Threshold on Child Node Removal, Permanently Locking Transaction Approval

### Summary
`ApproversService.removeTransactionApprover` soft-deletes an approver node and its subtree via `removeNode`, but never adjusts the parent threshold node's `threshold` field when the deleted node is a child (has a `listId`). This leaves the parent in a state where `threshold > remaining_children_count`, making the approval condition permanently unsatisfiable and freezing the transaction's approval workflow. The same parent-threshold correction that exists in `updateTransactionApprover` (when detaching a child via `dto.listId = null`) is entirely absent from the delete path.

### Finding Description

**Root cause — `removeTransactionApprover` / `removeNode`**

`removeTransactionApprover` fetches the approver and delegates to `removeNode`:

```typescript
// back-end/apps/api/src/transactions/approvers/approvers.service.ts
async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);
    const result = await this.removeNode(approver.id);          // ← deletes node + subtree
    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
    return result;
}
``` [1](#0-0) 

`removeNode` soft-deletes the target node and all its descendants via a recursive CTE, but performs **no update to the parent's `threshold`**: [2](#0-1) 

**Contrast — `updateTransactionApprover` correctly adjusts the parent**

When a child is detached via `dto.listId = null`, the code explicitly reads the parent's child count and either soft-deletes the parent (if empty) or lowers its threshold:

```typescript
if (parent) {
    const newParentApproversLength = parent.approvers.length - 1;
    if (newParentApproversLength === 0) {
        await transactionalEntityManager.softRemove(TransactionApprover, parent);
    } else if (newParentApproversLength < parent.threshold) {
        await transactionalEntityManager.update(TransactionApprover, parent.id, {
            threshold: newParentApproversLength,
        });
    }
}
``` [3](#0-2) 

This correction is **completely absent** from `removeTransactionApprover`.

**Entry point — controller**

The `DELETE /:id` endpoint verifies only that the caller is the transaction creator; it places no restriction on whether the target approver is a root or a child node:

```typescript
@Delete('/:id')
async removeTransactionApprover(@GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Param('id', ParseIntPipe) id: number) {
    await this.approversService.getCreatorsTransaction(transactionId, user);
    await this.approversService.removeTransactionApprover(id);
    return true;
}
``` [1](#0-0) [4](#0-3) 

**Resulting inconsistent state**

After removing a child node whose parent has `threshold = N` and `N` children, the parent retains `threshold = N` but now has only `N-1` children. The `isApproved` utility evaluates:

```typescript
const approvals = approver.approvers.filter(approver => isApproved(approver) === true);
if (approvals.length >= (approver.threshold || approvals.length)) { return true; }
``` [5](#0-4) 

With `threshold = N` and only `N-1` possible approvers, `approvals.length` can never reach `threshold`, so `isApproved` can never return `true` for that subtree.

### Impact Explanation

A transaction whose approval tree has a threshold node with a removed child is permanently stuck: the threshold condition can never be satisfied, the transaction can never advance from `WAITING_FOR_SIGNATURES` / `WAITING_FOR_EXECUTION` to execution, and it cannot be re-approved. The transaction creator cannot recover the state without cancelling the transaction entirely. This constitutes **permanent lock / unrecoverable corruption of transaction state**.

### Likelihood Explanation

The attacker precondition is simply being the authenticated creator of a transaction that uses a threshold approver tree — a normal, unprivileged user role. The trigger is a single `DELETE /transactions/:transactionId/approvers/:child_id` API call targeting any child approver node (one with a non-null `listId`). No special knowledge or tooling is required; the approver IDs are returned by the `GET /transactions/:transactionId/approvers` endpoint visible to the creator.

### Recommendation

In `removeTransactionApprover`, after soft-deleting the node, check whether the deleted approver had a parent (`listId !== null`). If so, fetch the parent with its remaining children and apply the same threshold correction that `updateTransactionApprover` already performs:

1. If the parent has no remaining active children → soft-delete the parent.
2. If the parent's `threshold` now exceeds the remaining child count → lower `threshold` to `remaining_children_count`.

Wrap the entire operation in a database transaction to keep the state atomic.

### Proof of Concept

1. Authenticate as a normal user (transaction creator).
2. Create a transaction with a threshold approver tree:
   - Root: `{ threshold: 2, approvers: [{ userId: A }, { userId: B }] }` → parent id=10, children id=11 (userId A), id=12 (userId B).
3. Call `DELETE /transactions/1/approvers/11` (remove child A).
4. `removeNode(11)` soft-deletes row 11. Parent row 10 still has `threshold = 2`.
5. Only child 12 (userId B) remains. Even if B approves, `approvals.length = 1 < threshold = 2`.
6. `isApproved(parent)` returns `null` forever; the transaction can never reach execution.
7. The transaction is permanently frozen in `WAITING_FOR_SIGNATURES`. [2](#0-1) [1](#0-0)

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

**File:** front-end/src/renderer/utils/sdk/index.ts (L342-358)
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
```
