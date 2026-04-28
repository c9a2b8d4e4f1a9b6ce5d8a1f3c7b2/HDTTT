### Title
`removeTransactionApprover` Does Not Atomically Update Parent `threshold` When a Child Approver Is Deleted

### Summary
The `threshold` and `approvers` (child count) of a `TransactionApprover` tree node are interdependent: the system enforces `threshold <= approvers.length` at creation and during `updateTransactionApprover`. However, `removeTransactionApprover` deletes a child node without adjusting the parent's `threshold`, breaking this invariant and leaving the approval tree in a state where the threshold can never be satisfied.

### Finding Description

The system maintains a tree of `TransactionApprover` records. Each internal (tree) node stores a `threshold` value that must satisfy:

```
1 <= threshold <= approvers.length
```

This invariant is enforced at creation time: [1](#0-0) 

And during the `updateTransactionApprover` detach path (`listId: null`), the parent's threshold is correctly adjusted when a child is detached: [2](#0-1) 

However, `removeTransactionApprover` simply calls `removeNode(approver.id)` with no parent threshold adjustment: [3](#0-2) 

`removeNode` performs a recursive soft-delete of the target node and all its descendants, but never touches the parent record: [4](#0-3) 

The controller's `DELETE /:id` endpoint accepts any approver `id` (child or root) and does not restrict deletion to root nodes: [5](#0-4) 

**Concrete scenario:**

1. Creator sets up an approval tree: Parent node P (`threshold=2`, children=[A, B]).
2. Creator calls `DELETE /transactions/:txId/approvers/:A.id`.
3. `removeNode(A.id)` soft-deletes A and A's subtree.
4. Parent P now has `threshold=2` but only 1 active child (B).
5. Invariant violated: `threshold (2) > approvers.length (1)`.
6. The approval requirement can never be satisfied — only 1 approver exists but 2 are required.

### Impact Explanation

The transaction's organization-level approval workflow is permanently broken until the creator manually discovers the inconsistency and calls `updateTransactionApprover` to lower the threshold. During this window, the transaction remains stuck in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`. If the Hedera transaction's `validStart` window expires before the creator corrects the threshold, the transaction expires and cannot be executed, resulting in a lost transaction.

### Likelihood Explanation

Any transaction creator can trigger this by deleting a child approver node via the standard `DELETE /transactions/:transactionId/approvers/:id` endpoint. No special privileges beyond being the transaction creator are required. The scenario arises naturally when a creator wants to remove one member from a multi-member threshold group without realizing the threshold must also be reduced.

### Recommendation

In `removeTransactionApprover`, before calling `removeNode`, fetch the parent of the target approver (if any) and atomically adjust the parent's `threshold` — mirroring the logic already present in `updateTransactionApprover` for the `listId: null` detach path:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  await this.dataSource.transaction(async em => {
    if (approver.listId !== null) {
      const parent = await em.findOne(TransactionApprover, {
        relations: ['approvers'],
        where: { id: approver.listId },
      });
      if (parent) {
        const newChildCount = parent.approvers.length - 1;
        if (newChildCount === 0) {
          await em.softRemove(TransactionApprover, parent);
        } else if (newChildCount < parent.threshold) {
          await em.update(TransactionApprover, parent.id, { threshold: newChildCount });
        }
      }
    }
    await this.removeNode(id); // existing recursive soft-delete
  });

  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
}
```

### Proof of Concept

1. Create a transaction as User A (creator).
2. Add a threshold approver tree: `POST /transactions/:txId/approvers` with `{ approversArray: [{ threshold: 2, approvers: [{ userId: B }, { userId: C }] }] }`. This creates parent P (`threshold=2`) with children B and C.
3. Note the `id` of child B's approver record (e.g., `id=2`).
4. Delete child B: `DELETE /transactions/:txId/approvers/2`.
5. Query the approvers: `GET /transactions/:txId/approvers`. Parent P still shows `threshold=2` but now has only 1 child (C).
6. User C attempts to approve: `POST /transactions/:txId/approvers/approve`. The approval is recorded, but the threshold of 2 is never reached — the transaction is permanently stuck awaiting a second approval that can never come. [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L302-307)
```typescript
          /* Check if the approver threshold is less or equal to the number of approvers */
          if (
            dtoApprover.approvers &&
            (dtoApprover.threshold > dtoApprover.approvers.length || dtoApprover.threshold === 0)
          )
            throw new Error(this.THRESHOLD_LESS_OR_EQUAL_APPROVERS(dtoApprover.approvers.length));
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
