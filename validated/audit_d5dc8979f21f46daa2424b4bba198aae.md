### Title
Broken Threshold State After Child Approver Removal Causes Permanently Unsatisfiable Approval Requirement

### Summary
When `removeTransactionApprover()` deletes a child node from a threshold-based approver tree, the parent's `threshold` value is never decremented. If the parent's threshold was equal to its child count before deletion, the approval requirement becomes permanently unsatisfiable — no combination of approvals can ever satisfy it. Additionally, the authorization check in the controller verifies the caller is the creator of the URL-supplied `transactionId`, but never verifies the approver `id` belongs to that transaction, allowing any authenticated user who has created at least one transaction to delete approvers from any other transaction.

### Finding Description

**Root cause — threshold not updated on child removal:**

`removeTransactionApprover` in `approvers.service.ts` fetches the approver and calls `removeNode`, which recursively soft-deletes the node and all its descendants. Neither function reads or updates the parent's `threshold`. [1](#0-0) 

`removeNode` only sets `deletedAt` on the target and its descendants; it never touches the parent row: [2](#0-1) 

The codebase already contains the correct fix pattern — `updateTransactionApprover` (the "detach" path) does update the parent threshold after removing a child: [3](#0-2) 

`removeTransactionApprover` simply omits this step entirely.

**Root cause — missing ownership check on the approver id:**

The controller verifies the caller is the creator of `transactionId`, then passes the unrelated `id` directly to `removeTransactionApprover` with no cross-check: [4](#0-3) 

`removeTransactionApprover` never verifies that the approver belongs to the transaction in the URL: [1](#0-0) 

**Combined exploit path:**

1. Attacker (any authenticated user) creates transaction T_attacker — this satisfies `getCreatorsTransaction`.
2. Attacker enumerates or guesses the `id` of a child approver belonging to victim transaction T_victim whose parent has `threshold = N` and exactly `N` children.
3. Attacker calls `DELETE /transactions/T_attacker/approvers/<child_id>`.
4. `getCreatorsTransaction(T_attacker, attacker)` passes.
5. `removeTransactionApprover(<child_id>)` deletes the child from T_victim's tree.
6. The parent node still has `threshold = N` but now has only `N-1` children.
7. T_victim's approval requirement can never be satisfied; the transaction is permanently locked.

### Impact Explanation

A permanently unsatisfiable threshold means the victim's transaction can never reach `WAITING_FOR_EXECUTION` status and can never be submitted to the Hedera network. The transaction is effectively frozen with no recovery path short of cancellation. For high-value or time-sensitive Hedera transactions (e.g., council-level account updates, large HBAR transfers), this constitutes permanent loss of the transaction's utility and potential financial harm.

**Impact: High** — permanent, unrecoverable lock of victim transactions.

### Likelihood Explanation

Any registered user can create a transaction (no special role required), satisfying the only precondition. Approver IDs are sequential integers assigned by the database, making enumeration trivial. The attack requires only a single authenticated API call. No leaked secrets or admin access are needed.

**Likelihood: High** — low barrier, reachable by any authenticated user.

### Recommendation

1. **Fix the threshold update gap in `removeTransactionApprover`:** After `removeNode`, fetch the deleted approver's parent (if any) and apply the same threshold-correction logic already present in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id); // includes relations: ['approvers']
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Fetch parent before deletion
  if (approver.listId) {
    const parent = await this.repo.findOne({
      relations: ['approvers'],
      where: { id: approver.listId },
    });
    if (parent) {
      const newChildCount = parent.approvers.length - 1;
      if (newChildCount === 0) {
        await this.repo.softRemove(parent);
      } else if (newChildCount < parent.threshold) {
        await this.repo.update(parent.id, { threshold: newChildCount });
      }
    }
  }

  await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
}
```

2. **Fix the authorization bypass in the controller:** After `getCreatorsTransaction`, verify the approver (or its root) belongs to `transactionId` before deletion:

```typescript
const root = await this.approversService.getRootNodeFromNode(id);
if (!root || root.transactionId !== transactionId) {
  throw new UnauthorizedException('Approver does not belong to this transaction');
}
```

### Proof of Concept

**Setup:**
- User A creates transaction T_A (A becomes creator).
- User B creates transaction T_B with a threshold approver tree: root node R (threshold=2) with children C1 (userId=10) and C2 (userId=11). C1 gets database id=42.

**Attack:**
```
DELETE /api/transactions/{T_A}/approvers/42
Authorization: Bearer <User A's JWT>
```

**Result:**
- `getCreatorsTransaction(T_A, A)` passes — A is creator of T_A.
- `removeTransactionApprover(42)` deletes C1 from T_B's tree.
- R still has `threshold=2` but only one child (C2).
- T_B's approval requirement requires 2 approvals but only 1 approver exists.
- T_B is permanently locked and can never be submitted to the Hedera network.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L205-231)
```typescript
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
