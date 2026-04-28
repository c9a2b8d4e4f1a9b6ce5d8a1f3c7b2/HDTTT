Looking at the actual code to validate each claim.

Audit Report

## Title
`removeTransactionApprover` Does Not Update Parent Threshold After Child Removal, Permanently Locking Transaction Approval State

## Summary
`removeTransactionApprover` in `approvers.service.ts` soft-deletes an approver node without reading or adjusting the parent list's `threshold`. If the parent's threshold exceeds the remaining child count after deletion, the approval condition becomes permanently unsatisfiable. Additionally, the controller's authorization check binds to the URL `transactionId` but the service never verifies the deleted approver belongs to that transaction, enabling a cross-transaction deletion attack.

## Finding Description

**Root cause — missing threshold adjustment:**

`removeTransactionApprover` (line 534) accepts only an `id`, calls `removeNode`, and emits a status event. It never reads the parent node, never checks `threshold ≤ remaining_children`, and never updates the parent record. [1](#0-0) 

Contrast with the `updateTransactionApprover` detach path (`dto.listId === null`), which explicitly reads the parent, computes `newParentApproversLength`, and reduces the threshold when `newParentApproversLength < parent.threshold`: [2](#0-1) 

The `removeTransactionApprover` code path has no equivalent guard.

**Root cause — missing approver-to-transaction ownership check:**

The controller calls `getCreatorsTransaction(transactionId, user)` (verifying the caller is creator of the URL's `transactionId`), then calls `removeTransactionApprover(id)` with no further binding between `id` and `transactionId`: [3](#0-2) 

`removeTransactionApprover` never verifies that the approver `id` belongs to the transaction the caller is authorized for. A creator of transaction A can supply any approver `id` from transaction B and delete it.

## Impact Explanation

1. **Stuck transaction (self or cross-transaction):** After a child approver is deleted, the parent list retains its original `threshold`. If `threshold > remaining_children`, no combination of approvals can satisfy the condition. The transaction is permanently locked in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` with no recovery path short of cancellation.

2. **Cross-transaction approver deletion:** Because the service does not bind the approver `id` to the URL `transactionId`, the creator of any transaction can delete approvers belonging to *other* transactions, triggering the stuck-state on transactions they do not own.

## Likelihood Explanation

The trigger is a normal `DELETE /transactions/:transactionId/approvers/:id` API call requiring only a valid JWT and creator status on *any* transaction. No cryptographic break or privileged key is required. The cross-transaction vector requires only knowledge of a target approver's numeric `id`, which is predictable from sequential integer primary keys. Any organization workflow using threshold approver trees is affected.

## Recommendation

1. **In `removeTransactionApprover`:** After calling `removeNode`, fetch the deleted approver's parent (if any), recount its remaining non-deleted children, and either soft-delete the parent (if zero children remain) or reduce `parent.threshold` to `remaining_children` when `remaining_children < parent.threshold` — mirroring the logic already present in `updateTransactionApprover` at lines 417–428.

2. **Bind approver to transaction:** Before executing the deletion, verify that the root node of the approver tree (via `getRootNodeFromNode`) has `transactionId` equal to the URL parameter `transactionId`. Throw `UnauthorizedException` if they differ. This check should live inside `removeTransactionApprover` (not only in the controller) to enforce the invariant at the service layer regardless of caller.

## Proof of Concept

**Stuck-state scenario:**
1. Creator builds: `parent (threshold=2)` → children `[UserA, UserB]`.
2. Creator calls `DELETE /transactions/T/approvers/UserA.id`.
3. Controller passes `getCreatorsTransaction(T, creator)` — authorized.
4. `removeNode(UserA.id)` soft-deletes UserA. Parent now has `threshold=2`, `children=[UserB]`.
5. Only 1 approver remains; threshold of 2 is unreachable. Transaction T is permanently stuck.

**Cross-transaction scenario:**
1. Attacker is creator of transaction A (threshold=1, one approver).
2. Attacker discovers approver ID `42` belonging to transaction B (owned by another user), which has `parent (threshold=2)` → `[approver42, approver43]`.
3. Attacker calls `DELETE /transactions/A/approvers/42`.
4. `getCreatorsTransaction(A, attacker)` passes (attacker owns A).
5. `removeTransactionApprover(42)` deletes approver 42 from transaction B with no ownership check.
6. Transaction B's parent now has `threshold=2`, `children=[approver43]` — permanently stuck.

### Citations

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
