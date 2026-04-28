### Title
Stale `threshold` in Parent `TransactionApprover` Node After Child Removal Causes Permanent Approval Deadlock

### Summary
When `removeTransactionApprover` deletes a child node from a threshold-based approver tree, the parent node's `threshold` value is never decremented. If the remaining active child count falls below the stored threshold, the transaction's approval condition becomes permanently unsatisfiable. The `updateTransactionApprover` path contains the correct parent-fixup logic, but `removeTransactionApprover` omits it entirely — a direct analog to the Gearbox `_nextCreditAccount` stale-pointer bug.

### Finding Description

**Root cause — `removeNode` does not update the parent's `threshold`:**

`removeTransactionApprover` (line 534) calls `removeNode` (line 539), which executes a recursive SQL `UPDATE` that sets `deletedAt = now()` on the target node and all its descendants. [1](#0-0) 

The SQL touches only the deleted subtree. The **parent** node that pointed to the deleted child is never touched — its `threshold` column retains the value it had when the child existed. [2](#0-1) 

**Contrast with `updateTransactionApprover`**, which correctly handles the parent after detaching a child (lines 417–428): [3](#0-2) 

That block either soft-deletes the parent (if it has no remaining children) or decrements its threshold. No equivalent block exists in the delete path.

**Entry point — the controller:**

`DELETE /transactions/:transactionId/approvers/:id` calls `getCreatorsTransaction` (authorization) and then `removeTransactionApprover`. Any authenticated transaction creator can reach this path. [4](#0-3) 

### Impact Explanation

Consider a threshold tree: `root (threshold=2) → [childA (userId=Alice), childB (userId=Bob)]`.

1. Creator deletes `childA` via `DELETE /transactions/T/approvers/{childA.id}`.
2. `removeNode` soft-deletes `childA`; `root.threshold` remains `2`.
3. Only `childB` (Bob) is now an active approver.
4. Bob approves — the chain service evaluates the tree and finds `threshold=2` satisfied by `1` approval → condition not met.
5. The transaction is **permanently locked**: it can never advance past `WAITING_FOR_SIGNATURES` because the threshold can never be satisfied with one approver.

The creator cannot recover: there is no API to lower the threshold of an existing node without adding a child back, and re-adding a child does not guarantee the threshold invariant is restored correctly.

### Likelihood Explanation

- **Attacker precondition:** authenticated user who created a transaction — no admin or privileged role required.
- **Trigger:** create a threshold tree with ≥2 children, then delete any one child via the standard REST API.
- **Frequency:** any organization workflow that uses threshold approvers and later modifies the approver set is affected.
- This is a normal, documented product flow (threshold approvers are shown in `front-end/docs/api.md` lines 198–229). [5](#0-4) 

### Recommendation

After `removeNode` soft-deletes the target, fetch the parent of the deleted node and apply the same fixup logic already present in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // NEW: fetch parent before deletion
  const parent = approver.listId
    ? await this.repo.findOne(TransactionApprover, {
        relations: ['approvers'],
        where: { id: approver.listId },
      })
    : null;

  await this.removeNode(approver.id);

  // NEW: fix parent threshold (mirrors updateTransactionApprover lines 417-428)
  if (parent) {
    const remaining = parent.approvers.filter(a => a.id !== approver.id).length;
    if (remaining === 0) {
      await this.repo.softRemove(parent);
    } else if (remaining < parent.threshold) {
      await this.repo.update(parent.id, { threshold: remaining });
    }
  }

  emitTransactionStatusUpdate(this.notificationsPublisher, [
    { entityId: approver.transactionId ?? parent?.transactionId },
  ]);
}
```

Note also that `approver.transactionId` is `null` for non-root nodes (only root nodes carry `transactionId`), so the current `emitTransactionStatusUpdate` call at line 541 already emits `entityId: null` for any non-root deletion — the fix above also corrects that secondary issue. [6](#0-5) 

### Proof of Concept

**Setup:**
```
POST /transactions/1/approvers
{
  "approversArray": [{
    "threshold": 2,
    "approvers": [{ "userId": 10 }, { "userId": 11 }]
  }]
}
```
This creates: `root (id=5, threshold=2) → [node6 (userId=10), node7 (userId=11)]`

**Trigger:**
```
DELETE /transactions/1/approvers/6
```

**Observed DB state after deletion:**
- `node6`: `deletedAt = now()` ✓
- `root (id=5)`: `threshold = 2`, `deletedAt = null` ← stale

**Result:**
- User 11 (Bob) calls `POST /transactions/1/approvers/approve` with a valid signature.
- The chain service evaluates the tree: `threshold=2`, active approvals=1 → not satisfied.
- Transaction remains in `WAITING_FOR_SIGNATURES` indefinitely.
- No path exists to recover without direct DB intervention.

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

**File:** front-end/docs/api.md (L198-229)
```markdown
Multiple Threshold Approvers Request (replace "accessTokenHere" with your access token):

```
POST https://example.com/transactions/1/approvers
Authorization: Bearer accessTokenHere
content-type: application/json

{
    approversArray: [
      {
        threshold: 2,
        approvers: [
          {
            threshold: 1,
            approvers: [
              {
                userId: 1,
              },
              {
                userId: 2,
              },
            ],
          },
          {
            userId: 3,
            approvers: [],
          },
        ],
      },
    ],
}
```
```
