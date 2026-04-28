### Title
Cross-Transaction Approver Deletion via Missing Ownership Verification in `removeTransactionApprover`

### Summary
The `removeTransactionApprover` endpoint verifies the requesting user is the creator of the `transactionId` supplied in the URL, but then deletes an approver node looked up solely by its `id` — with no check that the approver actually belongs to that transaction. Any authenticated user who has created at least one transaction can delete approvers from any other transaction by supplying a valid approver `id` from a different transaction.

### Finding Description

**Entry point** — `DELETE /transactions/:transactionId/approvers/:id`

In `approvers.controller.ts` the handler is:

```typescript
await this.approversService.getCreatorsTransaction(transactionId, user); // checks user owns transactionId
await this.approversService.removeTransactionApprover(id);               // deletes approver by id alone
``` [1](#0-0) 

`removeTransactionApprover` then fetches the approver by `id` with no `transactionId` filter and immediately deletes it:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);   // no transactionId filter
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);            // deletes node + all descendants
  ...
}
``` [2](#0-1) 

`getTransactionApproverById` queries only on `id`:

```typescript
const find: FindOneOptions<TransactionApprover> = {
  relations: ['approvers'],
  where: { id },
};
``` [3](#0-2) 

`removeNode` then recursively soft-deletes the target node and every descendant:

```typescript
update transaction_approver
set "deletedAt" = now()
from approversToDelete
where approversToDelete."id" = transaction_approver."listId" or transaction_approver."id" = $1;
``` [4](#0-3) 

The authorization gate (`getCreatorsTransaction`) only proves the caller owns `transactionId` from the URL — it says nothing about whether the approver `id` in the path belongs to that transaction. The two checks are completely decoupled.

### Impact Explanation

A malicious transaction creator can permanently soft-delete any approver node (and its entire subtree) from any other user's transaction. Because `TransactionApprover` nodes represent the multi-signature approval tree for high-value Hedera transactions, removing them:

- Eliminates required signers from another organization's transaction, allowing it to proceed without the intended approvals.
- Permanently corrupts the approval workflow (soft-delete is not reversed by normal flows).
- Affects the `threshold` invariant: if a parent node's child count drops below its threshold, the transaction can never reach the required approval count.

This is a **critical integrity failure** in the trust model of the multi-signature orchestration system.

### Likelihood Explanation

- **Attacker precondition:** Any authenticated user who has created at least one transaction. No admin or privileged role required.
- **Target discovery:** `TransactionApprover` IDs are sequential auto-incremented integers (`@PrimaryGeneratedColumn()`), making them trivially enumerable. [5](#0-4) 
- **Trigger:** A single crafted `DELETE` request.
- **Detection difficulty:** The operation looks like a normal approver deletion in logs; the only anomaly is the mismatch between `transactionId` in the URL and the actual transaction the approver belongs to.

### Recommendation

Inside `removeTransactionApprover`, verify the fetched approver's root transaction matches the `transactionId` supplied by the caller before deleting:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Verify the approver belongs to the expected transaction
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to this transaction');

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);
  return result;
}
```

Pass `transactionId` from the controller into `removeTransactionApprover`. This mirrors the pattern already used correctly in `updateTransactionApprover`. [6](#0-5) 

### Proof of Concept

**Setup:**
- User A creates Transaction 1 (becomes its creator).
- User B creates Transaction 2 with an approver tree: root node (threshold=1) → child node (User C, `id = 42`).

**Exploit:**
```
DELETE /transactions/1/approvers/42
Authorization: Bearer <User A's token>
```

**Step-by-step execution:**
1. Controller calls `getCreatorsTransaction(1, userA)` → succeeds (User A owns Transaction 1). [7](#0-6) 
2. Controller calls `removeTransactionApprover(42)`.
3. `getTransactionApproverById(42)` returns approver 42 (belongs to Transaction 2) — no ownership check. [8](#0-7) 
4. `removeNode(42)` soft-deletes approver 42 and all its descendants. [9](#0-8) 

**Result:** Approver 42 (User C) is permanently removed from Transaction 2's approval tree. Transaction 2 now has no approvers and can proceed without the intended multi-signature approval, or is left in a broken state where the threshold can never be satisfied.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L66-82)
```typescript
  getTransactionApproverById(
    id: number,
    entityManager?: EntityManager,
  ): Promise<TransactionApprover> {
    if (!id) return null;

    const find: FindOneOptions<TransactionApprover> = {
      relations: ['approvers'],
      where: { id },
    };

    if (entityManager) {
      return entityManager.findOne(TransactionApprover, find);
    }

    return this.repo.findOne(find);
  }
```

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

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L21-22)
```typescript
  @PrimaryGeneratedColumn()
  id: number;
```
