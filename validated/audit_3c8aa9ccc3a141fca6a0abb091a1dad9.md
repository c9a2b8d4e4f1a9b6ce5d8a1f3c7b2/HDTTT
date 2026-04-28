### Title
Cross-Transaction Approver Deletion via Missing Ownership Validation in `removeTransactionApprover`

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the authenticated user is the creator of `:transactionId`, but then passes `:id` directly to `removeTransactionApprover` without confirming that the approver record actually belongs to `:transactionId`. Any authenticated user who owns at least one transaction can delete approvers from any other user's transaction by supplying their own `transactionId` for the authorization check and a victim's approver `id` for the deletion.

### Finding Description
In `back-end/apps/api/src/transactions/approvers/approvers.controller.ts`, the `DELETE /:id` handler performs two independent operations:

```typescript
await this.approversService.getCreatorsTransaction(transactionId, user); // checks ownership of transactionId
await this.approversService.removeTransactionApprover(id);               // deletes approver by id, no cross-check
``` [1](#0-0) 

`getCreatorsTransaction` only verifies that `user` is the creator of the transaction identified by `transactionId` in the URL — it says nothing about `id`. [2](#0-1) 

`removeTransactionApprover` then fetches the approver by `id` alone and soft-deletes it and its entire subtree with no check that `approver.transactionId` matches the URL's `transactionId`. [3](#0-2) 

The recursive `removeNode` CTE deletes the targeted node and all its children unconditionally. [4](#0-3) 

By contrast, the observers subsystem correctly resolves the transaction from the observer record itself and checks creator ownership before any mutation, making it immune to this class of attack. [5](#0-4) 

### Impact Explanation
An attacker can silently remove any approver (or an entire approver subtree) from any transaction in the system, regardless of who owns it. This directly undermines the multi-signature approval workflow: a transaction that required N-of-M approvals can have its approver tree gutted, potentially allowing it to proceed with fewer approvals than intended, or permanently corrupting the approval state of a victim's pending transaction. This constitutes unauthorized state mutation of another user's transaction data.

### Likelihood Explanation
The attacker only needs to be an authenticated, verified user who is the creator of any one transaction (even a self-created dummy transaction). Approver IDs are sequential auto-increment integers, making them trivially enumerable. No privileged access, leaked credentials, or admin keys are required. The attack is a single crafted HTTP DELETE request.

### Recommendation
Inside `removeTransactionApprover` (or in the controller before calling it), resolve the root transaction of the approver being deleted and assert it equals the `transactionId` from the URL. The existing `getRootNodeFromNode` helper already traverses to the root and exposes `transactionId`; use it:

```typescript
const root = await this.getRootNodeFromNode(approver.id);
if (!root || root.transactionId !== expectedTransactionId) {
  throw new UnauthorizedException('Approver does not belong to this transaction');
}
```

This mirrors the pattern already used in `updateTransactionApprover`, which correctly calls `getRootNodeFromNode` and validates `rootNode.transactionId !== transactionId` before proceeding. [6](#0-5) 

### Proof of Concept

**Setup:**
- Attacker (User A) is authenticated and is the creator of transaction `T_A` (id = 1).
- Victim (User B) owns transaction `T_B` (id = 2) with approver record id = 99.

**Steps:**
1. Attacker sends:
   ```
   DELETE /transactions/1/approvers/99
   Authorization: Bearer <attacker_jwt>
   ```
2. Controller calls `getCreatorsTransaction(1, userA)` → succeeds (User A owns T_A).
3. Controller calls `removeTransactionApprover(99)` → fetches approver 99 (belongs to T_B), calls `removeNode(99)`, soft-deletes approver 99 and all its children.
4. Victim's transaction T_B now has its approver tree partially or fully destroyed.

**Expected result (correct behavior):** 403/401 — approver 99 does not belong to transaction 1.
**Actual result:** 200 — approver 99 is deleted from T_B.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L385-394)
```typescript
        /* Gets the root approver */
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L623-644)
```typescript
  /* Get the transaction by id and verifies that the user is the creator */
  async getCreatorsTransaction(
    transactionId: number,
    user: User,
    entityManager?: EntityManager,
  ): Promise<Transaction> {
    const find: FindOneOptions<Transaction> = {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user'],
    };

    const transaction = await (entityManager
      ? entityManager.findOne(Transaction, find)
      : this.dataSource.manager.findOne(Transaction, find));

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to modify it');

    return transaction;
  }
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L144-160)
```typescript
  private async getUpdateableObserver(id: number, user: User): Promise<TransactionObserver> {
    const observer = await this.repo.findOneBy({ id });

    if (!observer) throw new BadRequestException(ErrorCodes.ONF);

    const transaction = await this.entityManager.findOne(Transaction, {
      where: { id: observer.transactionId },
      relations: ['creatorKey', 'creatorKey.user'],
    });

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to update it');

    return observer;
  }
```
