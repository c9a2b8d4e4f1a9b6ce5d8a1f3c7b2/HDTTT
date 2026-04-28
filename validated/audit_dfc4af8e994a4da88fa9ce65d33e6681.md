Looking at the `removeTransactionApprover` flow in the controller and service, I found a concrete authorization bypass.

**The controller** (`approvers.controller.ts` lines 102–113) verifies the caller is the creator of `:transactionId`, then passes the raw `:id` (approver ID) directly to `removeTransactionApprover` — with no check that the approver belongs to that transaction.

**The service** (`approvers.service.ts` lines 533–544) removes any approver by its primary key, with no ownership validation.

---

### Title
Creator of Any Transaction Can Delete Approvers Belonging to Other Transactions (IDOR)

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies only that the caller is the creator of `:transactionId`, but then deletes the approver identified by `:id` without confirming that approver belongs to `:transactionId`. Any authenticated user who has created at least one transaction can delete approvers from any other transaction in the system, bypassing the approval workflow.

### Finding Description

The controller performs a two-step operation with a broken ownership chain:

```
// approvers.controller.ts lines 102–113
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // ← checks ownership of transactionId
  await this.approversService.removeTransactionApprover(id);               // ← deletes approver by id, no cross-check
  return true;
}
``` [1](#0-0) 

`getCreatorsTransaction` only validates that the authenticated user created the transaction referenced by `:transactionId` in the URL. [2](#0-1) 

`removeTransactionApprover` then fetches the approver by its own primary key and deletes it (plus all its children via the recursive SQL) with no check that `approver.transactionId` matches the `:transactionId` URL parameter. [3](#0-2) 

The recursive deletion in `removeNode` soft-deletes the entire subtree rooted at the given approver ID, regardless of which transaction it belongs to. [4](#0-3) 

### Impact Explanation

An attacker who is the creator of **any** transaction (Transaction A) can:

1. Enumerate approver IDs belonging to Transaction B (owned by another user) — approver IDs are sequential integers.
2. Call `DELETE /transactions/A/approvers/<B_approver_id>`.
3. The authorization check passes (attacker is creator of A), and the approver from B is deleted.

Concrete consequences:
- Required approvers are silently removed from transactions the attacker does not own.
- If the remaining approvers satisfy the threshold, the transaction moves to `WAITING_FOR_EXECUTION` without the intended signatories having approved it.
- The transaction creator (victim) loses control over their own approval workflow.
- For high-value Hedera transactions (e.g., system file updates, large HBAR transfers), this can cause unauthorized execution.

### Likelihood Explanation

- Attacker precondition: registered user who has created at least one transaction (no admin role required).
- Approver IDs are sequential integers — trivially enumerable.
- No rate-limiting or anomaly detection is visible on this endpoint.
- The flaw is reachable via a standard authenticated HTTP DELETE request.

### Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver being deleted actually belongs to the transaction in the URL parameter:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Resolve the root node to get the owning transactionId
  const root = await this.getRootNodeFromNode(approver.id);
  if (root?.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to this transaction');

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);
  return result;
}
```

This mirrors the ownership check already present in `updateTransactionApprover` (lines 386–394). [5](#0-4) 

### Proof of Concept

1. Attacker (User A) registers and creates Transaction 1 (any type). Attacker is now the creator of Transaction 1.
2. Victim (User B) creates Transaction 2 with a required approver (User C), which gets approver `id = 42`.
3. Attacker sends:
   ```
   DELETE /transactions/1/approvers/42
   Authorization: Bearer <attacker_jwt>
   ```
4. Server response: `200 true`.
5. Approver 42 (belonging to Transaction 2) is now soft-deleted. Transaction 2's approval requirements are silently modified without User B's knowledge.
6. If the remaining approvers satisfy the threshold, Transaction 2 transitions to `WAITING_FOR_EXECUTION` and may be executed without the intended approval set.

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
