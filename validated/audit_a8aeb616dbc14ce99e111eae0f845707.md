Audit Report

## Title
IDOR in `DELETE /transactions/:transactionId/approvers/:id` Allows Any Transaction Creator to Delete Approvers from Arbitrary Transactions

## Summary
The `removeTransactionApprover` controller action validates that the authenticated user is the creator of the transaction identified by `:transactionId`, but never validates that the approver identified by `:id` belongs to that transaction. An attacker who is the creator of any transaction can delete approvers belonging to any other transaction in the system.

## Finding Description

The `DELETE /:id` handler in `approvers.controller.ts` performs two sequential service calls: [1](#0-0) 

1. `getCreatorsTransaction(transactionId, user)` — confirms the caller is the creator of the transaction whose ID appears in the URL parameter. It does **not** return or bind the approvers of that transaction. [2](#0-1) 

2. `removeTransactionApprover(id)` — fetches the approver by its own primary key `id` and deletes it with no check that `approver.transactionId === transactionId`: [3](#0-2) 

The cross-object ownership check is entirely absent. By contrast, `updateTransactionApprover` — the sibling PATCH handler — correctly performs this check before proceeding: [4](#0-3) 

The DELETE path simply omits the equivalent guard, making the `transactionId` URL parameter a meaningless authorization token for the actual deletion.

## Impact Explanation
Any authenticated user who has created at least one transaction can permanently delete approvers from any transaction in the system. This allows:
- Bypassing approval workflows on transactions the attacker does not own
- Removing required approvers from high-value or sensitive transactions
- Disrupting the integrity of the approval process across the entire platform

The impact is a direct, unauthorized destructive write operation on data the attacker has no legitimate access to.

## Likelihood Explanation
Exploitation requires only a valid authenticated session and knowledge (or enumeration) of an approver `id` from another transaction. Approver IDs are sequential integers, making enumeration trivial. No special privileges, race conditions, or complex setup are required beyond having created at least one transaction.

## Recommendation
In `removeTransactionApprover` (or in the controller before calling it), verify that the fetched approver's root transaction matches the `transactionId` URL parameter, mirroring the pattern already used in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    // Resolve root node to handle nested approvers
    const rootNode = await this.getRootNodeFromNode(approver.id);
    if (!rootNode || rootNode.transactionId !== transactionId)
        throw new UnauthorizedException('Root transaction is not the same');

    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
    return result;
}
```

Pass `transactionId` from the controller into `removeTransactionApprover` and enforce the ownership check before deletion.

## Proof of Concept

**Setup:**
- User A creates Transaction `T1` (id=1) — attacker-controlled
- User B creates Transaction `T2` (id=2) with an approver (id=99) — victim

**Attack:**
```
DELETE /transactions/1/approvers/99
Authorization: Bearer <User A's JWT>
```

**Execution trace:**
1. `getCreatorsTransaction(1, UserA)` — passes, UserA is creator of T1
2. `removeTransactionApprover(99)` — fetches approver id=99 (belongs to T2), no ownership check, deletes it
3. Approver 99 from T2 is permanently deleted; UserA never had any rights over T2 [5](#0-4)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L386-391)
```typescript
        const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
        if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

        /* Verifies that the root transaction is the same as the param */
        if (rootNode.transactionId !== transactionId)
          throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L624-644)
```typescript
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
