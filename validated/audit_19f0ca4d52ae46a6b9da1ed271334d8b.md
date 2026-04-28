The code confirms this is a real vulnerability. The contrast with `updateTransactionApprover` is particularly telling — the update path explicitly validates the cross-reference, but the delete path does not.

**`updateTransactionApprover`** (lines 386–391) correctly does:
```typescript
const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
```

**`removeTransactionApprover`** (lines 534–544) does none of that — it only looks up the approver by `id` and deletes it.

---

Audit Report

## Title
IDOR in `removeTransactionApprover` Allows Any Transaction Creator to Delete Approvers from Arbitrary Transactions

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller is the creator of `:transactionId` but never validates that the approver record identified by `:id` actually belongs to that transaction. An authenticated user who has created any transaction can pass their own `transactionId` for the ownership check while targeting an approver `id` from a completely different transaction, silently deleting it.

## Finding Description

**Root cause — missing cross-reference check in the delete path**

The controller performs an ownership check on `transactionId`, then unconditionally delegates deletion using the unrelated `id` parameter:

`back-end/apps/api/src/transactions/approvers/approvers.controller.ts`, lines 102–113: [1](#0-0) 

```typescript
await this.approversService.getCreatorsTransaction(transactionId, user); // checks ownership of transactionId only
await this.approversService.removeTransactionApprover(id);               // deletes approver by id — no cross-check
```

The service method `removeTransactionApprover` accepts only the approver primary key and performs no transaction-membership validation:

`back-end/apps/api/src/transactions/approvers/approvers.service.ts`, lines 534–544: [2](#0-1) 

`getCreatorsTransaction` only verifies `creatorKey.userId === user.id` for the supplied `transactionId`: [3](#0-2) 

There is no subsequent assertion that the approver record's own `transactionId` field matches the URL parameter. The two IDs are never compared.

**The fix already exists in the sibling method — it was simply omitted from delete**

`updateTransactionApprover` correctly performs the cross-reference check before acting: [4](#0-3) 

```typescript
const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
```

This pattern is entirely absent from `removeTransactionApprover`.

## Impact Explanation

Approvers represent the multi-signature approval gate that must be satisfied before a Hedera transaction can be executed. Removing approvers from a victim transaction:

- **Bypasses approval requirements**: if all approvers are stripped, the transaction may advance to `WAITING_FOR_EXECUTION` without any human approval, enabling unauthorized on-chain execution.
- **Disrupts organizational workflows**: silently removing approvers corrupts the governance model for any transaction in the system.
- **Permanent state corruption**: `removeNode` performs a soft-delete via raw SQL (`set "deletedAt" = now()`); approvers are not automatically restored and recovery requires manual database intervention. [5](#0-4) 

## Likelihood Explanation

- **Attacker preconditions**: only a valid JWT (any registered organization user). Creating one transaction is sufficient to pass the ownership check.
- **Approver ID discovery**: IDs are sequential integers exposed in API responses (`GET /transactions/:transactionId/approvers`) to any user who is a participant in at least one transaction.
- **No rate limiting or anomaly detection** is visible in the codebase.
- The attack requires a single HTTP request per targeted approver.

## Recommendation

Apply the same cross-reference pattern already used in `updateTransactionApprover` to `removeTransactionApprover`. Before calling `removeNode`, resolve the root node of the approver and assert its `transactionId` matches the URL parameter, then re-verify creator ownership against that root transaction:

```typescript
async removeTransactionApprover(id: number, transactionId: number, user: User): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Cross-reference: ensure the approver belongs to the claimed transaction
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to this transaction');

  // Re-verify creator ownership against the actual transaction
  await this.getCreatorsTransaction(rootNode.transactionId, user);

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

The controller signature must also be updated to pass `transactionId` and `user` to the service method.

## Proof of Concept

1. Attacker registers as a normal user and creates any transaction → receives `transactionId = 1`. This satisfies `getCreatorsTransaction`.
2. Attacker observes (or enumerates) approver IDs from any transaction they participate in as an observer/signer. Suppose approver `id = 42` belongs to `transactionId = 99` (a victim transaction).
3. Attacker sends:
   ```
   DELETE /transactions/1/approvers/42
   Authorization: Bearer <attacker_jwt>
   ```
4. Controller calls `getCreatorsTransaction(1, attacker)` → passes (attacker owns transaction 1).
5. Controller calls `removeTransactionApprover(42)` → service fetches approver 42, calls `removeNode(42)`, soft-deletes it and all its children — no `transactionId` check ever occurs.
6. Approver 42 (belonging to transaction 99) is permanently deleted. If repeated for all approvers of transaction 99, the transaction's approval gate is fully bypassed.

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
