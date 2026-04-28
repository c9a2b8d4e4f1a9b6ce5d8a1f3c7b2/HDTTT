The code confirms all claims. The vulnerability is real and in scope.

---

Audit Report

## Title
Cross-Transaction Approver Deletion via Missing Ownership Validation in `removeTransactionApprover`

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the authenticated user owns `:transactionId`, but then deletes the approver identified by `:id` with no check that the approver actually belongs to `:transactionId`. Any authenticated user who owns at least one transaction can delete approvers from any other transaction in the system.

## Finding Description

In `approvers.controller.ts`, the `DELETE /:id` handler performs two independent, uncorrelated operations:

```typescript
await this.approversService.getCreatorsTransaction(transactionId, user);
await this.approversService.removeTransactionApprover(id);
``` [1](#0-0) 

`getCreatorsTransaction` only verifies that `user` is the creator of the transaction identified by `transactionId` in the URL — it says nothing about `id`: [2](#0-1) 

`removeTransactionApprover` then fetches the approver by `id` alone and soft-deletes it and its entire subtree with no check that `approver.transactionId` matches the URL's `transactionId`: [3](#0-2) 

The recursive `removeNode` CTE deletes the targeted node and all its children unconditionally: [4](#0-3) 

This is a clear inconsistency with `updateTransactionApprover`, which correctly resolves the root node and validates `rootNode.transactionId !== transactionId` before proceeding: [5](#0-4) 

The observers subsystem correctly resolves the transaction from the observer record itself (via `observer.transactionId`) and checks creator ownership before any mutation, making it immune to this class of attack: [6](#0-5) 

## Impact Explanation
An attacker can silently remove any approver — or an entire approver subtree — from any transaction in the system, regardless of who owns it. This directly undermines the multi-signature approval workflow: a transaction requiring N-of-M approvals can have its approver tree gutted, potentially allowing it to proceed with fewer approvals than intended, or permanently corrupting the approval state of a victim's pending transaction. This constitutes unauthorized state mutation of another user's transaction data.

## Likelihood Explanation
The attacker only needs to be an authenticated, verified user who is the creator of any one transaction (even a self-created dummy transaction). Approver IDs are sequential auto-increment integers, making them trivially enumerable. No privileged access, leaked credentials, or admin keys are required. The attack is a single crafted HTTP DELETE request.

## Recommendation
In `removeTransactionApprover` (or in the controller before calling it), resolve the root node of the approver identified by `id` and assert that `rootNode.transactionId === transactionId` before proceeding with deletion. This is exactly the pattern already used in `updateTransactionApprover`:

```typescript
const rootNode = await this.getRootNodeFromNode(id);
if (!rootNode || rootNode.transactionId !== transactionId) {
  throw new UnauthorizedException('Approver does not belong to the specified transaction');
}
```

Alternatively, pass `transactionId` into `removeTransactionApprover` and perform the cross-check there, mirroring the guard already present in the update path.

## Proof of Concept

1. Attacker (user A) creates their own transaction → receives `transactionId = 1`.
2. Attacker enumerates approver IDs (sequential integers) and identifies a victim approver with `id = 99` belonging to user B's transaction `transactionId = 42`.
3. Attacker sends:
   ```
   DELETE /transactions/1/approvers/99
   Authorization: Bearer <attacker_jwt>
   ```
4. `getCreatorsTransaction(1, userA)` passes — user A owns transaction 1.
5. `removeTransactionApprover(99)` fetches approver 99 (belonging to transaction 42) and calls `removeNode(99)`.
6. The recursive CTE soft-deletes approver 99 and its entire child subtree with no cross-check.
7. User B's transaction 42 now has its approver tree partially or fully destroyed, with no error returned to the attacker.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L108-109)
```typescript
    await this.approversService.getCreatorsTransaction(transactionId, user);
    await this.approversService.removeTransactionApprover(id);
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
