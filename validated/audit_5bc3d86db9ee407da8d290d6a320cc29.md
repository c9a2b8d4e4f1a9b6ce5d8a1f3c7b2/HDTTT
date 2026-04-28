The code confirms the vulnerability. All four code references check out exactly as described.

Audit Report

## Title
Missing Cross-Resource Ownership Check in `removeTransactionApprover` Allows Any Transaction Creator to Delete Approvers from Other Users' Transactions

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller owns the transaction at `:transactionId`, but never verifies that the approver at `:id` belongs to that same transaction. An authenticated attacker who owns any transaction can supply their own `transactionId` to pass the ownership check, then supply an arbitrary approver `id` from a victim's transaction to delete it.

## Finding Description

**Controller-level check uses a different resource than the deletion target.**

In `approvers.controller.ts`, the `DELETE /:id` handler calls `getCreatorsTransaction(transactionId, user)` to verify the caller owns the URL's transaction, then immediately calls `removeTransactionApprover(id)` with the approver ID — with no binding between the two: [1](#0-0) 

`getCreatorsTransaction` only checks `transaction.creatorKey?.userId !== user.id` for the URL's `transactionId`. It says nothing about the approver `id`: [2](#0-1) 

`removeTransactionApprover` then fetches the approver by `id` and deletes it with no check that `approver.transactionId` matches the URL's `transactionId`: [3](#0-2) 

**Contrast with `updateTransactionApprover`**, which correctly walks to the root node and validates `rootNode.transactionId !== transactionId` before proceeding: [4](#0-3) 

The delete path is missing this exact guard.

## Impact Explanation
Deleting an approver removes a required approval gate from a transaction. If the victim's transaction requires a threshold of approvers (e.g., 2-of-3), an attacker can reduce the approver set below the threshold or remove specific approvers entirely, causing the approval workflow to be bypassed or broken. This is an unauthorized state mutation on another user's transaction — a direct integrity failure in the multi-signature trust model.

## Likelihood Explanation
The attacker needs only:
- A valid authenticated account (no admin privileges required).
- Knowledge of any approver `id` from another transaction. Approver IDs are sequential database integers, trivially enumerable via `GET /transactions/:transactionId/approvers` on any transaction the attacker has access to, or by brute-forcing small integers.

No leaked secrets, no privileged access, and no cryptographic break are required.

## Recommendation
In `removeTransactionApprover` (or in the controller before calling it), add the same cross-resource ownership check that `updateTransactionApprover` already performs:

1. After fetching the approver by `id`, walk to its root node via `getRootNodeFromNode`.
2. Assert that `rootNode.transactionId === transactionId` (the URL parameter). If not, throw `UnauthorizedException`.
3. Only then proceed with deletion.

This mirrors the existing guard in `updateTransactionApprover`: [5](#0-4) 

## Proof of Concept

1. Attacker registers an account and creates any transaction → becomes its creator (`T_own`).
2. Attacker calls `GET /transactions/T_own/approvers` (or any accessible transaction) to enumerate approver IDs, or brute-forces small integers to find `A_victim` belonging to a different user's transaction.
3. Attacker sends: `DELETE /transactions/T_own/approvers/A_victim`.
4. `getCreatorsTransaction(T_own, attacker)` passes — attacker owns `T_own`.
5. `removeTransactionApprover(A_victim)` fetches the approver by `A_victim` and deletes it with no further check — the victim's approver is gone.

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
