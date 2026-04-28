### Title
Any Transaction Creator Can Delete Approvers Belonging to Other Users' Transactions

### Summary
The `removeTransactionApprover` endpoint in the approvers controller verifies that the authenticated user is the creator of the transaction identified by the URL's `transactionId` parameter, but then deletes the approver identified by the separate `id` parameter without verifying that this approver actually belongs to that same transaction. Any authenticated user who is the creator of at least one transaction can exploit this to delete approvers from any other transaction in the system.

### Finding Description

**Root cause:** The controller-level authorization check and the service-level deletion operate on two independent identifiers with no cross-validation between them.

In `back-end/apps/api/src/transactions/approvers/approvers.controller.ts`, the `DELETE /:id` handler:

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user);
  await this.approversService.removeTransactionApprover(id);
  return true;
}
``` [1](#0-0) 

Step 1 (`getCreatorsTransaction`) verifies the caller is the creator of `transactionId` (the URL path parameter). Step 2 (`removeTransactionApprover`) deletes the approver with the separate `id` parameter. There is no check that the approver `id` belongs to `transactionId`.

The service-level `removeTransactionApprover` accepts only an approver `id` and performs no ownership validation:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
``` [2](#0-1) 

`getTransactionApproverById` fetches by `id` alone with no transaction scope: [3](#0-2) 

And `removeNode` deletes the entire approver subtree rooted at the given `id` with no ownership check: [4](#0-3) 

**Exploit path:**
1. Attacker registers as a normal user and creates any transaction (transaction A). They are now the creator of A.
2. Attacker enumerates or guesses an approver `id` belonging to victim's transaction B (approver IDs are sequential integers).
3. Attacker sends: `DELETE /transactions/{A_id}/approvers/{B_approver_id}`
4. `getCreatorsTransaction(A_id, attacker)` passes — attacker is creator of A.
5. `removeTransactionApprover(B_approver_id)` executes — deletes the approver from transaction B without any further check.

### Impact Explanation

An attacker with a valid account can silently delete approvers from any transaction in the organization, including transactions they have no legitimate access to. This breaks the multi-signature approval workflow: removing a required approver can allow a transaction to proceed without the intended oversight, or corrupt the approval tree structure irreversibly. This constitutes unauthorized state mutation of another user's transaction data.

### Likelihood Explanation

The attacker only needs to be a registered, verified user — no admin or special role is required. Approver IDs are sequential integers, making enumeration trivial. The attack requires a single authenticated HTTP request. Any malicious organization member can exploit this immediately.

### Recommendation

Inside `removeTransactionApprover` (or before calling it in the controller), verify that the approver being deleted actually belongs to the `transactionId` the user is authorized for. Concretely, after fetching the approver, traverse to its root node and assert `rootNode.transactionId === transactionId` before proceeding with deletion. The `getRootNodeFromNode` helper already exists in the service and is used for exactly this purpose in `updateTransactionApprover`: [5](#0-4) 

Apply the same pattern to `removeTransactionApprover`.

### Proof of Concept

**Preconditions:** Two registered users, User A (attacker) and User B (victim). User B has a transaction (id=42) with an approver (id=99).

1. User A creates any transaction → receives transaction id=7.
2. User A sends:
   ```
   DELETE /transactions/7/approvers/99
   Authorization: Bearer <User_A_token>
   ```
3. Server response: `200 true`
4. Approver id=99 (belonging to User B's transaction 42) is now soft-deleted from the database.
5. User B's transaction 42 has lost its approver, breaking the intended approval workflow. [1](#0-0) [2](#0-1)

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
