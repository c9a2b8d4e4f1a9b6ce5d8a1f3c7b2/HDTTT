### Title
Incorrect Authorization in `removeTransactionApprover` Allows Any Transaction Creator to Delete Approvers from Arbitrary Transactions

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the requesting user is the creator of the transaction identified by the URL's `:transactionId` parameter, but never verifies that the approver identified by `:id` actually belongs to that transaction. This mismatch — checking authorization against the wrong entity — allows any authenticated user who owns at least one transaction to delete approvers from any other user's transaction.

### Finding Description

**Root cause — wrong authorization target:**

In `approvers.controller.ts`, the `removeTransactionApprover` handler performs two sequential calls:

```typescript
// back-end/apps/api/src/transactions/approvers/approvers.controller.ts  lines 102-113
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // ← checks URL's transactionId
  await this.approversService.removeTransactionApprover(id);               // ← deletes approver by id, no cross-check
  return true;
}
``` [1](#0-0) 

Step 1 (`getCreatorsTransaction`) only confirms the user is the creator of the transaction named in the URL:

```typescript
// back-end/apps/api/src/transactions/approvers/approvers.service.ts  lines 640-641
if (transaction.creatorKey?.userId !== user.id)
  throw new UnauthorizedException('Only the creator of the transaction is able to modify it');
``` [2](#0-1) 

Step 2 (`removeTransactionApprover`) then deletes the approver record identified by `:id` with **no check** that the approver's `transactionId` matches the URL's `:transactionId`:

```typescript
// back-end/apps/api/src/transactions/approvers/approvers.service.ts  lines 534-544
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(...);
  return result;
}
``` [3](#0-2) 

The sibling `updateTransactionApprover` correctly performs this cross-check:

```typescript
// back-end/apps/api/src/transactions/approvers/approvers.service.ts  lines 390-391
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
``` [4](#0-3) 

The absence of this check in `removeTransactionApprover` is the direct analog of the `only_owner` vs `only_outer` mismatch in the external report: the authorization is applied to the wrong entity (the URL's transaction rather than the approver's actual owning transaction).

### Impact Explanation

An authenticated user who is the creator of **any** transaction can delete approvers from **any other** transaction in the system. This allows:

- Silently removing required approvers from another user's transaction, causing it to proceed without the intended approval gate or become permanently stuck.
- Disrupting multi-signature workflows by removing threshold approvers, potentially allowing a transaction to execute without the required number of approvals.
- Permanent corruption of the approval state of transactions the attacker does not own.

This constitutes unauthorized state mutation and permanent corruption of user/project state.

### Likelihood Explanation

The attacker only needs to be a normal authenticated user with at least one transaction of their own (to pass the `getCreatorsTransaction` check). No admin privileges, no leaked credentials, and no special knowledge beyond knowing a valid approver `id` (which is a sequential integer and trivially enumerable) are required. The endpoint is reachable via a standard authenticated HTTP DELETE request.

### Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver being deleted actually belongs to the transaction identified by the URL parameter, mirroring the check already present in `updateTransactionApprover`:

```typescript
// In approvers.service.ts removeTransactionApprover, after fetching the approver:
const rootNode = await this.getRootNodeFromNode(approver.id);
if (!rootNode || rootNode.transactionId !== transactionId) {
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
}
```

Alternatively, pass `transactionId` into `removeTransactionApprover` and perform the cross-check there, consistent with how `updateTransactionApprover` handles it. [5](#0-4) 

### Proof of Concept

1. Alice (user A) creates **Transaction-1** and adds Bob (user B) as an approver → approver record gets `id = 99`, `transactionId = 1`.
2. Charlie (user C) creates **Transaction-2** → Charlie is the creator, `transactionId = 2`.
3. Charlie sends:
   ```
   DELETE /transactions/2/approvers/99
   Authorization: Bearer <charlie's JWT>
   ```
4. `getCreatorsTransaction(2, charlie)` passes — Charlie is the creator of Transaction-2.
5. `removeTransactionApprover(99)` executes — approver record 99 (belonging to Transaction-1, owned by Alice) is deleted with no further check.
6. Bob is no longer an approver of Alice's Transaction-1. Alice's approval workflow is silently corrupted. [1](#0-0) [3](#0-2)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L366-394)
```typescript
  /* Updates an approver of a transaction */
  async updateTransactionApprover(
    id: number,
    dto: UpdateTransactionApproverDto,
    transactionId: number,
    user: User,
  ): Promise<TransactionApprover> {
    try {
      let updated = false;

      const approver = await this.dataSource.transaction(async transactionalEntityManager => {
        /* Check if the dto updates only one thing */
        if (Object.keys(dto).length > 1 || Object.keys(dto).length === 0)
          throw new Error(this.INVALID_UPDATE_APPROVER);

        /* Verifies that the approver exists */
        const approver = await this.getTransactionApproverById(id, transactionalEntityManager);
        if (!approver) throw new BadRequestException(ErrorCodes.ANF);

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
