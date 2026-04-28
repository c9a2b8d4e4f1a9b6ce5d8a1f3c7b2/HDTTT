### Title
Cross-Transaction Approver Deletion via Missing Ownership Binding in `removeTransactionApprover`

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the caller is the creator of the transaction identified by `:transactionId`, but then passes the approver `:id` directly to `removeTransactionApprover()` without verifying that the approver actually belongs to that authorized transaction. Any authenticated user who owns at least one transaction can delete approvers from any other transaction in the system.

### Finding Description

**Root cause:** The controller performs authorization against `transactionId` (URL param), but the service method that executes the deletion operates only on the approver `id` (a separate URL param) with no cross-reference check.

**Controller** — `approvers.controller.ts` lines 102–113:

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // ← checks user owns transactionId
  await this.approversService.removeTransactionApprover(id);               // ← deletes approver `id` with no binding check
  return true;
}
``` [1](#0-0) 

**Service** — `approvers.service.ts` lines 533–544:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  // ...
}
``` [2](#0-1) 

The service never checks `approver.transactionId === transactionId`. The `transactionId` URL parameter is used only for the `getCreatorsTransaction` guard and is then discarded.

**Contrast with `updateTransactionApprover`**, which correctly validates the binding:

```typescript
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
``` [3](#0-2) 

The `update` path is protected; the `delete` path is not.

### Impact Explanation

An attacker can remove approvers from any transaction they do not own, bypassing the multi-signature approval workflow for those transactions. Concretely:

- Approval requirements for high-value Hedera transactions (account updates, token operations, etc.) can be silently stripped.
- A transaction that required N-of-M approvals can be reduced to 0 required approvals, allowing it to proceed to execution without the intended governance controls.
- The victim transaction creator has no indication that their approver configuration was tampered with.

### Likelihood Explanation

**Attacker preconditions (no privilege required beyond a normal account):**
1. Valid JWT — any registered, verified user.
2. Creator of at least one transaction — trivially satisfied by creating any transaction.
3. Knowledge of a target approver `id` — approver IDs are sequential integers (`1, 2, 3, …`), fully enumerable by brute-force or by observing one's own approver IDs.

The endpoint is reachable by any authenticated user. No admin role, no leaked credentials, no physical access required.

### Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), verify that the resolved approver belongs to the authorized transaction. The simplest fix mirrors what `updateTransactionApprover` already does:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Resolve root node to get the owning transactionId (handles nested approvers)
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to the specified transaction');

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

Pass `transactionId` from the controller into the service call, consistent with how `updateTransactionApprover` already receives and validates it.

### Proof of Concept

**Setup:**
- User A creates transaction T1 (attacker-controlled).
- User B creates transaction T2 with approver record `id=42` (victim).

**Attack:**
```http
DELETE /transactions/{T1_id}/approvers/42
Authorization: Bearer <User_A_JWT>
```

**Execution trace:**
1. `getCreatorsTransaction(T1_id, userA)` → passes (A owns T1). [4](#0-3) 
2. `removeTransactionApprover(42)` → fetches approver 42 (belongs to T2), calls `removeNode(42)`, soft-deletes it. No check that `42` belongs to T1. [5](#0-4) 
3. Approver 42 is deleted from T2. User B's transaction now has a modified approval structure they did not authorize.

**Expected result:** HTTP 200, `true`. Approver 42 is gone from T2.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L389-394)
```typescript
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
