### Title
IDOR in `removeTransactionApprover` Allows Any Transaction Creator to Delete Approvers from Arbitrary Transactions

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller is the creator of `:transactionId`, but never validates that the approver `:id` actually belongs to that transaction. Any authenticated user who created at least one transaction can delete approvers from any other transaction in the system, completely dismantling its multi-signature approval workflow.

### Finding Description
In `approvers.controller.ts`, the delete handler performs an ownership check on the route's `transactionId`, then passes the approver `id` directly to `removeTransactionApprover` with no cross-validation:

```typescript
// approvers.controller.ts lines 102-113
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // checks ownership of transactionId
  await this.approversService.removeTransactionApprover(id);               // deletes approver by id — no cross-check
  return true;
}
```

`removeTransactionApprover` in the service fetches the approver purely by its own `id` and deletes it:

```typescript
// approvers.service.ts lines 534-544
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id); // WHERE id = $1 only
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  ...
}
```

`getTransactionApproverById` queries with `where: { id }` only — no `transactionId` filter:

```typescript
// approvers.service.ts lines 66-82
const find: FindOneOptions<TransactionApprover> = {
  relations: ['approvers'],
  where: { id },   // no transactionId constraint
};
```

The correct pattern is demonstrated in `updateTransactionApprover`, which explicitly validates the approver's root transaction matches the route parameter before proceeding:

```typescript
// approvers.service.ts lines 389-391
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
```

This guard is entirely absent from the delete path.

### Impact Explanation
An attacker who is the creator of any transaction (even a trivial one they created themselves) can enumerate approver IDs belonging to high-value transactions owned by other users and delete them. This:
- Removes required signers from multi-signature transactions, preventing them from ever reaching the approval threshold.
- Can silently stall or permanently block critical Hedera transactions awaiting multi-party approval.
- Requires no special privilege beyond being a registered, verified user who has created at least one transaction.

### Likelihood Explanation
The attack requires only a valid JWT token and knowledge of an approver ID from another transaction. Approver IDs are sequential integers, making enumeration trivial. Any registered user in an organization can exploit this immediately.

### Recommendation
Inside `removeTransactionApprover` (or in the controller before calling it), resolve the root transaction of the approver being deleted and assert it matches the `transactionId` route parameter — exactly as `updateTransactionApprover` already does:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Root transaction is not the same');

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

### Proof of Concept
1. Attacker (User A) creates Transaction 1 — they are its creator.
2. Victim (User B) creates Transaction 2 with approvers having IDs 50, 51, 52.
3. Attacker sends:
   ```
   DELETE /transactions/1/approvers/50
   DELETE /transactions/1/approvers/51
   DELETE /transactions/1/approvers/52
   ```
4. The controller passes `getCreatorsTransaction(1, userA)` — User A is the creator of Transaction 1, so the check passes.
5. `removeTransactionApprover(50)` fetches approver 50 (belonging to Transaction 2) and deletes it — no transaction ownership check is performed.
6. All approvers for Transaction 2 are deleted; it can never reach its approval threshold.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L389-391)
```typescript
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
