### Title
`removeTransactionApprover` Authorization Scope Mismatch Allows Any Transaction Creator to Delete Approvers from Arbitrary Transactions

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller is the creator of the `transactionId` URL parameter, but then deletes the approver record identified by the separate `id` URL parameter without verifying that the approver actually belongs to `transactionId`. Any authenticated user who has created at least one transaction can delete approvers from any other transaction in the system by supplying their own `transactionId` and a victim transaction's approver `id`.

### Finding Description

**Root cause — controller-level authorization scope mismatch:**

In `approvers.controller.ts` the `removeTransactionApprover` handler performs two independent operations:

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // ← checks user owns transactionId
  await this.approversService.removeTransactionApprover(id);               // ← deletes approver by id, no binding
  return true;
}
``` [1](#0-0) 

Step 1 (`getCreatorsTransaction`) only confirms the caller is the creator of the transaction identified by the URL's `transactionId` parameter. It says nothing about the approver identified by `id`. [2](#0-1) 

Step 2 (`removeTransactionApprover`) fetches the approver by `id` and deletes it with no cross-check against `transactionId`:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  ...
}
``` [3](#0-2) 

There is no check that `approver.transactionId === transactionId` (or that the approver's root node belongs to `transactionId`). The two URL parameters are completely decoupled after the initial creator check.

**Contrast with the protected path:** The `updateTransactionApprover` service method correctly performs this cross-check before mutating:

```typescript
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
``` [4](#0-3) 

The delete path has no equivalent guard.

### Impact Explanation

An attacker can delete approvers from any transaction they do not own, disrupting the multi-signature approval workflow. Concretely:

- A transaction requiring threshold approvals (e.g., 2-of-3) can have its approver tree silently destroyed, causing the transaction to either stall permanently or proceed without the intended governance controls.
- The attacker can target high-value transactions belonging to other users or organizations and remove all approvers, bypassing the approval gate entirely.
- The `emitTransactionStatusUpdate` call inside `removeTransactionApprover` will trigger a status recalculation on the victim's transaction, potentially advancing it to `WAITING_FOR_EXECUTION` prematurely if the approval threshold is no longer enforced. [5](#0-4) 

### Likelihood Explanation

- **Attacker preconditions**: Must be an authenticated, verified user with at least one created transaction. This is a normal user role — no admin or privileged access required.
- **Approver IDs are sequential integers** (auto-increment primary keys), making enumeration of valid approver IDs trivial via a simple loop.
- The attack requires only a single HTTP `DELETE` request with a crafted `transactionId` (attacker's own) and `id` (victim's approver).
- No rate limiting or anomaly detection is visible on this endpoint.

### Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver's root transaction matches the `transactionId` URL parameter, mirroring the guard already present in `updateTransactionApprover`:

```typescript
// In the controller, after getCreatorsTransaction:
const approver = await this.approversService.getTransactionApproverById(id);
const rootNode = await this.approversService.getRootNodeFromNode(approver.id);
if (rootNode?.transactionId !== transactionId) {
  throw new UnauthorizedException('Approver does not belong to this transaction');
}
await this.approversService.removeTransactionApprover(id);
```

Alternatively, add the same `rootNode.transactionId !== transactionId` check inside `removeTransactionApprover` itself, accepting `transactionId` as a required parameter.

### Proof of Concept

**Setup:**
- User A creates Transaction A (ID = 1). User A is its creator.
- User B creates Transaction B (ID = 2) and adds User C as an approver (approver record ID = 7).

**Attack:**
```
DELETE /transactions/1/approvers/7
Authorization: Bearer <User A's JWT>
```

**Execution path:**
1. `getCreatorsTransaction(1, UserA)` → passes, UserA IS creator of transaction 1.
2. `removeTransactionApprover(7)` → fetches approver ID 7 (belongs to transaction 2), calls `removeNode(7)`, soft-deletes it. No ownership check fires.

**Result:** Approver ID 7 is deleted from Transaction B. User B's transaction loses its required approver without User B's knowledge or consent. The `emitTransactionStatusUpdate` call then triggers a status recalculation on Transaction B. [1](#0-0) [3](#0-2)

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
