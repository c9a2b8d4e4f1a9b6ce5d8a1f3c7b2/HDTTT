## Audit Report

## Title
IDOR in `removeTransactionApprover`: Creator of Any Transaction Can Delete Approvers Belonging to Other Transactions

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint authorizes the request by verifying the caller is the creator of `:transactionId` (the URL parameter), but then deletes the approver identified by `:id` without ever verifying that approver actually belongs to `:transactionId`. An attacker who is the creator of any one transaction can delete approvers from any other transaction in the system.

## Finding Description

**Controller** (`approvers.controller.ts`, lines 103–113):

```typescript
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // checks user owns transactionId
  await this.approversService.removeTransactionApprover(id);               // deletes approver by id — no cross-check
  return true;
}
``` [1](#0-0) 

**Service** (`approvers.service.ts`, lines 533–544):

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id); // fetches by id only, no transactionId filter
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);          // deletes unconditionally
  ...
}
``` [2](#0-1) 

`getTransactionApproverById` fetches by `id` alone with no `transactionId` constraint:

```typescript
const find: FindOneOptions<TransactionApprover> = {
  relations: ['approvers'],
  where: { id },   // no transactionId filter
};
``` [3](#0-2) 

**Contrast with `updateTransactionApprover`** (lines 386–394), which correctly performs both checks — it resolves the root node from the approver and verifies `rootNode.transactionId === transactionId` before calling `getCreatorsTransaction`:

```typescript
const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
``` [4](#0-3) 

The `removeTransactionApprover` flow has no equivalent cross-check. The two parameters — `transactionId` (used for authorization) and `id` (used for deletion) — are never reconciled.

## Impact Explanation
Any authenticated user who is the creator of at least one transaction can delete approvers belonging to any other transaction in the system. This allows:
- Bypassing multi-party approval requirements on transactions they do not own.
- Silently removing approvers from pending transactions, potentially allowing those transactions to execute without the required approvals.
- Disrupting the approval workflow of other users' transactions.

## Likelihood Explanation
The attack requires only that the attacker be a registered user who has created at least one transaction (to pass the `getCreatorsTransaction` check on their own `transactionId`). The approver `id` values are sequential integers, making enumeration trivial. No special privileges, leaked credentials, or physical access are required. The endpoint is a standard REST `DELETE` call.

## Recommendation
In the controller's `removeTransactionApprover`, after fetching the approver, verify that the approver's root transaction matches the authorized `transactionId`. The simplest fix mirrors the pattern already used in `updateTransactionApprover`:

1. After `getCreatorsTransaction(transactionId, user)` passes, resolve the root node of the target approver via `getRootNodeFromNode(id)`.
2. Assert `rootNode.transactionId === transactionId` before proceeding with deletion.

Alternatively, pass `transactionId` into `removeTransactionApprover` in the service and perform the ownership check there (as `updateTransactionApprover` does), keeping authorization logic co-located with the mutation.

## Proof of Concept

**Setup:**
- User A is the creator of Transaction 1 (id=1).
- User B is the creator of Transaction 2 (id=2), which has an approver with id=99.

**Attack:**
```
DELETE /transactions/1/approvers/99
Authorization: Bearer <User A's JWT>
```

**Execution trace:**
1. `getCreatorsTransaction(1, userA)` — passes, user A owns transaction 1.
2. `removeTransactionApprover(99)` — fetches approver 99 (belongs to transaction 2), no `transactionId` check, calls `removeNode(99)`.
3. Approver 99 is soft-deleted from transaction 2. User A never had any rights over transaction 2.

**Result:** User A has successfully deleted an approver from User B's transaction, bypassing the approval requirement without authorization.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L103-113)
```typescript
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
