The code confirms the vulnerability. Here is the audit report:

---

Audit Report

## Title
Missing Approver-to-Transaction Association Verification in `removeTransactionApprover` Allows Cross-Transaction Approver Deletion

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller is the creator of the transaction identified by `:transactionId`, but never verifies that the approver identified by `:id` belongs to that same transaction. Any authenticated user who is the creator of at least one transaction can delete approvers belonging to any other transaction in the system.

## Finding Description

In `approvers.controller.ts`, the delete handler is:

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

`getCreatorsTransaction` only confirms the caller owns the transaction referenced by `transactionId` — it says nothing about the approver referenced by `id`. [2](#0-1) 

`removeTransactionApprover` then fetches the approver by `id` alone and deletes it with no cross-check against `transactionId`:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
``` [3](#0-2) 

`getTransactionApproverById` fetches purely by `id` with no `transactionId` filter: [4](#0-3) 

By contrast, `updateTransactionApprover` correctly performs the cross-check:

```typescript
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
``` [5](#0-4) 

The analogous guard is entirely absent from the delete path.

## Impact Explanation

An attacker who is the creator of any transaction can delete approvers from any other transaction in the system. This directly undermines the multi-signature approval model: a transaction requiring N-of-M approvals can have its approvers silently removed, reducing the effective threshold and allowing the transaction to proceed without the required authorizations. Additionally, `emitTransactionStatusUpdate` is called with `approver.transactionId` (the victim transaction's ID for root nodes, or `null` for child nodes), not the attacker-supplied `transactionId`, meaning status notifications are misdirected, further obscuring the attack. [6](#0-5) 

## Likelihood Explanation

The attacker only needs to be a registered, verified user who has created at least one transaction — a trivially achievable precondition in normal product use. No privileged access, leaked credentials, or admin rights are required. Approver IDs are sequential integers, making enumeration straightforward. The attack is a single authenticated HTTP DELETE request.

## Recommendation

In `removeTransactionApprover` (service), after fetching the approver, resolve its root node using `getRootNodeFromNode` and verify that `rootNode.transactionId === transactionId` before proceeding with deletion — exactly as `updateTransactionApprover` does:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);
  if (rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: rootNode.transactionId }]);
  return result;
}
```

Pass `transactionId` from the controller into `removeTransactionApprover` so the check can be performed.

## Proof of Concept

1. Attacker (user A) creates Transaction T1 (attacker-owned) and Transaction T2 (victim-owned, belonging to user B with approvers configured).
2. Attacker enumerates or guesses approver ID `X` belonging to T2 (sequential integers).
3. Attacker sends:
   ```
   DELETE /transactions/{T1_id}/approvers/{X}
   Authorization: Bearer <attacker_token>
   ```
4. `getCreatorsTransaction(T1_id, userA)` passes — attacker owns T1.
5. `removeTransactionApprover(X)` fetches approver `X` (which belongs to T2) and deletes it with no further checks.
6. Approver `X` and its entire subtree are soft-deleted from T2, silently reducing T2's approval requirements. [7](#0-6) [3](#0-2)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L390-391)
```typescript
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
