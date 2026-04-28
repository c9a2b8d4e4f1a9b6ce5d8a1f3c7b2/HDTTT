Audit Report

## Title
Cross-Transaction Approver Deletion via Missing Ownership Binding in `removeTransactionApprover`

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller is the creator of `:transactionId`, but deletes the approver record identified by `:id` without verifying that approver belongs to `:transactionId`. Any authenticated user who has created at least one transaction can delete approvers from any other transaction by supplying their own `transactionId` and a victim's approver `id`.

## Finding Description

**Controller handler** — `removeTransactionApprover` in `approvers.controller.ts`:

```typescript
await this.approversService.getCreatorsTransaction(transactionId, user); // checks ownership of transactionId only
await this.approversService.removeTransactionApprover(id);               // deletes by id, no transaction scope
``` [1](#0-0) 

`getCreatorsTransaction` only confirms the caller is the creator of the transaction identified by `transactionId`: [2](#0-1) 

The service `removeTransactionApprover` then fetches the approver by `id` alone and soft-deletes it (and its entire subtree via `removeNode`) with no check that `approver.transactionId === transactionId`: [3](#0-2) 

The `transactionId` URL parameter is never used to scope the approver lookup in the delete path. This is in direct contrast to `updateTransactionApprover`, which correctly validates `rootNode.transactionId !== transactionId` before proceeding: [4](#0-3) 

**Exploit path:**
1. Attacker registers as a normal user and creates transaction `T_own` (becomes its creator).
2. Attacker enumerates approver IDs (sequential auto-increment integers) to discover approver `X` belonging to victim transaction `T_victim`.
3. Attacker sends: `DELETE /transactions/T_own/approvers/X`
4. `getCreatorsTransaction(T_own, attacker)` passes — attacker owns `T_own`.
5. `removeTransactionApprover(X)` deletes approver `X` (and its entire child subtree via the recursive CTE in `removeNode`) from `T_victim` with no further check.

## Impact Explanation
An attacker can silently remove any approver — or an entire approver subtree — from any transaction in the system. This directly disrupts the multi-signature approval workflow: a transaction requiring N approvals can have its approvers stripped, potentially allowing it to proceed with fewer approvals than intended, or permanently corrupting the approval tree for in-flight transactions. This is an unauthorized state mutation affecting the integrity of the transaction lifecycle.

## Likelihood Explanation
The attacker only needs to be an authenticated, verified user who has created at least one transaction — the lowest privilege level in the system. Approver IDs are auto-incremented integers, making enumeration trivial with a sequential scan. No admin access, leaked credentials, or privileged role is required.

## Recommendation
In `removeTransactionApprover` (service), after fetching the approver, resolve its root node via `getRootNodeFromNode` and assert that `rootNode.transactionId === transactionId` before proceeding with deletion — exactly as `updateTransactionApprover` already does:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to the specified transaction');

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

Pass `transactionId` from the controller call site:
```typescript
await this.approversService.removeTransactionApprover(id, transactionId);
```

## Proof of Concept

```
# Setup: attacker owns transaction 42, victim's approver id is 99 (belonging to transaction 77)

curl -X DELETE https://api.example.com/transactions/42/approvers/99 \
  -H "Authorization: Bearer <attacker_jwt>"

# Response: true
# Approver 99 (and its entire subtree) is now deleted from transaction 77
# Attacker never had any relationship to transaction 77
```

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
