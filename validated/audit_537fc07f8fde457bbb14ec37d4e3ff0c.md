Audit Report

## Title
Any Transaction Creator Can Remove Approvers from Transactions They Do Not Own

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint validates that the caller owns `:transactionId` but then deletes the approver identified by `:id` without verifying that this approver belongs to `:transactionId`. Any authenticated organization member who owns at least one transaction can exploit this IDOR to silently strip approvers from any other user's transaction.

## Finding Description

In `approvers.controller.ts`, the delete handler performs two sequential, decoupled calls:

```typescript
await this.approversService.getCreatorsTransaction(transactionId, user);
await this.approversService.removeTransactionApprover(id);
``` [1](#0-0) 

`getCreatorsTransaction` only verifies that the authenticated user is the creator of the URL-supplied `transactionId`. It performs no check whatsoever on the approver `id` parameter: [2](#0-1) 

`removeTransactionApprover` then fetches the approver purely by its own primary key and deletes it, with no assertion that it belongs to `transactionId`: [3](#0-2) 

`getTransactionApproverById` queries by `id` alone — no `transactionId` filter is present: [4](#0-3) 

The inconsistency is made explicit by comparing with `updateTransactionApprover`, which **does** perform the cross-check before acting:

```typescript
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
``` [5](#0-4) 

The `DELETE` handler is simply missing the equivalent guard that `PATCH` already implements.

## Impact Explanation
Removing all approvers from a victim's transaction eliminates the approval gate. Once all approvers are stripped, the transaction's status can advance to `WAITING_FOR_EXECUTION` and be submitted to the Hedera network without the required organizational sign-off. Depending on the transaction type (HBAR transfer, account update, file update, etc.), this results in unauthorized fund movement or unauthorized state changes on the Hedera ledger — directly analogous to bypassing a multi-sig approval requirement.

## Likelihood Explanation
The attacker requires only a valid authenticated account in the organization — no admin role, no leaked credentials, no privileged access. Approver IDs are sequential integers, making enumeration trivial. The attack requires no special timing, race condition, or browser bug. Any organization member who can create a single transaction can exploit this immediately against any other transaction in the system.

## Recommendation
In `removeTransactionApprover` (or in the controller before calling it), resolve the root node of the approver being deleted and assert that its `transactionId` matches the URL parameter, mirroring the guard already present in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Mirror the check already present in updateTransactionApprover
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Root transaction is not the same');

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

1. Attacker (normal authenticated user) creates their own transaction `T_attacker` — this satisfies the creator check.
2. Attacker discovers `approver_id` belonging to victim's transaction `T_victim` (sequential integer IDs make enumeration trivial; the attacker can also observe IDs as a legitimate approver on any other transaction).
3. Attacker sends:
   ```
   DELETE /transactions/{T_attacker}/approvers/{approver_id_from_T_victim}
   ```
4. `getCreatorsTransaction(T_attacker, attacker)` passes — attacker owns `T_attacker`. [6](#0-5) 
5. `removeTransactionApprover(approver_id_from_T_victim)` executes — the approver from `T_victim` is deleted with no further check. [7](#0-6) 
6. Repeat for all approvers on `T_victim` to fully strip its approval requirement, allowing the transaction to proceed to execution without required sign-off.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L107-109)
```typescript
  ) {
    await this.approversService.getCreatorsTransaction(transactionId, user);
    await this.approversService.removeTransactionApprover(id);
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
