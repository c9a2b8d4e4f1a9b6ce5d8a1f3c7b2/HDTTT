The code confirms the vulnerability. Here is the audit report:

---

Audit Report

## Title
Transaction Creator Can Remove Approvers From Any Transaction via Missing Cross-Transaction Authorization Check

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the requesting user is the creator of `:transactionId`, but then deletes the approver identified by `:id` without verifying that the approver actually belongs to `:transactionId`. Any authenticated user who has created at least one transaction can delete approvers from any other transaction in the system.

## Finding Description

**Root cause — authorization check is on the wrong object:**

In `approvers.controller.ts`, the `removeTransactionApprover` handler calls `getCreatorsTransaction(transactionId, user)` to confirm the caller is the creator of the URL-supplied `:transactionId`, then immediately calls `removeTransactionApprover(id)` with no check that the approver `id` belongs to that transaction: [1](#0-0) 

Inside the service, `removeTransactionApprover` fetches the approver by its own primary key and deletes it unconditionally — there is no assertion that `approver.transactionId` matches the `transactionId` from the URL: [2](#0-1) 

`getCreatorsTransaction` only validates ownership of the URL-supplied `transactionId`, not of the approver being deleted: [3](#0-2) 

**The fix pattern already exists in `updateTransactionApprover`** — that path explicitly checks `rootNode.transactionId !== transactionId` before proceeding, proving the cross-transaction guard was known and intentionally applied there but omitted in the delete path: [4](#0-3) 

**Secondary issue — null `transactionId` on child approvers:**

When a child approver (one with `listId` set) is created, its `transactionId` is stored as `null`: [5](#0-4) 

When such an approver is deleted, `emitTransactionStatusUpdate` is called with `entityId: null`, meaning the victim transaction's status is never recalculated, leaving it in a permanently inconsistent state. [6](#0-5) 

## Impact Explanation
- **Unauthorized data deletion across trust boundaries.** An attacker can delete approvers belonging to any transaction they do not own.
- **Permanent DoS on any transaction's approval workflow.** By repeatedly deleting approvers, an attacker can prevent a victim's transaction from ever reaching `WAITING_FOR_EXECUTION` and being submitted to the Hedera network.
- **Inconsistent state for child approvers.** Deleting a child approver with `transactionId: null` causes `emitTransactionStatusUpdate` to fire with `entityId: null`, leaving the parent transaction in a permanently broken state with no status recalculation.

## Likelihood Explanation
- **Precondition:** The attacker only needs a valid authenticated session and must have created at least one transaction — trivially achievable by any registered user.
- **No privileged access required.** The attack uses only standard API endpoints available to all authenticated users.
- **Approver IDs are sequential integers**, making enumeration straightforward.
- **No rate limiting** is visible on this endpoint, so the attack can be automated and repeated indefinitely.

## Recommendation
In `removeTransactionApprover` (service), after fetching the approver, resolve its root node via `getRootNodeFromNode` and assert that `rootNode.transactionId === transactionId` (the URL parameter) before proceeding with deletion — exactly as `updateTransactionApprover` already does at lines 386–391. If the root transaction does not match, throw an `UnauthorizedException`.

## Proof of Concept
1. Attacker registers an account and creates any dummy transaction, becoming the creator of transaction ID `N`.
2. Attacker enumerates approver IDs (sequential integers) belonging to a victim's transaction `M`.
3. Attacker sends:
   ```
   DELETE /transactions/N/approvers/<victim_approver_id>
   ```
4. The controller confirms the attacker is the creator of transaction `N` ✓, then `removeTransactionApprover(<victim_approver_id>)` deletes the approver from transaction `M` ✗ — no cross-transaction check is performed.
5. The victim's transaction `M` loses its approver. The attacker can repeat this indefinitely, permanently blocking the victim's transaction from reaching execution.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L309-312)
```typescript
          const data: DeepPartial<TransactionApprover> = {
            transactionId:
              dtoApprover.listId === null || isNaN(dtoApprover.listId) ? transactionId : null,
            listId: dtoApprover.listId,
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
