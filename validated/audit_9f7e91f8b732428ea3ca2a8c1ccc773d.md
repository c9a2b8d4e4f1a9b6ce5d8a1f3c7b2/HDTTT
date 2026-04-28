The code confirms the vulnerability. Here is the audit report:

---

Audit Report

## Title
Any Transaction Creator Can Delete Approvers Belonging to Other Transactions via Missing Cross-Reference Check in `removeTransactionApprover`

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller is the creator of `:transactionId`, but then deletes the approver identified by `:id` without verifying that `:id` actually belongs to `:transactionId`. Any authenticated user who is the creator of at least one transaction can exploit this to delete approvers from any other transaction in the system.

## Finding Description

**Root cause confirmed in `approvers.controller.ts` lines 103–113:**

```typescript
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // only checks ownership of transactionId
  await this.approversService.removeTransactionApprover(id);               // deletes approver by id — no cross-check
  return true;
}
``` [1](#0-0) 

**The service method `removeTransactionApprover` (lines 534–544) fetches the approver by primary key and immediately soft-deletes it with no transaction-ownership validation:**

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);  // deletes entire subtree
  ...
}
``` [2](#0-1) 

**Contrast with `updateTransactionApprover` (lines 386–394), which correctly validates the cross-reference before proceeding:**

```typescript
const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
``` [3](#0-2) 

**`getCreatorsTransaction` (lines 624–644) only checks ownership of the transaction passed to it — it says nothing about the approver `id`:** [4](#0-3) 

The failed assumption is that passing authorization on `transactionId` is sufficient to authorize deletion of approver `id`. It is not — `id` can belong to a completely different transaction.

## Impact Explanation
An attacker can silently remove any approver (or entire approver threshold subtree via `removeNode`) from any transaction in the system. This directly undermines the multi-signature approval workflow: a transaction requiring N-of-M approvals can have its approvers deleted, potentially allowing it to proceed to execution with fewer or no approvals than intended. This constitutes unauthorized state mutation and integrity failure in the trust/approval model.

## Likelihood Explanation
The attacker only needs to be a normal authenticated user who has created at least one transaction — a baseline capability for any organization member. Approver IDs are sequential integers (standard auto-increment primary keys), making enumeration trivial. No privileged access, leaked credentials, or cryptographic breaks are required.

## Recommendation
In the `removeTransactionApprover` service method, add a cross-reference check mirroring what `updateTransactionApprover` already does correctly:

1. After fetching the approver by `id`, call `getRootNodeFromNode(approver.id)` to get the root of the approver tree.
2. Assert that `rootNode.transactionId === transactionId` (the URL parameter). If not, throw `UnauthorizedException`.
3. Only then proceed with `removeNode`.

This ensures the caller's ownership of `transactionId` is meaningful — it must be the same transaction the approver actually belongs to.

## Proof of Concept

1. Attacker registers an account and creates transaction **A** (attacker is now creator of A).
2. Attacker enumerates approver IDs (sequential integers) to find approver **B** belonging to victim transaction **C** (owned by another user).
3. Attacker sends:
   ```
   DELETE /transactions/A/approvers/B
   ```
4. Server calls `getCreatorsTransaction(A, attacker)` → **passes** (attacker owns A).
5. Server calls `removeTransactionApprover(B)` → fetches approver B by primary key, calls `removeNode(B.id)`, **soft-deletes approver B and its entire subtree** from transaction C — with zero ownership check.
6. Transaction C's approval structure is now silently corrupted.

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
