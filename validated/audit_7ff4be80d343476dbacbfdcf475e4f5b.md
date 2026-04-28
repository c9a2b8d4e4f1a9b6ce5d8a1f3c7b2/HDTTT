All three code claims in the report are verified against the actual source. Here is the audit report:

---

Audit Report

## Title
IDOR in `removeTransactionApprover`: Any Transaction Creator Can Delete Approvers Belonging to Other Transactions

## Summary
The `DELETE /:id` handler in `ApproversController` verifies the caller is the creator of `transactionId`, but then passes the unrelated approver `id` directly to `removeTransactionApprover`, which deletes it with no ownership check. An attacker who is the creator of any transaction can delete approvers from transactions they do not own.

## Finding Description

**Controller — missing cross-check:**

In `approvers.controller.ts`, the handler at line 108 confirms the user owns `transactionId`, then at line 109 calls `removeTransactionApprover(id)` with the raw URL parameter — no verification that `id` belongs to `transactionId`:

```typescript
await this.approversService.getCreatorsTransaction(transactionId, user); // checks user owns transactionId
await this.approversService.removeTransactionApprover(id);               // deletes ANY approver by id
``` [1](#0-0) 

**Service — unconditional deletion:**

`removeTransactionApprover` fetches the approver by `id` alone and deletes it: [2](#0-1) 

`getTransactionApproverById` queries with `where: { id }` only — no `transactionId` constraint: [3](#0-2) 

**Contrast with `updateTransactionApprover` (correct pattern):**

`updateTransactionApprover` walks up to the root node and explicitly rejects the request if `rootNode.transactionId !== transactionId`: [4](#0-3) 

This guard is entirely absent from the delete path.

## Impact Explanation

`removeNode` performs a recursive soft-delete of the entire approver subtree rooted at the given `id`: [5](#0-4) 

Deleting a root approver node from a victim transaction silently removes that entire approval gate. If the transaction required N-of-M approvals and enough approvers are removed, the transaction can proceed to execution without the intended organizational oversight. Since approvers gate Hedera network transactions (account updates, fund transfers, node operations), this allows unauthorized Hedera transactions to be executed by bypassing the approval workflow entirely.

## Likelihood Explanation

The attacker only needs to be a registered user and the creator of at least one transaction — a normal workflow action. Approver IDs are sequential integers. The `GET /transactions/{id}/approvers` endpoint (`getVerifiedApproversByTransactionId`) exposes approver IDs to any user who is a creator, signer, observer, or approver of that transaction: [6](#0-5) 

No privileged access, leaked credentials, or cryptographic breaks are required.

## Recommendation

In `removeTransactionApprover` (or in the controller before calling it), walk up to the root node using `getRootNodeFromNode` and verify `rootNode.transactionId === transactionId` before proceeding — exactly as `updateTransactionApprover` does at lines 386–391. For example:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to the specified transaction');

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);
  return result;
}
```

Pass `transactionId` from the controller into the service call so the ownership check can be enforced.

## Proof of Concept

1. Attacker registers as a normal user and creates **Transaction A** — they are now its creator.
2. Attacker has any visibility into **Transaction B** (e.g., they are a signer or observer), or enumerates sequential approver IDs.
3. Attacker calls `GET /transactions/B/approvers` and records an approver ID, e.g. `approver_id = 42`.
4. Attacker calls:
   ```
   DELETE /transactions/A/approvers/42
   ```
5. The controller calls `getCreatorsTransaction(A, attacker)` — passes, because the attacker owns A.
6. The controller calls `removeTransactionApprover(42)` — the service fetches approver 42 (which belongs to B) and deletes it and its entire subtree with no further check.
7. The approval requirement on Transaction B is silently removed.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L108-109)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L131-149)
```typescript
    if (
      [
        TransactionStatus.EXECUTED,
        TransactionStatus.EXPIRED,
        TransactionStatus.FAILED,
        TransactionStatus.CANCELED,
        TransactionStatus.ARCHIVED,
      ].includes(transaction.status)
    )
      return approvers;

    if (
      userKeysToSign.length === 0 &&
      transaction.creatorKey?.userId !== user.id &&
      !transaction.observers.some(o => o.userId === user.id) &&
      !transaction.signers.some(s => s.userKey?.userId === user.id) &&
      !approvers.some(a => a.userId === user.id)
    )
      throw new UnauthorizedException("You don't have permission to view this transaction");
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L205-231)
```typescript
  async removeNode(listId: number): Promise<void> {
    if (!listId || typeof listId !== 'number') return null;

    await this.repo.query(
      `
      with recursive approversToDelete AS
        (
          select "id", "listId", "deletedAt"
          from transaction_approver
          where "id" = $1
  
            union all
              select transaction_approver."id", transaction_approver."listId", transaction_approver."deletedAt"
              from transaction_approver, approversToDelete     
              where approversToDelete."id" = transaction_approver."listId"
      
        )
      update transaction_approver
      set "deletedAt" = now()
      from approversToDelete
      where approversToDelete."id" = transaction_approver."listId" or transaction_approver."id" = $1;
    `,
      [listId],
    );

    // notifyTransactionAction(this.notificationsService);
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L386-391)
```typescript
        const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
        if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

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
