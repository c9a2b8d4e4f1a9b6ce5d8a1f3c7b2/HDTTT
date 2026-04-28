The code confirms the vulnerability. The DELETE handler at line 108-109 performs the ownership check on `transactionId` but then deletes by `id` with no cross-check, while the PATCH handler at lines 390-391 explicitly validates `rootNode.transactionId !== transactionId`.

---

Audit Report

## Title
Creator of Any Transaction Can Delete Approvers Belonging to a Different Transaction

## Summary
The `removeTransactionApprover` DELETE endpoint verifies that the requesting user is the creator of the transaction identified by `:transactionId`, but then deletes the approver record identified by the separate `:id` parameter without confirming that approver belongs to that same transaction. Any verified user who has created at least one transaction can therefore delete approvers from transactions they do not own.

## Finding Description

**File:** `back-end/apps/api/src/transactions/approvers/approvers.controller.ts`

The `removeTransactionApprover` handler performs two independent, uncorrelated operations:

```typescript
// Step 1 — verifies user is creator of :transactionId
await this.approversService.getCreatorsTransaction(transactionId, user);

// Step 2 — deletes approver by :id, with NO check that it belongs to :transactionId
await this.approversService.removeTransactionApprover(id);
``` [1](#0-0) 

`getCreatorsTransaction` only validates that the user created the transaction referenced by `transactionId` — it says nothing about the approver record: [2](#0-1) 

`removeTransactionApprover` then fetches the approver by `id` and calls `removeNode` with no check that `approver.transactionId === transactionId`: [3](#0-2) 

`removeNode` performs a recursive soft-delete of the entire subtree rooted at the given `id`, meaning entire approval trees can be wiped: [4](#0-3) 

By contrast, the PATCH handler (`updateTransactionApprover`) correctly validates that the root node's `transactionId` matches the URL parameter before proceeding:

```typescript
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
``` [5](#0-4) 

The DELETE path omits this cross-check entirely.

**Root cause:** The authorization check (Step 1) is performed on resource A (`transactionId`), while the destructive action (Step 2) is applied to resource B (`id`), with no binding between the two.

## Impact Explanation

An attacker with a normal verified user account can unilaterally remove any approver record from any transaction in the organization. Because `removeNode` recursively soft-deletes entire subtrees, a single request can wipe a complex threshold-tree approval structure. This bypasses the multi-signature approval workflow, potentially allowing transactions to advance to execution without the required approvals. The integrity of the organization's governance model is broken without any audit trail pointing to the victim transaction.

## Likelihood Explanation

- **Attacker preconditions:** Must be a registered, verified user — no admin or privileged role required.
- **Knowledge required:** Approver IDs are sequential integers (`id: number`). An attacker who has ever created a transaction and added approvers will have observed IDs in the same namespace. Blind enumeration across a small integer range is trivially feasible.
- No rate-limiting or anomaly detection is evident on this endpoint.
- The attack is a single authenticated HTTP DELETE request.

## Recommendation

In `removeTransactionApprover` (service), after fetching the approver, resolve its root node and assert that `rootNode.transactionId === transactionId` before calling `removeNode` — exactly as `updateTransactionApprover` already does:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Cross-resource ownership check (mirrors updateTransactionApprover)
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

Pass `transactionId` from the controller into `removeTransactionApprover` so the check can be performed.

## Proof of Concept

1. Attacker (verified user) creates **Transaction A** — they become its creator.
2. Admin creates **Transaction B** and assigns User C as an approver; the resulting `TransactionApprover` record has `id = N`.
3. Attacker observes approver IDs from their own transactions (sequential integers) or enumerates blindly.
4. Attacker sends:
   ```
   DELETE /transactions/{A_id}/approvers/{N}
   ```
5. `getCreatorsTransaction(A_id, attacker)` passes — attacker owns Transaction A. [6](#0-5) 
6. `removeTransactionApprover(N)` is called with no ownership check; it fetches approver `N` (belonging to Transaction B) and calls `removeNode(N)`. [7](#0-6) 
7. Transaction B's approver (and any subtree) is silently soft-deleted. The endpoint returns `true`.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L107-112)
```typescript
  ) {
    await this.approversService.getCreatorsTransaction(transactionId, user);
    await this.approversService.removeTransactionApprover(id);
    // await this.approversService.emitSyncIndicators(transactionId);

    return true;
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
