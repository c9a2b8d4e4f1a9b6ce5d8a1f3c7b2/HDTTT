### Title
Any Transaction Creator Can Delete Approvers Belonging to Another User's Transaction

### Summary

The `DELETE /transactions/:transactionId/approvers/:id` endpoint in the approvers controller verifies that the authenticated user is the creator of `:transactionId`, but never validates that the approver record identified by `:id` actually belongs to that same transaction. Any verified user who has created at least one transaction can exploit this mismatch to soft-delete approvers from any other transaction in the system, bypassing the multi-signature approval workflow.

### Finding Description

**Root cause — controller-level authorization is scoped to the wrong object.**

In `approvers.controller.ts`, the `removeTransactionApprover` handler performs two independent operations:

```
await this.approversService.getCreatorsTransaction(transactionId, user);  // checks user owns transactionId
await this.approversService.removeTransactionApprover(id);                // deletes approver by id — no cross-check
``` [1](#0-0) 

The first call confirms the caller is the creator of `transactionId`. The second call deletes the approver row identified by `id` without ever verifying that this approver belongs to `transactionId`.

The service-level `removeTransactionApprover` function performs no such cross-check either:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);
    const result = await this.removeNode(approver.id);   // deletes by approver.id, no transactionId guard
    ...
}
``` [2](#0-1) 

By contrast, the `updateTransactionApprover` service function correctly validates that the approver's root transaction matches the URL parameter before proceeding:

```typescript
if (rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
``` [3](#0-2) 

This guard is entirely absent from the delete path.

**Exploit flow:**

1. Attacker (verified user) creates transaction A — they become its creator.
2. Admin creates transaction B and assigns approvers (e.g., approver record with `id = 99`, `transactionId = B`).
3. Attacker sends:
   ```
   DELETE /transactions/{transactionA_id}/approvers/99
   Authorization: Bearer <attacker_token>
   ```
4. `getCreatorsTransaction(transactionA_id, attacker)` passes — attacker is the creator of A.
5. `removeTransactionApprover(99)` executes the recursive soft-delete SQL on approver 99, which belongs to transaction B.
6. Approver 99 (and all its children in the approval tree) are silently removed from transaction B. [4](#0-3) 

### Impact Explanation

An attacker can remove any approver — including entire approval trees — from any transaction they do not own. This directly undermines the multi-signature approval workflow: a transaction that required N-of-M approvals can have its approvers stripped, potentially allowing it to advance to `WAITING_FOR_EXECUTION` or `EXECUTED` status with fewer (or zero) required approvals than the creator intended. This is an unauthorized state change with direct integrity impact on the organization's transaction governance model.

### Likelihood Explanation

The attacker precondition is minimal: any registered, verified user who has created at least one transaction (even a trivial one) satisfies the authorization check. No admin access, no leaked credentials, and no special role is required. The attack is a single crafted HTTP DELETE request with a mismatched `transactionId`/approver `id` pair. It is fully reachable from the public API surface.

### Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver being deleted actually belongs to the transaction the caller is authorized to modify. The simplest fix mirrors the pattern already used in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    // Resolve the root node and verify it belongs to the expected transaction
    const rootNode = await this.getRootNodeFromNode(approver.id);
    if (!rootNode || rootNode.transactionId !== transactionId)
        throw new UnauthorizedException('Approver does not belong to this transaction');

    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);
    return result;
}
```

Pass `transactionId` from the controller into the service call, and propagate the same guard that `updateTransactionApprover` already applies.

### Proof of Concept

**Preconditions:** Two verified users — `attacker` and `victim`. Victim has created transaction B (`id = 42`) with an approver record (`id = 7`).

**Step 1 — Attacker creates any transaction to obtain a valid `transactionId`:**
```
POST /transactions
Authorization: Bearer <attacker_token>
→ 201 { "id": 10, ... }
```

**Step 2 — Attacker deletes victim's approver using their own transaction ID in the URL:**
```
DELETE /transactions/10/approvers/7
Authorization: Bearer <attacker_token>
→ 200 true
```

**Expected (correct) behavior:** 401 Unauthorized — approver 7 does not belong to transaction 10.

**Actual behavior:** Approver 7 is soft-deleted from transaction B. The approval requirement for transaction B is silently removed. The `getCreatorsTransaction(10, attacker)` check passes because the attacker owns transaction 10; the subsequent `removeTransactionApprover(7)` executes with no cross-transaction validation. [1](#0-0) [2](#0-1)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L204-231)
```typescript
  /* Soft deletes approvers' tree */
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L389-391)
```typescript
        /* Verifies that the root transaction is the same as the param */
        if (rootNode.transactionId !== transactionId)
          throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
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
