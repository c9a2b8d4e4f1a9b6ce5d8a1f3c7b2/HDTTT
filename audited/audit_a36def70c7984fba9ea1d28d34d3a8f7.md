### Title
Any Authenticated User Can Delete Approvers Belonging to Another User's Transaction via Mismatched Authorization Check in `removeTransactionApprover`

### Summary

The `DELETE /transactions/:transactionId/approvers/:id` endpoint in `ApproversController` performs an authorization check against `transactionId` (verifying the caller is the creator of that transaction), but then deletes the approver record identified by `id` without verifying that `id` actually belongs to `transactionId`. This decoupling means any verified user who owns at least one transaction can delete approvers from any other user's transaction by supplying their own `transactionId` for the auth check and a victim's approver `id` for the deletion.

### Finding Description

**Root Cause**

In `approvers.controller.ts`, the `removeTransactionApprover` handler performs two independent operations:

```typescript
// back-end/apps/api/src/transactions/approvers/approvers.controller.ts
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // ← checks user owns transactionId
  await this.approversService.removeTransactionApprover(id);               // ← deletes approver by id, no binding check
  return true;
}
``` [1](#0-0) 

Step 1 (`getCreatorsTransaction`) verifies the caller is the creator of the transaction identified by the URL's `transactionId`. Step 2 (`removeTransactionApprover`) deletes the approver record identified by `id`. Critically, **`removeTransactionApprover` never checks that the approver's `transactionId` matches the URL's `transactionId`**:

```typescript
// back-end/apps/api/src/transactions/approvers/approvers.service.ts
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);  // ← deletes without transaction binding
  emitTransactionStatusUpdate(...);
  return result;
}
``` [2](#0-1) 

`getTransactionApproverById` fetches any approver by primary key with no transaction scope: [3](#0-2) 

`removeNode` then recursively soft-deletes the entire approver subtree rooted at that `id`: [4](#0-3) 

**Contrast with `updateTransactionApprover`**, which correctly validates the binding:

```typescript
// Verifies that the root transaction is the same as the param
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
``` [5](#0-4) 

The `DELETE` path is missing this exact check, making the authorization check on `transactionId` effectively redundant — analogous to the external report's `_from != _msgSender()` check that validates the wrong variable.

### Impact Explanation

An attacker can permanently remove approvers (including entire approval trees) from any transaction they do not own. This breaks the multi-signature approval workflow that is a core security invariant of the system. Consequences include:

- Removing required approvers from a victim's transaction, preventing it from ever reaching the required approval threshold and blocking execution.
- Alternatively, if the approval tree is structured such that removing nodes reduces the threshold requirement, it could allow a transaction to proceed with fewer approvals than intended.
- The deletion is a soft-delete (`deletedAt = now()`), but the approver tree is gone from the active workflow and cannot be restored through normal API flows.

**Severity: High** — unauthorized state mutation of another user's transaction approval structure with no recovery path.

### Likelihood Explanation

**High.** The attacker only needs to:
1. Be a registered, verified user (standard account).
2. Have created at least one transaction of their own (to pass the `getCreatorsTransaction` check).
3. Know or enumerate any approver `id` from a victim's transaction (approver IDs are sequential integers, trivially enumerable).

No privileged access, leaked credentials, or special roles are required.

### Recommendation

Inside `removeTransactionApprover` (or before calling it in the controller), verify that the approver being deleted actually belongs to the `transactionId` supplied in the URL. The fix mirrors the check already present in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Resolve root node and verify it belongs to the expected transaction
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to the specified transaction');

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

Pass `transactionId` from the controller into `removeTransactionApprover` so the binding can be enforced at the service layer.

### Proof of Concept

**Setup:**
- User A (attacker) creates Transaction A and is its creator.
- User B (victim) creates Transaction B and adds approver records (e.g., approver with `id = 42` belonging to Transaction B).

**Exploit:**
```
DELETE /transactions/{A_id}/approvers/42
Authorization: Bearer <User A's JWT>
```

**Execution trace:**
1. `getCreatorsTransaction(A_id, userA)` → passes, User A is creator of Transaction A.
2. `removeTransactionApprover(42)` → fetches approver 42 (belongs to Transaction B), calls `removeNode(42)`, soft-deletes the entire approver subtree.
3. No check ever compares `approver.transactionId` (Transaction B) against the URL's `transactionId` (Transaction A).

**Result:** Approver 42 and its entire subtree are deleted from Transaction B, which User A does not own, with a `200 OK` response. [1](#0-0) [2](#0-1)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L65-82)
```typescript
  /* Get the approver by id */
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
