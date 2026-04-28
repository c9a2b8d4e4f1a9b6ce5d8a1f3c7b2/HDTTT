### Title
Cross-Transaction Approver Deletion: Missing Ownership Binding in `removeTransactionApprover`

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the caller is the creator of the transaction identified by `:transactionId`, but then deletes the approver identified by `:id` without verifying that this approver actually belongs to `:transactionId`. Any authenticated user who owns at least one transaction can delete approvers from any other user's transaction by supplying their own `transactionId` and a victim's `approver id`.

### Finding Description

**Root cause — missing cross-entity ownership binding in `removeTransactionApprover`**

The controller handler at `approvers.controller.ts` lines 102–113 performs two independent calls:

```typescript
// Step 1 – verifies caller owns transactionId (URL param)
await this.approversService.getCreatorsTransaction(transactionId, user);

// Step 2 – deletes approver by id (URL param) — NO check that id ∈ transactionId
await this.approversService.removeTransactionApprover(id);
``` [1](#0-0) 

The service method `removeTransactionApprover` only checks that the approver record exists; it never validates that `approver.transactionId === transactionId`:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  ...
}
``` [2](#0-1) 

**Contrast with `updateTransactionApprover`**, which correctly enforces both checks — it walks to the root node and asserts `rootNode.transactionId === transactionId` before calling `getCreatorsTransaction`: [3](#0-2) 

The delete path skips this binding entirely.

**Exploit path:**

1. Attacker (Bob) registers as a normal user and creates any transaction — call it `txA`. Bob is its creator.
2. Victim (Alice) creates `txB` and adds approvers; one approver has `id = 99` and `transactionId = txB.id`.
3. Bob sends:
   ```
   DELETE /transactions/{txA.id}/approvers/99
   ```
4. `getCreatorsTransaction(txA.id, Bob)` passes — Bob owns `txA`.
5. `removeTransactionApprover(99)` fetches approver 99 (which belongs to `txB`), finds it exists, and soft-deletes it via `removeNode`.
6. Alice's approver is gone. Her transaction can no longer reach the required approval threshold.

### Impact Explanation

An attacker with a valid account (no admin privileges required) can silently delete any approver from any other user's transaction. This:

- Breaks multi-signature approval workflows — a transaction requiring N-of-M approvals may become permanently unable to reach threshold.
- Constitutes unauthorized state mutation on another user's transaction, violating the integrity of the approval model.
- Can be used to selectively sabotage high-value or time-sensitive organizational transactions.

The `removeNode` call performs a cascading soft-delete of the entire approver subtree rooted at the targeted id, so a single request can wipe an entire threshold-key tree belonging to a victim transaction. [4](#0-3) 

### Likelihood Explanation

- **Attacker precondition:** valid JWT (registered user). No admin key, no leaked secret, no privileged role.
- **Discovery:** approver IDs are sequential integers. An attacker can enumerate them trivially via `GET /transactions/:id/approvers` on any transaction they have read access to, or by brute-forcing small integers.
- **Detectability:** the delete emits a `transactionStatusUpdate` event on the victim's transaction, but there is no alert to the victim's creator that an approver was removed by a third party.

### Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), assert that the resolved approver belongs to the transaction in the URL:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Walk to root and verify ownership — mirrors updateTransactionApprover
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to the specified transaction');

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

This mirrors the pattern already used correctly in `updateTransactionApprover`. [3](#0-2) 

### Proof of Concept

**Setup:**
- User Alice (id=2) owns `transaction B` (id=10) with approver record id=99 (`transactionId=10`).
- User Bob (id=3) owns `transaction A` (id=5).

**Request (Bob's JWT):**
```
DELETE /transactions/5/approvers/99
Authorization: Bearer <Bob's JWT>
```

**Server execution trace:**
1. `getCreatorsTransaction(5, Bob)` → finds transaction 5, `creatorKey.userId === 3` ✓ passes.
2. `removeTransactionApprover(99)` → finds approver 99 (belongs to transaction 10), calls `removeNode(99)` → soft-deletes approver 99 and all its children.

**Result:** Approver 99 is deleted from Alice's transaction 10. Alice's multi-sig workflow is broken. Bob receives HTTP 200 `true`.

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
