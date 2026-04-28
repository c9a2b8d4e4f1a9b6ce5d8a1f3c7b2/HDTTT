Looking at the codebase, I need to trace the authorization pattern in the `removeTransactionApprover` flow and compare it to the `updateTransactionApprover` flow, which has a cross-transaction ownership check.

---

### Title
`removeTransactionApprover` Lacks Cross-Transaction Ownership Verification, Enabling IDOR to Delete Approvers from Arbitrary Transactions

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint authorizes the caller as the creator of `:transactionId`, but then passes the unrelated `:id` (approver ID) directly to `removeTransactionApprover()` in the service, which never verifies that the approver belongs to the authorized transaction. Any authenticated user who is the creator of at least one transaction can delete approvers from any other transaction by supplying their own `transactionId` for the authorization check and a victim's approver `id` for the deletion.

### Finding Description

**Root cause — controller authorization is decoupled from service action:**

In `approvers.controller.ts` the `DELETE` handler authorizes the caller against `transactionId`, then immediately calls the service with the unrelated `id`: [1](#0-0) 

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // ← authorizes transactionId
  await this.approversService.removeTransactionApprover(id);               // ← acts on id, no cross-check
  return true;
}
```

The service `removeTransactionApprover` accepts only the approver `id` and performs no check that the approver belongs to the transaction that was just authorized: [2](#0-1) 

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(...);
  return result;
}
```

**Contrast with `updateTransactionApprover`**, which correctly performs the cross-transaction check before acting: [3](#0-2) 

```typescript
/* Verifies that the root transaction is the same as the param */
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

/* Verifies that the user is the creator of the transaction */
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
```

The fix was applied to `updateTransactionApprover` but was never applied to `removeTransactionApprover`, leaving the delete path unguarded.

### Impact Explanation

An attacker who is the creator of any transaction (even a trivial one they created themselves) can:
1. Enumerate or guess approver IDs belonging to other transactions (IDs are sequential integers).
2. Call `DELETE /transactions/{own_tx_id}/approvers/{victim_approver_id}`.
3. The authorization check passes (they own `own_tx_id`), and the victim's approver record is permanently soft-deleted.

This allows unauthorized removal of required approvers from any pending multi-signature transaction in the organization, bypassing the approval workflow entirely and potentially allowing transactions to proceed without the required approvals, or permanently disrupting the approval tree of critical transactions.

### Likelihood Explanation

- **Precondition**: The attacker must be an authenticated, verified organization user who has created at least one transaction. This is a normal user role with no elevated privileges.
- **Approver IDs** are sequential integers (auto-increment primary keys), making enumeration trivial.
- The attack requires a single crafted HTTP DELETE request with a mismatched `transactionId`/`id` pair.
- No rate limiting or anomaly detection is needed to bypass; the authorization logic itself is structurally broken.

### Recommendation

Add the same cross-transaction ownership check that exists in `updateTransactionApprover` to the `removeTransactionApprover` service method. Specifically, after fetching the approver, resolve its root node and verify `rootNode.transactionId === transactionId` before proceeding with deletion:

```typescript
async removeTransactionApprover(id: number, transactionId: number, user: User): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

  // Verify the approver belongs to the authorized transaction
  if (rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Root transaction is not the same');

  // Verify the caller is the creator of that transaction
  await this.getCreatorsTransaction(rootNode.transactionId, user);

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

Update the controller to pass `transactionId` and `user` to the service method, and remove the redundant `getCreatorsTransaction` call from the controller since it will now be inside the service.

### Proof of Concept

**Setup:**
- User A creates Transaction 1 (attacker-controlled).
- User B creates Transaction 2 with a required approver record having `id = 99`.

**Attack:**
```
DELETE /transactions/1/approvers/99
Authorization: Bearer <User A's JWT>
```

**Expected behavior:** Request should be rejected because approver `99` belongs to Transaction 2, not Transaction 1.

**Actual behavior:** `getCreatorsTransaction(1, userA)` passes (User A owns Transaction 1). `removeTransactionApprover(99)` deletes approver `99` from Transaction 2 without any cross-transaction check. Transaction 2's approval tree is now corrupted.

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
