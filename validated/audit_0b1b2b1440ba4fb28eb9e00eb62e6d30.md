### Title
IDOR in `removeTransactionApprover` Allows Any Transaction Creator to Delete Approvers from Arbitrary Transactions

### Summary
In `back-end/apps/api/src/transactions/approvers/approvers.controller.ts`, the `DELETE /transactions/:transactionId/approvers/:id` handler verifies that the authenticated user is the creator of `:transactionId`, but then passes the unrelated `:id` (approver ID) directly to `approversService.removeTransactionApprover(id)`, which deletes the approver without verifying it belongs to the authorized transaction. Any user who is the creator of at least one transaction can delete approvers from any other transaction in the system.

### Finding Description
The controller performs an ownership check on the URL-supplied `transactionId`, then calls the service with the URL-supplied approver `id`:

```typescript
// approvers.controller.ts lines 103-113
@Delete('/:id')
async removeTransactionApprover(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Param('id', ParseIntPipe) id: number,
) {
    await this.approversService.getCreatorsTransaction(transactionId, user); // checks user owns transactionId
    await this.approversService.removeTransactionApprover(id);               // deletes approver `id` — no cross-check
    return true;
}
``` [1](#0-0) 

The service method `removeTransactionApprover` accepts only the approver `id` and performs no check that the approver belongs to the transaction that was just authorized:

```typescript
// approvers.service.ts lines 534-544
async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);
    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(...);
    return result;
}
``` [2](#0-1) 

By contrast, `updateTransactionApprover` in the same service correctly validates the cross-reference:

```typescript
if (rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, ...);
``` [3](#0-2) 

The ownership check `getCreatorsTransaction` enforces `creatorKey.userId === user.id` only for the transaction in the URL path, not for the transaction that actually owns the approver being deleted. [4](#0-3) 

### Impact Explanation
An attacker who is the creator of any transaction (even a trivial one they created themselves) can delete approvers from any other transaction in the organization. This directly undermines the multi-signature governance model: by removing required approvers from a victim transaction, the attacker can either prevent it from ever reaching the execution threshold or silently reduce the approval requirements, allowing a transaction to proceed without the intended oversight. This is an unauthorized state change with direct impact on transaction integrity and organizational governance.

### Likelihood Explanation
The precondition is minimal: the attacker only needs to be a registered, verified organization member who has created at least one transaction (which is a normal user action). No admin privileges, leaked secrets, or special roles are required. The approver IDs are sequential integers, making enumeration trivial. The endpoint is a standard authenticated REST call.

### Recommendation
Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver being deleted actually belongs to the authorized transaction. The fix mirrors the existing check in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const rootNode = await this.getRootNodeFromNode(approver.id);
    if (!rootNode || rootNode.transactionId !== transactionId)
        throw new UnauthorizedException('Approver does not belong to this transaction');

    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
    return result;
}
```

Update the controller to pass `transactionId` to the service method accordingly.

### Proof of Concept

**Setup:**
- Attacker is the creator of `Transaction A` (id=1), which has no approvers.
- Victim's `Transaction B` (id=2) has a critical approver with id=99 (e.g., a required governance signer).

**Steps:**
1. Attacker authenticates and obtains a JWT token.
2. Attacker sends:
   ```
   DELETE /transactions/1/approvers/99
   Authorization: Bearer <attacker_token>
   ```
3. The controller calls `getCreatorsTransaction(1, attacker)` — passes, because the attacker owns transaction 1.
4. The controller calls `removeTransactionApprover(99)` — the service looks up approver 99 (which belongs to transaction 2) and deletes it without any further check.
5. Approver 99 is permanently removed from Transaction B, corrupting its approval structure.

**Expected result (correct behavior):** 403 Unauthorized — approver 99 does not belong to transaction 1.
**Actual result:** 200 OK — approver 99 is deleted from transaction 2.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L389-394)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L638-643)
```typescript
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to modify it');

    return transaction;
```
