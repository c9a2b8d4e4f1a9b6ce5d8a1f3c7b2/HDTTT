### Title
Any Transaction Creator Can Delete Approvers Belonging to Other Transactions via IDOR in `removeTransactionApprover`

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller is the creator of the transaction identified by `transactionId`, but then deletes the approver identified by `id` without verifying that approver actually belongs to `transactionId`. Any authenticated user who is the creator of at least one transaction can delete approvers from any other user's transaction.

### Finding Description

**Root cause:** In `approvers.controller.ts`, the `removeTransactionApprover` handler performs an authorization check on `transactionId` and a state mutation on `id` — two independent parameters — without cross-validating that the target approver belongs to the authorized transaction. [1](#0-0) 

```
Step 1: getCreatorsTransaction(transactionId, user)  ← checks user owns transactionId
Step 2: removeTransactionApprover(id)                ← deletes approver by id, no ownership check
```

The service-level `removeTransactionApprover` only checks that the approver record exists, then deletes it unconditionally: [2](#0-1) 

There is no check that `approver.transactionId` (or its root node's `transactionId`) matches the `transactionId` the caller was authorized against.

**Contrast with `updateTransactionApprover`**, which correctly performs this cross-validation: [3](#0-2) 

The `update` path verifies `rootNode.transactionId !== transactionId` before proceeding. The `delete` path has no equivalent check.

**Exploit path:**
1. Attacker (authenticated, verified user) creates their own transaction — call it `txA`. They are its creator.
2. Victim creates `txB` with approvers. Attacker enumerates or guesses an approver ID (`approverB_id`) belonging to `txB`.
3. Attacker sends: `DELETE /transactions/{txA_id}/approvers/{approverB_id}`
4. `getCreatorsTransaction(txA_id, attacker)` passes — attacker IS the creator of `txA`.
5. `removeTransactionApprover(approverB_id)` deletes the approver from `txB` with no further check.

### Impact Explanation

An attacker can silently remove any approver from any transaction they do not own. This breaks the multi-signature approval workflow: a transaction that required N approvals can have its approvers stripped, potentially allowing it to proceed without the intended governance controls, or permanently corrupting the approval tree of another user's transaction. This is an unauthorized state change with direct integrity impact on the transaction approval model.

### Likelihood Explanation

The attacker only needs to be an authenticated, verified user and the creator of at least one transaction (a normal product flow). Approver IDs are sequential integers, making enumeration trivial. No privileged access, leaked secrets, or special timing is required.

### Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver's root transaction matches the `transactionId` the caller was authorized against — mirroring the check already present in `updateTransactionApprover`:

```typescript
// In the controller, after getCreatorsTransaction:
const approver = await this.approversService.getTransactionApproverById(id);
const root = await this.approversService.getRootNodeFromNode(approver.id);
if (root.transactionId !== transactionId) {
  throw new UnauthorizedException('Approver does not belong to this transaction');
}
await this.approversService.removeTransactionApprover(id);
```

### Proof of Concept

1. Attacker registers and logs in as `attacker@example.com` (verified user).
2. Attacker creates `txA` → receives `txA_id`.
3. Victim creates `txB` with an approver → `approverB_id` is returned (or enumerated as integer `N`).
4. Attacker sends:
   ```
   DELETE /transactions/{txA_id}/approvers/{approverB_id}
   Authorization: Bearer <attacker_jwt>
   ```
5. Response: `200 true` — the approver belonging to `txB` is deleted.
6. Victim's transaction `txB` now has its approval tree corrupted without the victim's or the creator's consent.

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
