### Title
Missing Transaction Ownership Cross-Check in `removeTransactionApprover` Allows Deletion of Approvers Belonging to Other Transactions

---

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller is the creator of the transaction identified by `:transactionId`, but never verifies that the approver identified by `:id` actually belongs to that same transaction. Any authenticated user who owns at least one transaction can delete approvers from any other transaction they do not own.

---

### Finding Description
In `approvers.controller.ts`, the delete handler performs two sequential calls:

```typescript
// approvers.controller.ts lines 102–113
@Delete('/:id')
async removeTransactionApprover(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Param('id', ParseIntPipe) id: number,
) {
    await this.approversService.getCreatorsTransaction(transactionId, user);
    await this.approversService.removeTransactionApprover(id);
    return true;
}
```

`getCreatorsTransaction(transactionId, user)` confirms the caller created the transaction at `:transactionId`. However, `removeTransactionApprover(id)` then deletes the approver row by `:id` with no check that `approver.transactionId === transactionId`:

```typescript
// approvers.service.ts lines 534–544
async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);
    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(...);
    return result;
}
```

The service function accepts only `id` — no `transactionId`, no `user`. There is no cross-reference check.

By contrast, `updateTransactionApprover` in the same service **correctly** performs this check:

```typescript
// approvers.service.ts lines 386–394
const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);
if (rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
```

The delete path is missing the equivalent guard that the update path has.

---

### Impact Explanation
An attacker who is the creator of any transaction (even a trivial one they created themselves) can delete approvers from any other transaction in the system. This disrupts the approval workflow of victim transactions — removing required approvers can cause a transaction to bypass its intended approval threshold, or silently eliminate a required signer from the approval tree, allowing a transaction to proceed without the intended authorization.

---

### Likelihood Explanation
Any registered, verified user can create a transaction, satisfying the ownership check on their own transaction. Approver IDs are sequential integers, making enumeration trivial. No special privilege is required beyond a valid account. The attack requires only two pieces of information: the attacker's own `transactionId` and a target `approverId` from another transaction.

---

### Recommendation
In `removeTransactionApprover`, add the same cross-reference check that `updateTransactionApprover` already performs. Specifically, after fetching the approver, resolve its root node and verify `rootNode.transactionId === transactionId`, then confirm the caller is the creator of that transaction:

```typescript
async removeTransactionApprover(id: number, transactionId: number, user: User): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const rootNode = await this.getRootNodeFromNode(approver.id);
    if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);
    if (rootNode.transactionId !== transactionId)
        throw new UnauthorizedException('Approver does not belong to this transaction');

    await this.getCreatorsTransaction(rootNode.transactionId, user);
    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
    return result;
}
```

The controller's separate `getCreatorsTransaction` call (line 108) can then be removed since the service now owns the full authorization check.

---

### Proof of Concept

**Setup:**
- User A creates Transaction 1 (owns it).
- User B creates Transaction 2 and adds Approver with `id = 99` to it.

**Attack:**
```
DELETE /transactions/1/approvers/99
Authorization: Bearer <User A's JWT>
```

**Step-by-step:**
1. Controller calls `getCreatorsTransaction(1, userA)` → passes, because User A created Transaction 1.
2. Controller calls `removeTransactionApprover(99)` → fetches approver 99 (which belongs to Transaction 2), calls `removeNode(99)`, deletes it.
3. Approver 99 is permanently deleted from Transaction 2 with no authorization from User B.

**Root cause references:** [1](#0-0) [2](#0-1) [3](#0-2)

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
