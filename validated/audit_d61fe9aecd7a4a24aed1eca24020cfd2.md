### Title
Any Authenticated Transaction Creator Can Delete Approvers Belonging to Other Users' Transactions

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the requesting user is the creator of the transaction identified by `:transactionId`, but never verifies that the approver identified by `:id` actually belongs to that transaction. A malicious user who owns any transaction can supply their own `transactionId` to pass the ownership check, then supply an arbitrary approver `id` from a completely different transaction to delete it.

### Finding Description

**Root cause:** In `approvers.controller.ts`, the `removeTransactionApprover` handler performs two independent operations:

1. `getCreatorsTransaction(transactionId, user)` — verifies the caller is the creator of the URL's `:transactionId`.
2. `removeTransactionApprover(id)` — deletes the approver row with the given `:id`.

There is no check that the approver `:id` belongs to `:transactionId`. [1](#0-0) 

The service method `removeTransactionApprover` only checks that the approver exists, then deletes it unconditionally: [2](#0-1) 

Contrast this with `updateTransactionApprover`, which correctly validates that the approver's root transaction matches the URL parameter **and** that the user is the creator of that root transaction: [3](#0-2) 

**Exploit path:**
1. Attacker registers as a normal user and creates transaction A (attacker is its creator).
2. Attacker enumerates or guesses approver IDs belonging to victim's transaction B (IDs are sequential integers).
3. Attacker calls `DELETE /transactions/A/approvers/{victimApproverID}`.
4. The controller passes the ownership check (attacker owns A), then the service deletes the victim's approver without any cross-transaction validation.

### Impact Explanation

Removing an approver from a transaction that requires multi-party approval can:
- Bypass the approval threshold, allowing a transaction to proceed to execution without the required signatures.
- Permanently corrupt the approval workflow of any transaction in the system.
- Silently remove a required approver without the transaction creator's knowledge.

This is an unauthorized state change with direct impact on transaction integrity and multi-signature security guarantees.

### Likelihood Explanation

Any registered, verified user who has created at least one transaction can exploit this. No admin or privileged access is required. Approver IDs are sequential integers, making enumeration trivial. The attacker only needs a valid JWT token.

### Recommendation

In `removeTransactionApprover` (controller), after fetching the approver, verify that the approver's root transaction matches the URL's `transactionId` before deleting. The simplest fix mirrors what `updateTransactionApprover` already does:

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user);
  // Add: verify the approver belongs to transactionId
  const rootNode = await this.approversService.getRootNodeFromNode(id);
  if (!rootNode || rootNode.transactionId !== transactionId) {
    throw new UnauthorizedException('Approver does not belong to this transaction');
  }
  await this.approversService.removeTransactionApprover(id);
  return true;
}
```

Alternatively, move the cross-transaction check into `removeTransactionApprover` itself, as `updateTransactionApprover` does at the service layer.

### Proof of Concept

**Setup:**
- User A creates transaction 1 (attacker-owned).
- User B creates transaction 2 with approver record ID = 42.

**Attack:**
```
DELETE /transactions/1/approvers/42
Authorization: Bearer <User A's JWT>
```

**Expected (correct) behavior:** 403 Unauthorized — approver 42 does not belong to transaction 1.

**Actual behavior:** 200 OK — approver 42 is deleted from transaction 2 without any authorization check, because `getCreatorsTransaction(1, userA)` passes (user A owns transaction 1), and `removeTransactionApprover(42)` deletes approver 42 with no transaction-membership validation. [1](#0-0) [2](#0-1)

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
