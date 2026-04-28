### Title
Cross-Transaction Approver Deletion via Missing Ownership Binding in `removeTransactionApprover`

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the caller is the creator of `:transactionId`, but then deletes the approver identified by `:id` without confirming that approver actually belongs to `:transactionId`. Any authenticated user who owns at least one transaction can delete approvers from any other user's transaction by supplying their own `transactionId` and a victim's approver `id`. This silently removes required approval gates from transactions the attacker does not own, bypassing the multi-signature approval workflow.

### Finding Description

**Root cause — controller/service ownership mismatch**

`ApproversController.removeTransactionApprover` performs two independent operations: [1](#0-0) 

1. `getCreatorsTransaction(transactionId, user)` — confirms the caller is the creator of the URL-supplied `transactionId`.
2. `removeTransactionApprover(id)` — deletes the approver row identified by the URL-supplied `id`.

`ApproversService.removeTransactionApprover` accepts only the approver `id` and performs no cross-check against any transaction: [2](#0-1) 

There is no assertion that `approver.transactionId === transactionId` (or that the approver's root node belongs to that transaction). The authorization check and the deletion target are completely decoupled.

**Exploit path**

1. Attacker (User A) registers and creates their own transaction → receives `transactionId = 7`.
2. Attacker learns approver `id = 42` belonging to victim's transaction `transactionId = 3` (sequential integer IDs are guessable; the attacker may also be an observer or signer on transaction 3 and can enumerate approver IDs via `GET /transactions/3/approvers`).
3. Attacker sends:
   ```
   DELETE /transactions/7/approvers/42
   Authorization: Bearer <attacker_jwt>
   ```
4. `getCreatorsTransaction(7, attacker)` passes — attacker owns transaction 7.
5. `removeTransactionApprover(42)` executes `removeNode(42)` with no ownership check, soft-deleting approver 42 (and its entire child subtree) from transaction 3. [3](#0-2) 

### Impact Explanation
Removing an approver from a transaction eliminates a required approval gate. In a threshold-based approval tree, deleting enough approvers can reduce the required threshold below the remaining count, or remove the entire tree, allowing a transaction to proceed to execution without the intended multi-party consent. This directly undermines the core security invariant of the platform (HIP-1300 multi-signature workflows) and can result in unauthorized Hedera network transactions being submitted on behalf of an organization.

### Likelihood Explanation
- **Preconditions**: The attacker must be an authenticated, verified user (`JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard` are all satisfied by any normal account) and must own at least one transaction of their own.
- **Approver ID discovery**: Approver IDs are sequential database integers. An attacker who is a signer, observer, or approver on any shared transaction can call `GET /transactions/:id/approvers` to enumerate IDs. Even without that, sequential IDs are trivially brute-forced.
- **No rate limiting or anomaly detection** is visible in the controller path.

This is a realistic attack for any registered user in a multi-user organization deployment.

### Recommendation
Inside `removeTransactionApprover` (or before calling it in the controller), verify that the approver's root transaction matches the authorized `transactionId`. The simplest fix is to pass `transactionId` into the service method and assert ownership:

```typescript
// approvers.service.ts
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Verify the approver belongs to the authorized transaction
  const root = await this.getRootNodeFromNode(approver.id);
  if (!root || root.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to this transaction');

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
``` [2](#0-1) 

The `updateTransactionApprover` method already demonstrates the correct pattern — it calls `getRootNodeFromNode` and asserts `rootNode.transactionId === transactionId` before proceeding: [4](#0-3) 

The delete path must apply the same guard.

### Proof of Concept

**Setup**:
- User A (attacker) creates transaction `T_A` → internal id `7`.
- User B (victim) creates transaction `T_B` → internal id `3`, with approver `id = 42` (User C must approve before execution).

**Attack**:
```http
DELETE /transactions/7/approvers/42
Authorization: Bearer <User_A_JWT>
```

**Expected (correct) behavior**: 403 Unauthorized — approver 42 does not belong to transaction 7.

**Actual behavior**: 200 OK — approver 42 is soft-deleted from transaction 3. User B's transaction now has its approval requirement silently removed, and the transaction can proceed to execution without User C's approval. [1](#0-0) [2](#0-1)

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
