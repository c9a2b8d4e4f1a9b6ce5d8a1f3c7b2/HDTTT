### Title
Missing Cross-Reference Ownership Check in `removeTransactionApprover` Allows Any Transaction Creator to Delete Approvers from Other Users' Transactions

### Summary

The `DELETE /transactions/:transactionId/approvers/:id` endpoint in `ApproversController` verifies that the caller is the creator of the transaction identified by the URL parameter `transactionId`, but never verifies that the approver identified by `id` actually belongs to that same `transactionId`. Any authenticated user who has created at least one transaction can supply their own `transactionId` to pass the ownership check, then supply an arbitrary approver `id` belonging to a completely different transaction — causing that approver to be silently deleted without authorization.

### Finding Description

**Root cause — controller-level check is scoped to the wrong object:** [1](#0-0) 

```
@Delete('/:id')
async removeTransactionApprover(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Param('id', ParseIntPipe) id: number,
) {
    await this.approversService.getCreatorsTransaction(transactionId, user);  // ← checks ownership of transactionId only
    await this.approversService.removeTransactionApprover(id);                // ← deletes approver by id, no cross-check
    return true;
}
```

`getCreatorsTransaction` confirms the caller is the creator of `transactionId`: [2](#0-1) 

But `removeTransactionApprover` in the service layer only checks that the approver record exists — it never verifies the approver belongs to `transactionId`: [3](#0-2) 

```typescript
async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);
    const result = await this.removeNode(approver.id);   // ← deletes whatever approver.id points to
    emitTransactionStatusUpdate(...);
    return result;
}
```

**Contrast with `updateTransactionApprover`**, which correctly performs the cross-reference check: [4](#0-3) 

```typescript
if (rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
```

The `DELETE` path has no equivalent guard.

**Exploit flow:**

1. Attacker (User A) creates transaction `T_A` (ID = 1). They are its creator.
2. Victim (User B) creates transaction `T_B` (ID = 2) and adds an approver with ID = 99.
3. Attacker calls `DELETE /transactions/1/approvers/99`.
4. `getCreatorsTransaction(1, userA)` passes — attacker is creator of transaction 1.
5. `removeTransactionApprover(99)` deletes approver 99, which belongs to transaction 2, with no further check.
6. Victim's transaction `T_B` has its approver silently removed.

### Impact Explanation

- **Unauthorized state mutation**: Any authenticated user who has created at least one transaction can delete approvers from any other transaction in the system.
- **Approval bypass**: Removing approvers from a transaction that requires approval can allow it to proceed without the required signatures/approvals, breaking the multi-party authorization model that is the core security guarantee of the platform.
- **Denial of service on approval workflows**: An attacker can repeatedly destroy approval trees for targeted transactions, permanently disrupting their lifecycle.

### Likelihood Explanation

- **Precondition**: The attacker only needs to be a registered, verified user who has created at least one transaction — a normal, unprivileged product action.
- **No special knowledge required**: Approver IDs are sequential integers. An attacker can enumerate them trivially.
- **No rate limiting or anomaly detection** is visible on this endpoint.
- Likelihood is **high**.

### Recommendation

Inside `removeTransactionApprover` (service), after fetching the approver, verify that it belongs to the `transactionId` supplied by the caller. Mirror the pattern already used in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    // Cross-reference: ensure the approver belongs to the expected transaction
    const rootNode = await this.getRootNodeFromNode(approver.id);
    if (!rootNode || rootNode.transactionId !== transactionId)
        throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
    return result;
}
```

Pass `transactionId` from the controller call site:

```typescript
await this.approversService.removeTransactionApprover(id, transactionId);
```

### Proof of Concept

**Setup:**
- User A registers and creates transaction `T_A` (ID = 1).
- User B registers and creates transaction `T_B` (ID = 2) with an approver (approver ID = 5, `userId` = User C).

**Attack:**
```
DELETE /transactions/1/approvers/5
Authorization: Bearer <User A's JWT>
```

**Expected (correct) behavior:** `401 Unauthorized` — approver 5 does not belong to transaction 1.

**Actual behavior:** `200 OK` — approver 5 is deleted from transaction 2 without User A having any ownership over it.

**Verification:** Query the database — `transaction_approver` row with `id = 5` is soft-deleted; transaction 2's approval requirement is now broken.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L388-394)
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
