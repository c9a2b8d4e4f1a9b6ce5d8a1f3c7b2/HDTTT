### Title
Missing Cross-Resource Ownership Check in `removeTransactionApprover` Allows Any Transaction Creator to Delete Approvers from Other Users' Transactions

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the caller is the creator of the transaction identified by `:transactionId`, but never verifies that the approver identified by `:id` actually belongs to that same transaction. An attacker who is the creator of any transaction can supply their own `transactionId` to pass the ownership check, then supply an arbitrary approver `id` from a victim's transaction to delete it — bypassing the approval workflow for transactions they do not own.

### Finding Description

**Root cause — controller-level check uses a different resource than the deletion target:**

In `approvers.controller.ts`, the `DELETE /:id` handler first calls `getCreatorsTransaction(transactionId, user)` to verify the caller owns the transaction in the URL, then calls `removeTransactionApprover(id)` with the approver ID from the URL path: [1](#0-0) 

`getCreatorsTransaction` only checks `transaction.creatorKey?.userId !== user.id` for the URL's `transactionId` — it says nothing about the approver `id`: [2](#0-1) 

`removeTransactionApprover` then fetches the approver by `id` and deletes it with no check that `approver.transactionId` matches the URL's `transactionId`: [3](#0-2) 

**Contrast with `updateTransactionApprover`**, which correctly validates that the approver's root transaction matches the URL parameter before proceeding: [4](#0-3) 

The delete path is missing this exact guard.

**Exploit flow:**
1. Attacker registers an account and creates any transaction → becomes its creator (own `transactionId = T_own`).
2. Attacker enumerates or guesses an approver `id` (`A_victim`) belonging to a different user's transaction.
3. Attacker sends: `DELETE /transactions/T_own/approvers/A_victim`.
4. `getCreatorsTransaction(T_own, attacker)` passes — attacker owns `T_own`.
5. `removeTransactionApprover(A_victim)` deletes the victim's approver with no further check.

### Impact Explanation
Deleting an approver from a transaction removes a required approval gate. If the victim's transaction requires a threshold of approvers (e.g., 2-of-3), an attacker can reduce the approver set below the threshold or remove specific approvers entirely, causing the approval workflow to be bypassed or broken. This is an unauthorized state mutation on another user's transaction — a direct integrity failure in the trust model of the multi-signature workflow.

### Likelihood Explanation
The attacker needs only:
- A valid authenticated account (no admin privileges).
- Knowledge of any approver `id` from another transaction. Approver IDs are sequential database integers, making them trivially enumerable via the `GET /transactions/:transactionId/approvers` endpoint on any transaction the attacker has access to, or by brute-forcing small integers.

No leaked secrets, no privileged access, and no cryptographic break are required.

### Recommendation
Add the same cross-resource ownership check that `updateTransactionApprover` already performs. Inside `removeTransactionApprover`, after fetching the approver, resolve its root transaction and verify it matches the caller's authorized `transactionId`:

```typescript
async removeTransactionApprover(id: number, transactionId: number, user: User): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Verify the approver belongs to the transaction the caller is authorized for
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId) {
    throw new UnauthorizedException('Approver does not belong to this transaction');
  }

  // Verify the caller is the creator of that transaction
  await this.getCreatorsTransaction(rootNode.transactionId, user);

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(...);
  return result;
}
```

The controller's standalone `getCreatorsTransaction` call can then be removed since the service now owns the full authorization check — matching the pattern already used in `updateTransactionApprover`. [5](#0-4) 

### Proof of Concept

**Preconditions:**
- Two registered, verified accounts: `attacker` and `victim`.
- `victim` has created a transaction `T_victim` with an approver record `A_victim` (approver ID = 7, for example).
- `attacker` has created any transaction `T_own` (transaction ID = 3, for example).

**Steps:**
```
# 1. Attacker logs in and obtains JWT
POST /auth/login  { email: "attacker@x.com", password: "..." }
→ { token: "JWT_ATTACKER" }

# 2. Attacker calls delete using their own transactionId but victim's approver id
DELETE /transactions/3/approvers/7
Authorization: Bearer JWT_ATTACKER

# 3. getCreatorsTransaction(3, attacker) → passes (attacker owns tx 3)
# 4. removeTransactionApprover(7) → deletes victim's approver with no further check

→ HTTP 200 true
```

**Expected result:** `403 Unauthorized` — approver 7 does not belong to transaction 3.

**Actual result:** `200 true` — victim's approver is silently deleted, corrupting the approval workflow of `T_victim`.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L366-395)
```typescript
  /* Updates an approver of a transaction */
  async updateTransactionApprover(
    id: number,
    dto: UpdateTransactionApproverDto,
    transactionId: number,
    user: User,
  ): Promise<TransactionApprover> {
    try {
      let updated = false;

      const approver = await this.dataSource.transaction(async transactionalEntityManager => {
        /* Check if the dto updates only one thing */
        if (Object.keys(dto).length > 1 || Object.keys(dto).length === 0)
          throw new Error(this.INVALID_UPDATE_APPROVER);

        /* Verifies that the approver exists */
        const approver = await this.getTransactionApproverById(id, transactionalEntityManager);
        if (!approver) throw new BadRequestException(ErrorCodes.ANF);

        /* Gets the root approver */
        const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
        if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

        /* Verifies that the root transaction is the same as the param */
        if (rootNode.transactionId !== transactionId)
          throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

        /* Verifies that the user is the creator of the transaction */
        await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);

```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L534-543)
```typescript
  async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);

    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const result = await this.removeNode(approver.id);

    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);

    return result;
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
