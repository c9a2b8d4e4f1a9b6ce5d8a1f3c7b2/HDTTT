### Title
`removeTransactionApprover` Does Not Verify the Approver Belongs to the URL-Scoped Transaction, Allowing Cross-Transaction Approver Deletion

### Summary

The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies only that the requesting user is the creator of the transaction identified by `:transactionId`, but then passes the raw `:id` to `removeTransactionApprover` without confirming that the targeted approver record actually belongs to that transaction. Any user who is the creator of at least one transaction and has visibility into another transaction's approver IDs can silently delete approvers from that foreign transaction.

### Finding Description

**Root cause — missing cross-transaction ownership check in `removeTransactionApprover`**

The controller handler:

```
back-end/apps/api/src/transactions/approvers/approvers.controller.ts  lines 102-113
```

calls two service methods in sequence:

1. `getCreatorsTransaction(transactionId, user)` — confirms the caller is the creator of the transaction in the URL.
2. `removeTransactionApprover(id)` — looks up the approver by primary key `id` and soft-deletes it (and its entire subtree) with no check that `approver.transactionId` (or its root's `transactionId`) equals the URL-supplied `transactionId`. [1](#0-0) 

The service method: [2](#0-1) 

`getTransactionApproverById` fetches by `id` alone with no transaction scope: [3](#0-2) 

`removeNode` then recursively soft-deletes the entire approver subtree, again with no transaction constraint: [4](#0-3) 

**Contrast with the sibling operations that are safe**

`updateTransactionApprover` explicitly validates `rootNode.transactionId !== transactionId` before proceeding: [5](#0-4) 

`createTransactionApprovers` validates the same invariant for any supplied `listId`: [6](#0-5) 

Only the delete path omits this guard.

**Exploit flow**

1. Attacker creates transaction A (they become its creator — a normal user action).
2. Attacker is added as an approver or observer to transaction B (owned by a different creator).
3. Attacker calls `GET /transactions/B/approvers` — `getVerifiedApproversByTransactionId` grants access because the attacker is a participant; the response includes the integer primary-key IDs of B's approvers. [7](#0-6) 

4. Attacker calls `DELETE /transactions/A/approvers/<approver_B_id>`.
5. `getCreatorsTransaction(A, attacker)` passes — attacker is creator of A.
6. `removeTransactionApprover(<approver_B_id>)` deletes the approver (and its entire subtree) from transaction B without any further check.

### Impact Explanation

- **Unauthorized state mutation**: Any approver (including threshold-list root nodes and their entire subtrees) can be deleted from a transaction the attacker does not own.
- **Approval-workflow bypass**: Deleting required approvers from a transaction in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` status can reduce the effective approval threshold, potentially allowing the transaction to advance to execution without the intended governance sign-off.
- **Denial of service on approval workflows**: Deleting all approvers from a transaction prevents it from ever reaching `WAITING_FOR_EXECUTION`, permanently stalling it.
- Secondary: when the deleted approver is a nested node (`transactionId = null`), the `emitTransactionStatusUpdate` call fires with `entityId: null`, corrupting the notification event. [8](#0-7) 

### Likelihood Explanation

- **No privileged access required**: the attacker needs only (a) to have created any transaction (a standard user action) and (b) to be a participant (approver, observer, or signer) in the target transaction — both are reachable without admin rights.
- Approver primary-key IDs are sequential integers exposed through the normal `GET /transactions/:id/approvers` endpoint to any participant.
- The attack is a single authenticated HTTP request with no race condition or timing dependency.

### Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), resolve the root node of the targeted approver and assert that its `transactionId` equals the URL-supplied `transactionId`, mirroring the guard already present in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Guard: ensure the approver belongs to the expected transaction
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to this transaction');

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);
  return result;
}
```

Pass `transactionId` from the controller, which already holds the verified value.

### Proof of Concept

**Preconditions**
- User Alice is the creator of transaction `T_A` (id = 10).
- User Alice is also an approver of transaction `T_B` (id = 20), owned by Bob.
- `T_B` has an approver record with id = 99 (Bob's required approver).

**Steps**
1. Alice calls `GET /transactions/20/approvers` → receives `[{id: 99, userId: <Bob's approver>, ...}]`.
2. Alice calls `DELETE /transactions/10/approvers/99` with her JWT.
3. Server executes `getCreatorsTransaction(10, Alice)` → passes (Alice created T_A).
4. Server executes `removeTransactionApprover(99)` → soft-deletes approver 99 (Bob's required approver on T_B) with no further check.
5. `T_B`'s approval tree is now missing a required approver; the transaction is stalled or its threshold is effectively reduced. [1](#0-0) [2](#0-1)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L110-152)
```typescript
  /* Get the full list of approvers by transactionId if user has access */
  async getVerifiedApproversByTransactionId(
    transactionId: number,
    user: User,
  ): Promise<TransactionApprover[]> {
    const transaction = await this.dataSource.manager.findOne(Transaction, {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user', 'observers', 'signers', 'signers.userKey'],
    });

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    const approvers = await this.getApproversByTransactionId(transactionId);

    const userKeysToSign = await userKeysRequiredToSign(
      transaction,
      user,
      this.transactionSignatureService,
      this.dataSource.manager,
    );

    if (
      [
        TransactionStatus.EXECUTED,
        TransactionStatus.EXPIRED,
        TransactionStatus.FAILED,
        TransactionStatus.CANCELED,
        TransactionStatus.ARCHIVED,
      ].includes(transaction.status)
    )
      return approvers;

    if (
      userKeysToSign.length === 0 &&
      transaction.creatorKey?.userId !== user.id &&
      !transaction.observers.some(o => o.userId === user.id) &&
      !transaction.signers.some(s => s.userKey?.userId === user.id) &&
      !approvers.some(a => a.userId === user.id)
    )
      throw new UnauthorizedException("You don't have permission to view this transaction");

    return approvers;
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L261-267)
```typescript
            /* Check if the root transaction is the same */
            const root = await this.getRootNodeFromNode(
              dtoApprover.listId,
              transactionalEntityManager,
            );
            if (root?.transactionId !== transactionId)
              throw new Error(this.ROOT_TRANSACTION_NOT_SAME);
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
