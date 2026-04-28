### Title
Missing Cross-Reference Validation in `removeTransactionApprover` Allows Any Transaction Creator to Delete Approvers Belonging to Other Transactions

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint authorizes the caller by verifying they are the creator of `transactionId`, but then removes the approver identified by `:id` without ever verifying that approver actually belongs to `transactionId`. This is the direct analog of the reported vulnerability: a reference is used for authorization, but the state mutation targets a different element without validating the relationship between them. Any authenticated user who has created at least one transaction can delete approvers from any other transaction in the system.

### Finding Description

The controller at `back-end/apps/api/src/transactions/approvers/approvers.controller.ts` handles deletion as follows:

```typescript
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
``` [1](#0-0) 

`getCreatorsTransaction(transactionId, user)` only verifies the caller is the creator of `transactionId`. It says nothing about the approver identified by `id`. [2](#0-1) 

`removeTransactionApprover(id)` then fetches the approver by `id` and soft-deletes its entire subtree — with **no check that the approver belongs to `transactionId`**:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);
    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
    return result;
}
``` [3](#0-2) 

`removeNode` performs a recursive soft-delete of the entire approver subtree rooted at `id`: [4](#0-3) 

The missing check is: **`approver.transactionId === transactionId`** (or equivalently, that the root of the approver tree belongs to `transactionId`). The `updateTransactionApprover` path correctly performs this check at line 390, but `removeTransactionApprover` does not. [5](#0-4) 

The `TransactionApprover` entity uses `transactionId` (for root nodes) and `listId` (for child nodes) to encode tree membership: [6](#0-5) 

### Impact Explanation

An attacker who is the creator of any transaction (even a trivial one they created themselves) can:

1. Enumerate approver IDs (sequential integers) belonging to any other transaction.
2. Call `DELETE /transactions/{their_own_txId}/approvers/{victim_approver_id}`.
3. The authorization check passes (they are the creator of `their_own_txId`).
4. The approver with `victim_approver_id` — belonging to a completely different transaction — is soft-deleted along with its entire subtree.

This allows **unauthorized destruction of approval requirements on any transaction in the system**, enabling transactions to proceed without the required approvals. It also causes **permanent corruption of the approver tree** for victim transactions, which cannot be recovered without manual database intervention.

### Likelihood Explanation

The preconditions are minimal: the attacker must be a registered, verified user who has created at least one transaction. This is a normal user flow. Approver IDs are sequential integers and are trivially enumerable via the `GET /transactions/:transactionId/approvers` endpoint (which returns IDs). No privileged access, leaked credentials, or external dependencies are required.

### Recommendation

In `removeTransactionApprover` (or in the controller before calling it), verify that the approver being deleted actually belongs to the authorized `transactionId`. The same pattern already used in `updateTransactionApprover` should be applied:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    // Verify the approver belongs to the authorized transaction
    const rootNode = await this.getRootNodeFromNode(approver.id);
    if (!rootNode || rootNode.transactionId !== transactionId)
        throw new UnauthorizedException('Approver does not belong to this transaction');

    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);
    return result;
}
```

This mirrors the check already present in `updateTransactionApprover` at lines 386–391. [5](#0-4) 

### Proof of Concept

**Setup:**
- User A creates Transaction T1 (attacker-controlled).
- User B creates Transaction T2 with an approver tree: root approver node with `id = 42`, `transactionId = T2.id`.

**Attack:**
```http
DELETE /transactions/{T1.id}/approvers/42
Authorization: Bearer <User A's JWT>
```

**Execution path:**
1. `getCreatorsTransaction(T1.id, userA)` → passes (User A is creator of T1).
2. `removeTransactionApprover(42)` → fetches approver 42 (belongs to T2), calls `removeNode(42)`.
3. `removeNode(42)` soft-deletes approver 42 and all its children via recursive CTE.

**Result:** Transaction T2's entire approver tree is destroyed. T2 can now proceed without the required approvals, or its approval state is permanently corrupted. User A never had any relationship to T2. [1](#0-0) [3](#0-2)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L386-391)
```typescript
        const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
        if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

        /* Verifies that the root transaction is the same as the param */
        if (rootNode.transactionId !== transactionId)
          throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L623-644)
```typescript
  /* Get the transaction by id and verifies that the user is the creator */
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

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L24-42)
```typescript
  /* If the approver has a listId, then transactionId should be null */
  @ManyToOne(() => Transaction, transaction => transaction.approvers, {
    nullable: true,
  })
  @JoinColumn({ name: 'transactionId' })
  transaction?: Transaction;

  @Column({ nullable: true })
  transactionId?: number;

  @ManyToOne(() => TransactionApprover, approverList => approverList.approvers, {
    nullable: true,
  })
  @JoinColumn({ name: 'listId' })
  list?: TransactionApprover;

  @Column({ nullable: true })
  listId?: number;

```
