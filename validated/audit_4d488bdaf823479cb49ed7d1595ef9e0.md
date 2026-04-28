### Title
Any Transaction Creator Can Delete Approvers Belonging to Other Transactions via Missing Cross-Reference Check in `removeTransactionApprover`

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the calling user is the creator of `:transactionId`, but then deletes the approver identified by `:id` without verifying that `:id` actually belongs to `:transactionId`. Any authenticated user who is the creator of at least one transaction can exploit this to delete approvers from any other transaction in the system by supplying their own `transactionId` and a victim's approver `id`.

### Finding Description

**Root cause:** In `approvers.controller.ts`, the `removeTransactionApprover` handler performs two independent operations:

1. `getCreatorsTransaction(transactionId, user)` — verifies the caller is the creator of the URL-supplied `transactionId`.
2. `removeTransactionApprover(id)` — deletes the approver tree rooted at `id` with no check that `id` belongs to `transactionId`. [1](#0-0) 

The service method `removeTransactionApprover` fetches the approver by its primary key and immediately soft-deletes it (and its entire subtree via `removeNode`) without any transaction-ownership validation: [2](#0-1) 

Compare this with `updateTransactionApprover`, which correctly validates that the approver's root transaction matches the URL parameter before checking creator ownership: [3](#0-2) 

The `getCreatorsTransaction` helper only checks ownership of the transaction passed to it — it says nothing about the approver `id`: [4](#0-3) 

**Exploit path:**

1. Attacker registers an account and creates any transaction (transaction A). They are now the creator of A.
2. Attacker enumerates approver IDs (sequential integers) to find approver `B` belonging to victim transaction C.
3. Attacker sends: `DELETE /transactions/A/approvers/B`
4. Server calls `getCreatorsTransaction(A, attacker)` → passes (attacker owns A).
5. Server calls `removeTransactionApprover(B)` → deletes approver B (and its entire subtree) from transaction C without any ownership check.

### Impact Explanation

An attacker can silently remove any approver (or entire approver threshold tree) from any transaction in the system. This directly undermines the multi-signature approval workflow: a transaction that required N-of-M approvals can have its approvers deleted, potentially allowing it to proceed to execution with fewer or no approvals than intended. This constitutes unauthorized state mutation and integrity failure in the trust/approval model.

### Likelihood Explanation

The attacker only needs to be a normal authenticated user who has created at least one transaction — a baseline capability for any organization member. Approver IDs are sequential integers, making enumeration trivial. No privileged access, leaked credentials, or cryptographic breaks are required.

### Recommendation

In the `removeTransactionApprover` controller handler, after fetching the approver by `id`, verify that the approver's root transaction matches the URL-supplied `transactionId` before proceeding with deletion. Mirror the pattern already used in `updateTransactionApprover`:

```typescript
// In the controller, after getCreatorsTransaction:
const approver = await this.approversService.getTransactionApproverById(id);
const root = await this.approversService.getRootNodeFromNode(approver.id);
if (root?.transactionId !== transactionId) {
  throw new UnauthorizedException('Approver does not belong to this transaction');
}
await this.approversService.removeTransactionApserver(id);
```

Alternatively, move the full ownership check into `removeTransactionApprover` itself so it cannot be called without a transaction-scoped authorization check.

### Proof of Concept

**Setup:** Two users — Alice (creator of transaction 1) and Bob (creator of transaction 2). Bob adds an approver (approver ID = 5) to transaction 2.

**Attack:**
```
DELETE /transactions/1/approvers/5
Authorization: Bearer <Alice's JWT>
```

**Expected (correct) behavior:** 401 Unauthorized — Alice is not the creator of transaction 2.

**Actual behavior:** 200 OK — `getCreatorsTransaction(1, Alice)` passes; `removeTransactionApprover(5)` deletes approver 5 from transaction 2 without any ownership check. [1](#0-0) [2](#0-1)

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
