### Title
Cross-Transaction Approver Deletion: Creator of Any Transaction Can Delete Approvers Belonging to Other Transactions

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the caller is the creator of the transaction identified by `:transactionId`, but never verifies that the approver identified by `:id` actually belongs to that same transaction. Any authenticated user who is the creator of at least one transaction can delete approvers from any other transaction in the system by supplying their own `transactionId` and a victim's `approver id`.

### Finding Description

**Root cause:** The controller's `removeTransactionApprover` handler performs two independent, uncorrelated checks:

```
back-end/apps/api/src/transactions/approvers/approvers.controller.ts  lines 102-113
```

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user);  // checks user owns transactionId
  await this.approversService.removeTransactionApprover(id);                // deletes approver by id — no cross-check
  return true;
}
```

`getCreatorsTransaction` only confirms the caller is the creator of the transaction referenced by the URL's `:transactionId` parameter. [1](#0-0) 

`removeTransactionApprover` then deletes whatever approver row has the supplied `:id`, with no check that this approver's `transactionId` matches the URL's `:transactionId`. [2](#0-1) 

**Contrast with `updateTransactionApprover`**, which correctly performs the cross-check:

```typescript
/* Verifies that the root transaction is the same as the param */
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
``` [3](#0-2) 

The `removeTransactionApprover` service method was written without a `user` or `transactionId` parameter, making it structurally impossible to perform the binding check inside the service. [4](#0-3) 

**Exploit path:**
1. Attacker registers as a normal user and creates any transaction (Transaction A). They are now the creator of Transaction A.
2. Attacker enumerates approver IDs (sequential integers) to find an approver ID belonging to Transaction B (owned by another user).
3. Attacker sends: `DELETE /transactions/{A_id}/approvers/{victim_approver_id}`
4. `getCreatorsTransaction(A_id, attacker)` passes — attacker is creator of A.
5. `removeTransactionApprover(victim_approver_id)` executes with no further check — the victim's approver is deleted.

### Impact Explanation

An attacker can silently remove required approvers from any transaction in the system. In the multi-signature organization workflow, approvers are the gatekeepers that must sign off before a transaction is submitted to the Hedera network. Removing an approver can:

- Reduce the required approval threshold, allowing a transaction to proceed with fewer authorizations than intended.
- Completely remove all approvers from a transaction, bypassing the approval gate entirely.
- Disrupt or permanently corrupt the approval state of any in-flight transaction.

This is an unauthorized state change with direct impact on transaction integrity and the multi-signature trust model.

### Likelihood Explanation

The precondition is minimal: the attacker only needs to be a registered, verified user and the creator of any one transaction (which is a normal product workflow). Approver IDs are sequential database integers and are returned in API responses, making enumeration trivial. No privileged access, leaked credentials, or cryptographic break is required.

### Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver being deleted actually belongs to the transaction the caller owns. Mirror the pattern already used in `updateTransactionApprover`:

```typescript
// In approvers.service.ts — removeTransactionApprover
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Resolve the root node (handles child approvers whose own transactionId is null)
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to this transaction');

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
- User A creates Transaction 1 (attacker-owned).
- User B creates Transaction 2 with an approver (approver ID = 99) assigned to User C.

**Attack:**
```http
DELETE /transactions/1/approvers/99
Authorization: Bearer <User A JWT>
```

**Expected (correct) behavior:** 401 Unauthorized — approver 99 does not belong to Transaction 1.

**Actual behavior:** 200 OK — approver 99 is deleted from Transaction 2 without User A having any ownership of Transaction 2 or its approvers. [5](#0-4) [2](#0-1)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L389-391)
```typescript
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
