### Title
IDOR in `removeTransactionApprover` Allows Any Transaction Creator to Delete Approvers from Arbitrary Transactions

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller is the creator of `:transactionId`, but never validates that the approver record identified by `:id` actually belongs to that transaction. Any authenticated user who has created at least one transaction can supply their own `transactionId` for the ownership check while targeting an approver `id` from a completely different transaction, silently deleting it.

### Finding Description

**Root cause — controller/service split with no cross-reference check**

The controller performs an ownership check on `transactionId`, then unconditionally delegates deletion to the service using the unrelated `id` parameter:

```
back-end/apps/api/src/transactions/approvers/approvers.controller.ts  lines 102-113
``` [1](#0-0) 

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user);  // ← checks ownership of transactionId
  await this.approversService.removeTransactionApprover(id);                // ← deletes approver by id, no cross-check
  return true;
}
```

The service method `removeTransactionApprover` accepts only the approver primary key and performs no ownership or transaction-membership validation: [2](#0-1) 

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);   // recursive soft-delete, no transactionId check
  emitTransactionStatusUpdate(...);
  return result;
}
```

`getCreatorsTransaction` only verifies `creatorKey.userId === user.id` for the supplied `transactionId`: [3](#0-2) 

There is no subsequent assertion that the approver record's own `transactionId` field matches the URL parameter. The two IDs are never compared.

**Exploit path**

1. Attacker registers as a normal user and creates any transaction (e.g., `transactionId = 1`). This satisfies `getCreatorsTransaction`.
2. Attacker enumerates approver IDs (sequential integers) belonging to a victim transaction (e.g., approver `id = 42`, which belongs to `transactionId = 99`).
3. Attacker sends:
   ```
   DELETE /transactions/1/approvers/42
   ```
4. Controller passes the ownership check for transaction 1. Service deletes approver 42 (belonging to transaction 99) without complaint.

### Impact Explanation

Approvers represent the multi-signature approval gate that must be satisfied before a Hedera transaction can be executed. Removing approvers from a victim transaction:

- **Bypasses approval requirements**: if all approvers are stripped, the transaction may advance to `WAITING_FOR_EXECUTION` without any human approval, enabling unauthorized on-chain execution.
- **Disrupts organizational workflows**: silently removing approvers corrupts the governance model for any transaction in the system.
- **Permanent state corruption**: soft-deleted approvers are not automatically restored; recovery requires manual database intervention. [4](#0-3) 

### Likelihood Explanation

- **Attacker preconditions**: only a valid JWT (any registered organization user). Creating one transaction is sufficient to pass the ownership check.
- **Approver ID discovery**: IDs are sequential integers exposed in API responses to any user who is a participant in at least one transaction.
- **No rate limiting or anomaly detection** is visible in the codebase.
- The attack requires a single HTTP request per targeted approver.

### Recommendation

Add a cross-reference check in the controller (or service) that asserts the resolved approver's `transactionId` matches the URL `transactionId` before deletion:

```typescript
// In the controller, after getCreatorsTransaction:
const approver = await this.approversService.getTransactionApproverById(id);
if (!approver || approver.transactionId !== transactionId) {
  throw new UnauthorizedException('Approver does not belong to this transaction');
}
await this.approversService.removeTransactionApprover(id);
```

Alternatively, pass `transactionId` into `removeTransactionApprover` and enforce the membership check inside the service, keeping authorization logic co-located with the mutation.

### Proof of Concept

**Setup**
- User A creates transaction `T_A` (id=1) — attacker-controlled.
- User B creates transaction `T_B` (id=2) with approver record `id=5` (User C must approve).

**Attack**
```http
DELETE /transactions/1/approvers/5
Authorization: Bearer <User A JWT>
```

**Expected (correct) behavior**: 403 Unauthorized — approver 5 does not belong to transaction 1.

**Actual behavior**: 200 OK — approver 5 is soft-deleted from transaction 2. Transaction 2's approval requirement is silently removed. If User C was the sole approver, transaction 2 can now proceed to execution without any approval. [1](#0-0) [2](#0-1)

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
