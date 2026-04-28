### Title
Cross-Transaction Approver Deletion via Missing Ownership Binding in `removeTransactionApprover`

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint in `approvers.controller.ts` verifies the caller is the creator of `:transactionId`, but then deletes the approver record identified by `:id` without verifying that approver belongs to `:transactionId`. Any authenticated user who has created at least one transaction can delete approvers from any other transaction in the system by supplying their own `transactionId` and a victim's approver `id`.

### Finding Description

**Root cause — controller handler:** [1](#0-0) 

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user);  // ← checks ownership of transactionId
  await this.approversService.removeTransactionApprover(id);                // ← deletes approver by id, no transaction scope
  return true;
}
```

The authorization check `getCreatorsTransaction(transactionId, user)` only confirms the caller is the creator of the transaction identified by `transactionId`: [2](#0-1) 

After that check passes, `removeTransactionApprover(id)` is called with the raw approver `id` from the URL: [3](#0-2) 

The service fetches the approver by `id` and deletes it with no check that `approver.transactionId === transactionId`. The `transactionId` URL parameter is never used to scope the approver lookup.

**Exploit path:**
1. Attacker registers as a normal user and creates transaction `T_own` (becomes its creator).
2. Attacker enumerates approver IDs (sequential integers) to discover approver `X` belonging to victim transaction `T_victim`.
3. Attacker sends: `DELETE /transactions/T_own/approvers/X`
4. `getCreatorsTransaction(T_own, attacker)` passes — attacker owns `T_own`.
5. `removeTransactionApprover(X)` deletes approver `X` from `T_victim` with no further check.

### Impact Explanation
An attacker can silently remove any approver from any transaction in the organization. This directly disrupts the multi-signature approval workflow: a transaction that required N approvals can have its approvers stripped, potentially allowing it to proceed with fewer approvals than intended, or permanently breaking the approval tree for in-flight transactions. This is an unauthorized state mutation affecting the integrity of the transaction lifecycle.

### Likelihood Explanation
The attacker only needs to be an authenticated, verified user who has created at least one transaction — the lowest privilege level in the system. Approver IDs are auto-incremented integers, making enumeration trivial with a simple sequential scan. No admin access, leaked credentials, or privileged role is required.

### Recommendation
After `getCreatorsTransaction` passes, verify that the approver being deleted actually belongs to the authorized transaction before deleting it:

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user);

  const approver = await this.approversService.getTransactionApproverById(id);
  if (!approver || approver.transactionId !== transactionId) {
    throw new BadRequestException('Approver does not belong to this transaction');
  }

  await this.approversService.removeTransactionApprover(id);
  return true;
}
```

Alternatively, scope the approver lookup inside `removeTransactionApprover` to accept and enforce `transactionId`.

### Proof of Concept

**Preconditions:**
- Two normal authenticated users: `attacker` and `victim`.
- `victim` creates transaction `T_victim` (id = 5) and adds approver user `U` → approver record created with id = 12.
- `attacker` creates any transaction `T_own` (id = 7).

**Request:**
```
DELETE /transactions/7/approvers/12
Authorization: Bearer <attacker_jwt>
```

**Expected (broken) behavior:**
- `getCreatorsTransaction(7, attacker)` → passes (attacker owns transaction 7).
- `removeTransactionApprover(12)` → deletes approver 12 from transaction 5 (victim's transaction).
- Response: `200 true`

**Expected (correct) behavior:**
- After ownership check, verify `approver(12).transactionId === 7` → fails → `400 Bad Request`.

The approver record for `T_victim` is permanently deleted, breaking its approval workflow, with no action required from the victim and no admin privilege required from the attacker.

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
