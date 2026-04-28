### Title
Cross-Transaction Authorization Bypass in `removeTransactionApprover` Allows Any Creator to Delete Approvers from Arbitrary Transactions

### Summary

The `DELETE /transactions/:transactionId/approvers/:id` endpoint in `ApproversController` verifies that the caller is the creator of the transaction identified by `:transactionId` in the URL, but then deletes the approver identified by `:id` without verifying that the approver actually belongs to that transaction. Any authenticated user who is the creator of at least one transaction can delete approvers from any other transaction in the system by supplying their own `transactionId` for the ownership check and a victim's `approver id` for the deletion.

### Finding Description

**Root cause — controller-level TOCTOU on ownership scope:**

In `approvers.controller.ts` lines 102–113, the `removeTransactionApprover` handler performs two independent operations:

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // ← checks ownership of transactionId
  await this.approversService.removeTransactionApprover(id);               // ← deletes approver by id, no cross-check
  return true;
}
``` [1](#0-0) 

`getCreatorsTransaction` only verifies the caller owns the transaction at `:transactionId`: [2](#0-1) 

`removeTransactionApprover` then deletes the approver by raw `id` with no check that it belongs to the verified transaction: [3](#0-2) 

`getTransactionApproverById` fetches any approver by primary key, with no transaction-scoping: [4](#0-3) 

**Contrast with `updateTransactionApprover`**, which correctly validates the cross-transaction boundary before acting:

```typescript
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
``` [5](#0-4) 

The delete path is missing this exact guard.

**Exploit flow:**

1. Attacker (Eve) registers an account and creates Transaction A — she is its creator.
2. Victim (Bob) creates Transaction B with a required approver set (approver record IDs are sequential integers, discoverable by probing the `GET /transactions/:id/approvers` endpoint on any transaction Eve has access to, or by brute-force enumeration since IDs are integers).
3. Eve sends:
   ```
   DELETE /transactions/{transactionA_id}/approvers/{approverB_id}
   Authorization: Bearer <eve_token>
   ```
4. `getCreatorsTransaction(transactionA_id, eve)` passes — Eve is the creator of Transaction A.
5. `removeTransactionApprover(approverB_id)` executes — soft-deletes Bob's approver (and its entire subtree via `removeNode`) with no ownership check.
6. Bob's transaction now has fewer approvers than required, potentially allowing it to proceed without the intended multi-party approval.

### Impact Explanation

An attacker with a valid authenticated session (any verified user who has created at least one transaction) can permanently delete approvers from any other user's transaction. This:

- Breaks the multi-signature approval workflow — required approvers are silently removed, allowing transactions to execute without the intended authorization threshold.
- Constitutes unauthorized state mutation on another user's data.
- Is irreversible (soft-delete; the approver record is marked `deletedAt` and excluded from all future queries).

Severity: **High** — direct integrity failure in the core approval/authorization model of the system.

### Likelihood Explanation

- Precondition: attacker must be a registered, verified user with at least one transaction of their own. This is a normal user role — no privilege escalation required.
- Approver IDs are sequential integers. An attacker can enumerate them by observing IDs returned from their own transactions or from any transaction they have read access to.
- The attack requires a single authenticated HTTP DELETE request. No special tooling, timing, or cryptographic capability is needed.
- Likelihood: **High**.

### Recommendation

Inside `removeTransactionApprover` (service), after fetching the approver, verify that its root transaction matches the `transactionId` supplied by the caller — exactly as `updateTransactionApprover` already does:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Cross-check: ensure the approver belongs to the transaction the caller owns
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Root transaction is not the same');

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

Pass `transactionId` from the controller into the service call, mirroring the pattern already used in `updateTransactionApprover`.

### Proof of Concept

**Setup:**
- Eve: authenticated user, creator of Transaction A (`transactionId = 1`), which has no approvers.
- Bob: authenticated user, creator of Transaction B (`transactionId = 2`), which has approver record with `id = 5` (userId = Carol).

**Attack request (Eve):**
```http
DELETE /transactions/1/approvers/5
Authorization: Bearer <eve_jwt>
```

**Server execution trace:**
1. `getCreatorsTransaction(1, eve)` → Transaction 1 found, `creatorKey.userId === eve.id` ✓ — passes.
2. `removeTransactionApprover(5)` → fetches approver id=5 (belongs to Transaction 2), calls `removeNode(5)` → soft-deletes approver id=5 and all its children.

**Expected (correct) outcome:** 401 Unauthorized — approver does not belong to the caller's transaction.

**Actual outcome:** 200 OK — Carol is silently removed as a required approver from Bob's Transaction B. Bob's transaction can now proceed without Carol's signature.

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
