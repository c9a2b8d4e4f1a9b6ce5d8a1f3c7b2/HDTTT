### Title
Any Transaction Creator Can Remove Approvers From Arbitrary Transactions Due to Missing Cross-Reference Check

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the calling user is the creator of the transaction identified by `:transactionId`, but then deletes the approver identified by `:id` without verifying that the approver actually belongs to `:transactionId`. This is a direct analog to the ERC20 `allowance[_from][_to]` bug: the authorization check is performed on the wrong entity. Any authenticated user who is the creator of at least one transaction can remove approvers from any other transaction in the system.

### Finding Description

**Root cause — wrong entity authorized:**

In `approvers.controller.ts`, the `DELETE /:id` handler performs two independent operations: [1](#0-0) 

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // ← checks user owns transactionId
  await this.approversService.removeTransactionApprover(id);               // ← deletes approver by id, no cross-check
  return true;
}
```

Step 1 verifies the caller is the creator of the transaction at `:transactionId`. Step 2 deletes the approver at `:id`. There is no check that the approver at `:id` belongs to `:transactionId`.

The service method `removeTransactionApprover` only checks existence, never ownership relative to the authorized transaction: [2](#0-1) 

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

`approver.transactionId` is never compared to the `transactionId` that was authorized. The notification even fires against `approver.transactionId` — the victim's transaction — confirming the operation targets the wrong transaction.

**Contrast with correct pattern elsewhere:**

The `createTransactionApprovers` path correctly gates on `getCreatorsTransaction` and then operates only within that transaction's scope. The `removeTransactionApprover` path breaks this invariant by decoupling the authorization scope from the operation scope. [3](#0-2) 

### Impact Explanation

An attacker who is the creator of any one transaction (Transaction A) can:

1. Enumerate approver IDs from any other transaction (Transaction B) via `GET /transactions/:B/approvers` — accessible to any verified user who has visibility of Transaction B.
2. Call `DELETE /transactions/:A/approvers/:approverB_id`.
3. The guard passes (attacker is creator of A); the service deletes the approver from Transaction B.

**Concrete consequences:**
- Required approvers are silently removed from victim transactions, allowing those transactions to proceed without the intended approval threshold — bypassing the multi-party authorization model entirely.
- An attacker can reduce a threshold-based approver tree to zero approvers, making a transaction auto-approvable or permanently broken.
- This is an unauthorized state change on another user's transaction with no audit trail pointing to the attacker's transaction.

### Likelihood Explanation

- **Attacker preconditions:** Must be an authenticated, verified organization user and the creator of at least one transaction. This is a normal user role with no elevated privileges.
- **Attack complexity:** Trivial — a single crafted HTTP DELETE request with a mismatched `:transactionId` and `:id`.
- **Discoverability:** Approver IDs are returned by the `GET /transactions/:id/approvers` endpoint, which is accessible to any user with transaction visibility. IDs are sequential integers, making enumeration straightforward even without direct visibility.
- **No rate limiting or anomaly detection** is described for this endpoint.

### Recommendation

In `approvers.controller.ts` (or `approvers.service.ts`), add a cross-reference check before deletion to confirm the target approver belongs to the authorized transaction:

```typescript
// In removeTransactionApprover or in the controller before calling it:
const approver = await this.approversService.getTransactionApproverById(id);
if (!approver || approver.transactionId !== transactionId) {
  throw new BadRequestException(ErrorCodes.ANF);
}
```

Alternatively, scope the approver lookup to the authorized transaction from the start:

```typescript
const approver = await this.getTransactionApproverById(id, transactionId); // add transactionId filter
```

This mirrors the correct pattern used in `getApproversByTransactionId`, which always scopes queries to a specific `transactionId`. [4](#0-3) 

### Proof of Concept

**Setup:**
- User Alice creates Transaction A (`id=10`) with approver Carol (`approver id=5`).
- User Bob creates Transaction B (`id=20`) with no approvers.
- Bob is a normal authenticated user.

**Attack:**
```http
DELETE /transactions/20/approvers/5
Authorization: Bearer <Bob's JWT>
```

**What happens:**
1. `getCreatorsTransaction(20, Bob)` → passes (Bob is creator of transaction 20).
2. `removeTransactionApprover(5)` → fetches approver id=5 (Carol on Alice's transaction 10), deletes it. No check that `approver.transactionId (10) === transactionId (20)`.

**Result:** Carol is removed as an approver from Alice's Transaction A. Alice's transaction now has no required approvers and may proceed without Carol's approval. Bob's Transaction B is unaffected. The authorization check was performed on the wrong transaction — a direct analog to `allowance[_from][_to]` being checked instead of `allowance[_from][msg.sender]`.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L84-108)
```typescript
  /* Get the full list of approvers by transactionId. This will return an array of approvers that may be trees */
  async getApproversByTransactionId(
    transactionId: number,
    userId?: number,
    entityManager?: EntityManager,
  ): Promise<TransactionApprover[]> {
    if (typeof transactionId !== 'number' || (userId && typeof userId !== 'number')) return null;

    return (entityManager || this.repo).query(
      `
      with recursive approverList as
        (
          select * from transaction_approver 
          where "transactionId" = $1
            union all
              select approver.* from transaction_approver as approver
              join approverList on approverList."id" = approver."listId"
        )
      select * from approverList
      where approverList."deletedAt" is null
        ${userId ? 'and approverList."userId" = $2' : ''}
      `,
      userId ? [transactionId, userId] : [transactionId],
    );
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-240)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);

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
