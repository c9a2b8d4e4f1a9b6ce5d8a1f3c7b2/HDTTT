### Title
IDOR in `removeTransactionApprover`: Transaction Creator Can Delete Approvers Belonging to Any Other Transaction

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the requesting user is the creator of `:transactionId`, but then passes the approver `:id` directly to `removeTransactionApprover()` without verifying that the approver actually belongs to `:transactionId`. Any authenticated user who is the creator of at least one transaction can delete approvers from any other transaction in the system by supplying their own `transactionId` for the authorization check and a victim approver's `id` as the target.

### Finding Description

**Root cause — decoupled authorization and operation:**

In `approvers.controller.ts`, the `DELETE /:id` handler performs two independent calls:

```typescript
// back-end/apps/api/src/transactions/approvers/approvers.controller.ts  lines 102-113
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // ← checks user owns transactionId
  await this.approversService.removeTransactionApprover(id);               // ← deletes approver by id, no ownership check
  return true;
}
``` [1](#0-0) 

The service method `removeTransactionApprover` accepts only the approver `id` and performs no cross-check against the transaction:

```typescript
// back-end/apps/api/src/transactions/approvers/approvers.service.ts  lines 533-544
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);   // deletes whatever approver has this id
  emitTransactionStatusUpdate(...);
  return result;
}
``` [2](#0-1) 

**Contrast with `updateTransactionApprover`**, which correctly validates ownership:

```typescript
// back-end/apps/api/src/transactions/approvers/approvers.service.ts  lines 386-394
const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);
if (rootNode.transactionId !== transactionId)          // ← cross-check present here
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
``` [3](#0-2) 

The delete path is missing this exact cross-check, creating an IDOR.

**Exploit flow:**
1. Attacker (Alice) creates Transaction A — she is its creator.
2. Victim (Bob) creates Transaction B with a multi-approver workflow. Alice is listed as one of the approvers of Transaction B (a normal, unprivileged role).
3. Alice calls `GET /transactions/{B_id}/approvers` — `getVerifiedApproversByTransactionId` allows this because she is an approver of B, returning all approver records including their integer IDs.
4. Alice sends: `DELETE /transactions/{A_id}/approvers/{victim_approver_id}` where `victim_approver_id` belongs to Transaction B.
5. Server checks: is Alice the creator of Transaction A? Yes → passes.
6. Server calls `removeTransactionApprover(victim_approver_id)` — fetches the approver (which belongs to B), soft-deletes it and its entire subtree. No transaction ownership check occurs.
7. The approval requirement for Transaction B is silently removed or corrupted.

### Impact Explanation

An attacker can unilaterally delete any approver node (including entire approval subtrees) from any transaction they are not the creator of. This directly undermines the multi-signature approval workflow: required approvals can be removed, reducing or eliminating the threshold of signatures needed before a transaction is executed on the Hedera network. This constitutes unauthorized state mutation of another user's transaction governance structure and can lead to transactions being executed without the intended number of approvals.

### Likelihood Explanation

The attacker preconditions are minimal: the attacker must be an authenticated, verified user and the creator of at least one transaction (a normal product flow). Being listed as an approver on the victim transaction (also a normal flow) provides the approver IDs needed. Sequential integer IDs also make brute-force enumeration feasible even without that relationship. No privileged access, leaked credentials, or admin keys are required.

### Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver being deleted actually belongs to the `transactionId` supplied in the URL. Mirror the pattern already used in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Cross-check: walk to root and confirm it belongs to the expected transaction
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

Pass `transactionId` from the controller into the service call, exactly as `updateTransactionApprover` already does.

### Proof of Concept

**Setup:**
- Alice creates Transaction A (she is creator). `transactionId = 10`.
- Bob creates Transaction B with a 2-of-3 approver tree. `transactionId = 20`. Alice is one of the three approvers (approver record `id = 55`).

**Step 1 — Alice discovers approver IDs for Transaction B:**
```
GET /transactions/20/approvers
Authorization: Bearer <alice_jwt>
→ 200 OK: [{id: 53, ...}, {id: 54, ...}, {id: 55, userId: alice_id, ...}]
```
Alice is an approver, so `getVerifiedApproversByTransactionId` returns all approvers including IDs 53 and 54 (belonging to other users).

**Step 2 — Alice deletes a victim approver using her own transaction as the auth anchor:**
```
DELETE /transactions/10/approvers/53
Authorization: Bearer <alice_jwt>
→ 200 OK: true
```

**Result:** Approver record 53 (belonging to Transaction B) is soft-deleted. Bob's 2-of-3 approval requirement is now 1-of-2, or the entire approval subtree is removed, allowing Transaction B to proceed with fewer approvals than Bob intended.

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
