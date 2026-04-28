### Title
Any Authenticated Transaction Creator Can Delete Approvers Belonging to Other Users' Transactions

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint in the approvers controller verifies that the requesting user is the creator of `:transactionId`, but then calls `removeTransactionApprover(id)` which deletes the approver row by its own primary key `id` without verifying that the approver actually belongs to the authorized `:transactionId`. Any authenticated user who is the creator of at least one transaction can therefore delete approvers from any other transaction in the system.

### Finding Description

**Root cause — missing cross-ownership check in the delete path.**

The controller handler: [1](#0-0) 

performs two independent steps:
1. `getCreatorsTransaction(transactionId, user)` — confirms the caller owns `:transactionId`.
2. `removeTransactionApprover(id)` — deletes the approver row identified by `:id`.

The service method that executes the deletion: [2](#0-1) 

accepts only the approver's primary key and never checks whether that approver's `transactionId` matches the `:transactionId` that was authorized. There is no binding between the two parameters.

**Contrast with the update path**, which correctly validates ownership before mutating: [3](#0-2) 

The update path explicitly asserts `rootNode.transactionId !== transactionId` and then re-runs `getCreatorsTransaction` against the approver's actual transaction. The delete path has no equivalent guard.

**Exploit flow:**
1. Attacker (User A) creates Transaction 1 — they become its creator.
2. Victim (User B) creates Transaction 2 and adds approvers (approver IDs are sequential integers, easily enumerable).
3. Attacker sends:
   ```
   DELETE /transactions/1/approvers/<victim_approver_id>
   ```
4. `getCreatorsTransaction(1, userA)` succeeds — User A owns Transaction 1.
5. `removeTransactionApprover(<victim_approver_id>)` soft-deletes the approver from Transaction 2 with no further check.

### Impact Explanation
An attacker can silently remove all approvers from any transaction they do not own. This directly mirrors the Augur `clearCrowdsourcers` bug: the approval workflow — which is the primary authorization gate before a transaction is executed on the Hedera network — can be gutted by any authenticated user. A transaction that required multi-party approval can be reduced to zero approvers, potentially allowing it to proceed to execution without the intended oversight. This is an unauthorized state mutation with direct impact on transaction integrity and multi-signature security guarantees.

### Likelihood Explanation
The precondition is minimal: the attacker only needs a valid JWT (i.e., a registered, verified account) and must have created at least one transaction (trivially achievable). Approver IDs are sequential database integers, making enumeration straightforward. No privileged role is required. The endpoint is a standard REST `DELETE` call with no rate-limiting specific to this operation.

### Recommendation
Pass `transactionId` into `removeTransactionApprover` and assert that the resolved approver's root transaction matches before deletion, mirroring the pattern already used in `updateTransactionApprover`:

```typescript
// approvers.service.ts — removeTransactionApprover
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Verify the approver belongs to the authorized transaction
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to this transaction');

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

Update the controller to pass `transactionId` to the service call accordingly.

### Proof of Concept

**Setup:**
- User A registers and creates Transaction 1 (ID = 1). Obtains JWT `tokenA`.
- User B registers and creates Transaction 2 (ID = 2) with an approver (approver ID = 5).

**Attack request (sent by User A):**
```http
DELETE /transactions/1/approvers/5
Authorization: Bearer <tokenA>
```

**Expected (correct) behavior:** `403 Unauthorized` — approver 5 does not belong to Transaction 1.

**Actual behavior:** `200 OK` — approver 5 is soft-deleted from Transaction 2.

**Verification:** Query `transaction_approver` where `id = 5`; `deletedAt` is now set. Transaction 2's approval workflow is broken. [4](#0-3) [2](#0-1)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L93-113)
```typescript
  /* Remove transaction approver or a tree by id of the root approver */
  @ApiOperation({
    summary: 'Removes transaction approver',
    description: 'Removes transaction approver by id.',
  })
  @ApiResponse({
    status: 200,
    type: Boolean,
  })
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L534-544)
```typescript
  async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);

    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const result = await this.removeNode(approver.id);

    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);

    return result;
  }
```
