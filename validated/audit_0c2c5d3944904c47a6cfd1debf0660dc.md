### Title
IDOR in `removeTransactionApprover`: Any Transaction Creator Can Delete Approvers Belonging to Other Transactions

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller is the creator of `:transactionId`, but then passes the unrelated `:id` parameter directly to `removeTransactionApprover()` without confirming that the targeted approver actually belongs to that transaction. Any authenticated user who owns at least one transaction can exploit this to soft-delete approvers from any other transaction in the system, disrupting or permanently blocking its approval workflow.

### Finding Description
**Root cause:** The authorization check and the destructive action operate on two different, unlinked objects.

In `approvers.controller.ts` lines 102–113:

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

`getCreatorsTransaction` only confirms the caller created the transaction identified by `:transactionId`. It says nothing about `:id`.

`removeTransactionApprover` in `approvers.service.ts` lines 533–544 then fetches the approver by `:id` alone and soft-deletes it with no ownership verification:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  ...
}
``` [2](#0-1) 

**Contrast with `updateTransactionApprover`**, which correctly validates the cross-reference at lines 389–391:

```typescript
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
``` [3](#0-2) 

The delete path is missing this exact guard.

**Exploit flow:**
1. Attacker registers and creates Transaction A (`transactionId = 1`) — they are its creator.
2. Attacker enumerates or guesses an approver ID (`id = 99`) that belongs to Transaction B (`transactionId = 2`), owned by a different user.
3. Attacker sends: `DELETE /transactions/1/approvers/99`
4. `getCreatorsTransaction(1, attacker)` passes — attacker owns Transaction 1.
5. `removeTransactionApprover(99)` executes — approver 99 (belonging to Transaction 2) is soft-deleted with no further check.
6. Transaction B's approval tree is now corrupted or incomplete.

### Impact Explanation
An attacker can silently remove any approver from any transaction they do not own. Depending on the approval tree structure, this can:
- Reduce the threshold quorum below the intended level, allowing a transaction to execute with fewer approvals than required.
- Completely remove all approvers from a transaction, making it impossible to satisfy the approval condition and permanently blocking execution.
- Disrupt multi-signature governance workflows for the entire organization.

This is a permanent state corruption — soft-deleted approvers are not automatically restored.

### Likelihood Explanation
The attacker only needs to be a normal authenticated user who has created at least one transaction (a standard product action). Approver IDs are sequential integers, making enumeration trivial. No admin privileges, leaked secrets, or internal access are required. The endpoint is a standard REST `DELETE` call.

### Recommendation
Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver being deleted actually belongs to the `transactionId` supplied in the URL — exactly as `updateTransactionApprover` does:

```typescript
// In removeTransactionApprover or the controller:
const rootNode = await this.getRootNodeFromNode(approver.id, entityManager);
if (!rootNode || rootNode.transactionId !== transactionId) {
  throw new UnauthorizedException('Approver does not belong to this transaction');
}
```

Alternatively, scope the database lookup itself to the given `transactionId` so a mismatched approver simply returns "not found."

### Proof of Concept

**Preconditions:**
- Two organization users: `alice` (creator of Transaction 1) and `bob` (creator of Transaction 2 with approver id=99).
- Both are normal authenticated users.

**Steps:**
```
# 1. Alice creates Transaction 1 (she becomes its creator)
POST /transactions  →  { id: 1 }

# 2. Alice discovers approver id=99 on Transaction 2
#    (sequential IDs make this trivial to enumerate)
GET /transactions/2/approvers  →  [{ id: 99, userId: ... }]

# 3. Alice sends a delete using her own transactionId but Bob's approver id
DELETE /transactions/1/approvers/99
Authorization: Bearer <alice_token>

# Expected: 403 Unauthorized
# Actual:   200 true  — approver 99 is soft-deleted from Transaction 2
```

**Outcome:** Bob's Transaction 2 approval tree is permanently mutated by Alice, who has no ownership over it.

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
