### Title
Transaction Creator Can Remove Approvers From Any Transaction via Missing Cross-Transaction Authorization Check

### Summary

The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the requesting user is the creator of `:transactionId`, but then removes the approver identified by `:id` without checking that the approver actually belongs to `:transactionId`. Any authenticated user who has created at least one transaction can remove approvers from any other transaction in the system, permanently disrupting the approval workflow of transactions they do not own.

### Finding Description

**Root cause — authorization check is on the wrong object:**

In `approvers.controller.ts`, the `removeTransactionApprover` handler first calls `getCreatorsTransaction(transactionId, user)` to confirm the caller is the creator of the transaction identified by the URL parameter `:transactionId`. It then immediately calls `removeTransactionApprover(id)` where `id` is the approver's primary key — with no check that this approver belongs to `:transactionId`. [1](#0-0) 

Inside the service, `removeTransactionApprover` fetches the approver by its own primary key and deletes it unconditionally: [2](#0-1) 

`getCreatorsTransaction` only validates ownership of the URL-supplied `transactionId`, not of the approver being deleted: [3](#0-2) 

**Exploit path:**

1. Attacker registers an account and creates any dummy transaction (e.g., a zero-value transfer). This makes them the "creator" of transaction ID `N`.
2. Attacker enumerates approver IDs (sequential integers) belonging to a victim's transaction `M` (which the attacker did not create).
3. Attacker sends:
   ```
   DELETE /transactions/N/approvers/<victim_approver_id>
   ```
4. The controller confirms the attacker is the creator of transaction `N` ✓, then deletes the approver from transaction `M` ✗.
5. The victim's transaction loses its approver(s). If the transaction was in `WAITING_FOR_EXECUTION` (all approvals obtained), the status recalculation triggered by `emitTransactionStatusUpdate` reverts it to `WAITING_FOR_SIGNATURES`. The deleted approver must be re-added and re-approve — but the attacker can repeat the deletion indefinitely.

**Secondary issue — null `transactionId` on child approvers:**

For child approvers (those with `listId` set), `approver.transactionId` is `null`. When such an approver is deleted, `emitTransactionStatusUpdate` is called with `entityId: null`, meaning the victim's transaction status is never recalculated at all, leaving the transaction in a permanently inconsistent state. [4](#0-3) 

### Impact Explanation

- **Permanent DoS on any transaction's approval workflow.** An attacker can repeatedly delete approvers from any transaction they do not own, preventing it from ever reaching `WAITING_FOR_EXECUTION` and being submitted to the Hedera network.
- **Unauthorized state mutation across trust boundaries.** The attacker modifies data belonging to a transaction they have no ownership over.
- **Organizational workflow disruption.** In multi-party organizational use cases, critical transactions (e.g., treasury transfers, account updates) can be indefinitely blocked by any authenticated user.

### Likelihood Explanation

- **Precondition:** The attacker only needs a valid authenticated session and must have created at least one transaction (trivially achievable by any registered user).
- **No privileged access required.** The attack uses only standard API endpoints available to all users.
- **Approver IDs are sequential integers**, making enumeration straightforward with a simple loop.
- **No rate limiting** is visible on this endpoint, so the attack can be automated.

### Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver being deleted actually belongs to the `transactionId` supplied in the URL. For example, after fetching the approver, resolve its root transaction via `getRootNodeFromNode` and assert `rootNode.transactionId === transactionId`. Reject the request if they do not match.

Additionally, for child approvers, `emitTransactionStatusUpdate` should use the root transaction's ID, not `approver.transactionId` (which is `null` for non-root nodes).

### Proof of Concept

```
# Step 1: Attacker creates a dummy transaction → receives transactionId = 99
POST /transactions  { ... }

# Step 2: Attacker discovers approver IDs on victim's transaction (id=42)
# by observing sequential IDs or via any information leak.

# Step 3: Attacker deletes victim's approver using their own transactionId as the URL param
DELETE /transactions/99/approvers/42
Authorization: Bearer <attacker_token>

# Result: HTTP 200 true
# Victim's approver (id=42) is deleted from transaction 42.
# Victim's transaction reverts from WAITING_FOR_EXECUTION → WAITING_FOR_SIGNATURES.
# Attacker repeats step 3 each time the victim re-adds the approver.
``` [1](#0-0) [2](#0-1)

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
