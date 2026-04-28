The code confirms the vulnerability. Here is the audit report:

---

Audit Report

## Title
`removeTransactionApprover` Lacks Cross-Transaction Ownership Verification, Enabling IDOR to Delete Approvers from Arbitrary Transactions

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint authorizes the caller as the creator of `:transactionId`, but then passes the unrelated `:id` (approver ID) directly to `removeTransactionApprover()` in the service, which never verifies that the approver belongs to the authorized transaction. Any authenticated user who is the creator of at least one transaction can delete approvers from any other transaction by supplying their own `transactionId` for the authorization check and a victim's approver `id` for the deletion.

## Finding Description

**Root cause — controller authorization is decoupled from service action:**

In `approvers.controller.ts`, the `DELETE` handler authorizes the caller against `transactionId`, then immediately calls the service with the unrelated `id`:

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // ← authorizes transactionId
  await this.approversService.removeTransactionApprover(id);               // ← acts on id, no cross-check
  return true;
}
``` [1](#0-0) 

The service `removeTransactionApprover` accepts only the approver `id` and performs no check that the approver belongs to the transaction that was just authorized:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(...);
  return result;
}
``` [2](#0-1) 

**Contrast with `updateTransactionApprover`**, which correctly performs the cross-transaction check before acting:

```typescript
/* Verifies that the root transaction is the same as the param */
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

/* Verifies that the user is the creator of the transaction */
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
``` [3](#0-2) 

The fix was applied to `updateTransactionApprover` but was never applied to `removeTransactionApprover`, leaving the delete path unguarded.

## Impact Explanation
An attacker who is the creator of any transaction (even a trivial one they created themselves) can:
1. Enumerate or guess approver IDs belonging to other transactions (IDs are sequential integers).
2. Call `DELETE /transactions/{own_tx_id}/approvers/{victim_approver_id}`.
3. The authorization check passes (they own `own_tx_id`), and the victim's approver record is permanently soft-deleted.

This allows unauthorized removal of required approvers from any pending multi-signature transaction in the organization, bypassing the approval workflow entirely and potentially allowing transactions to proceed without the required approvals, or permanently disrupting the approval tree of critical transactions.

## Likelihood Explanation
- **Precondition**: The attacker must be an authenticated, verified organization user who has created at least one transaction. This is a normal user role with no elevated privileges.
- **Approver IDs** are sequential integers (auto-increment primary keys), making enumeration trivial.
- The attack requires a single crafted HTTP DELETE request with a mismatched `transactionId`/`id` pair.
- No rate limiting or anomaly detection is needed to bypass; the authorization logic itself is structurally broken.

## Recommendation
Apply the same cross-transaction ownership check that exists in `updateTransactionApprover` to the `removeTransactionApprover` service method. Specifically, after fetching the approver by `id`, resolve its root node and verify that `rootNode.transactionId === transactionId` before proceeding with deletion. The controller should pass `transactionId` to the service method, and the service should perform:

```typescript
async removeTransactionApprover(id: number, transactionId: number, user: User): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

  // Cross-transaction ownership check (mirrors updateTransactionApprover)
  if (rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

  await this.getCreatorsTransaction(rootNode.transactionId, user);

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

## Proof of Concept
1. Attacker (user A) creates their own transaction → `transactionId = 1`.
2. Victim (user B) creates a transaction with approvers → `transactionId = 99`, approver record `id = 42`.
3. Attacker sends:
   ```
   DELETE /transactions/1/approvers/42
   Authorization: Bearer <attacker_token>
   ```
4. `getCreatorsTransaction(1, userA)` passes — attacker owns transaction 1.
5. `removeTransactionApprover(42)` executes with no further checks — approver 42 (belonging to transaction 99) is soft-deleted.
6. Transaction 99's approval tree is now corrupted without user B's knowledge or consent.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L389-394)
```typescript
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
