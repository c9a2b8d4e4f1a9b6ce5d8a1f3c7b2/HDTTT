All code references have been verified against the actual source. The vulnerability is confirmed.

---

Audit Report

## Title
Unauthorized Cross-Transaction Approver Deletion via Decoupled Authorization in `removeTransactionApprover`

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint authorizes the caller by verifying they are the creator of `:transactionId`, but then deletes the approver identified by `:id` without verifying that approver belongs to `:transactionId`. Any authenticated, verified user who has created at least one transaction can delete approvers from any other transaction in the system.

## Finding Description

**Root cause:** The authorization check and the deletion are decoupled with no cross-reference validation.

In `approvers.controller.ts`, the `removeTransactionApprover` handler at lines 103–113:

```typescript
async removeTransactionApprover(...) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // checks caller owns transactionId
  await this.approversService.removeTransactionApprover(id);               // deletes id — no ownership check
  return true;
}
``` [1](#0-0) 

The service method `removeTransactionApprover` (lines 534–544) only checks that the approver record exists, then immediately soft-deletes it via `removeNode`:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(..., [{ entityId: approver.transactionId }]);
  return result;
}
``` [2](#0-1) 

There is no check that `approver.transactionId === transactionId`. By contrast, `updateTransactionApprover` (lines 386–391) **does** perform this cross-reference before proceeding:

```typescript
const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
``` [3](#0-2) 

The delete path has no equivalent guard.

## Impact Explanation

An attacker with a single created transaction can delete approvers from **any** transaction in the system:

- Required approvers can be silently removed, allowing transactions to advance to execution without the intended multi-party sign-off.
- The `emitTransactionStatusUpdate` call after deletion (line 541) uses `approver.transactionId` — the victim transaction's ID — meaning a status recalculation is triggered on the victim transaction, potentially moving it to `WAITING_FOR_EXECUTION` prematurely if the deleted approver was the last pending one.
- Targeted disruption of specific transactions' approval chains. [4](#0-3) 

## Likelihood Explanation

- **Attacker precondition:** Must be a registered, verified user who has created at least one transaction — a normal product workflow requiring no privilege escalation.
- **Approver ID discovery:** `TransactionApprover` uses `@PrimaryGeneratedColumn()` (sequential integers), making IDs trivially enumerable or inferable from the attacker's own transactions. [5](#0-4) 

- No rate limiting or anomaly detection is evident on this endpoint.

## Recommendation

Apply the same cross-reference guard that `updateTransactionApprover` already uses. In `approvers.service.ts`, modify `removeTransactionApprover` to accept `transactionId` as a parameter and validate ownership before deletion:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Cross-reference: walk up to root and verify it belongs to transactionId
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);
  return result;
}
```

Update the controller call at line 109 to pass `transactionId`:

```typescript
await this.approversService.removeTransactionApprover(id, transactionId);
``` [6](#0-5) 

## Proof of Concept

1. Attacker registers as a normal user and creates **Transaction A** (attacker is now its creator).
2. Attacker observes approver IDs from their own transactions to infer the sequential range, or simply enumerates from 1.
3. Attacker identifies **approver ID `X`** belonging to **Transaction B** (owned by another user).
4. Attacker sends:
   ```
   DELETE /transactions/{A_id}/approvers/{X}
   Authorization: Bearer <attacker_jwt>
   ```
5. `getCreatorsTransaction(A_id, attacker)` passes — attacker is creator of A.
6. `removeTransactionApprover(X)` executes — fetches approver `X` (which belongs to Transaction B), calls `removeNode(X)`, soft-deletes it and its entire subtree.
7. `emitTransactionStatusUpdate` fires for Transaction B, potentially triggering a premature status transition.
8. Transaction B's approval chain is now corrupted without the owner of Transaction B being notified of any authorization failure. [2](#0-1)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L103-113)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L386-391)
```typescript
        const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
        if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

        /* Verifies that the root transaction is the same as the param */
        if (rootNode.transactionId !== transactionId)
          throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
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

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L21-22)
```typescript
  @PrimaryGeneratedColumn()
  id: number;
```
