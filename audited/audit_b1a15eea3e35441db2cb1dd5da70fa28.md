### Title
Unauthorized Cross-Transaction Approver Deletion via Decoupled Authorization in `removeTransactionApprover`

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint in the backend API authorizes the caller by verifying they are the creator of `:transactionId`, but then deletes the approver identified by `:id` without verifying that approver actually belongs to `:transactionId`. Any authenticated user who has created at least one transaction can delete approvers from any other transaction in the system, bypassing the ownership model entirely.

### Finding Description

**Root cause:** The controller's authorization check and the service's deletion are decoupled with no cross-reference validation.

In `approvers.controller.ts`, the `removeTransactionApprover` handler:

1. Calls `getCreatorsTransaction(transactionId, user)` — verifies the caller is the creator of `transactionId`.
2. Calls `removeTransactionApprover(id)` — deletes the approver with `id`, with no check that `id` belongs to `transactionId`. [1](#0-0) 

The service method `removeTransactionApprover` only checks that the approver record exists, then immediately soft-deletes it: [2](#0-1) 

There is no check that `approver.transactionId === transactionId` (or that the approver's root node belongs to the authorized transaction). Compare this to `updateTransactionApprover`, which **does** perform this cross-reference: [3](#0-2) 

The `updateTransactionApprover` path explicitly validates `rootNode.transactionId !== transactionId` before proceeding. The delete path has no equivalent guard.

**Exploit flow:**
1. Attacker registers as a normal user and creates Transaction A (attacker is now its creator).
2. Attacker enumerates or guesses approver IDs belonging to Transaction B (owned by another user). Approver IDs are sequential integers.
3. Attacker sends: `DELETE /transactions/{A_id}/approvers/{B_approver_id}`
4. `getCreatorsTransaction(A_id, attacker)` passes — attacker is creator of A.
5. `removeTransactionApprover(B_approver_id)` executes — deletes the approver from Transaction B without any ownership check.

### Impact Explanation

An attacker with a single created transaction can delete approvers from **any** transaction in the system. This breaks the approval workflow integrity:
- Required approvers can be silently removed, allowing transactions to advance to execution without the intended multi-party sign-off.
- The `emitTransactionStatusUpdate` call after deletion may trigger a status recalculation that moves a transaction to `WAITING_FOR_EXECUTION` prematurely if the deleted approver was the last pending one.
- Targeted DoS of specific transactions' approval chains. [4](#0-3) 

### Likelihood Explanation

- **Attacker precondition:** Must be a registered, verified user who has created at least one transaction. This is a normal product workflow — no privilege escalation required.
- **Approver ID discovery:** `TransactionApprover` IDs are sequential integers (`@PrimaryGeneratedColumn()`). An attacker can enumerate them trivially or observe IDs from their own transactions to infer the range.
- **No rate limiting or anomaly detection** is evident on this endpoint. [5](#0-4) 

### Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver's root transaction matches the authorized `transactionId`. Mirror the guard already present in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Cross-reference: ensure the approver belongs to the authorized transaction
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to this transaction');

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

Pass `transactionId` from the controller into the service call, consistent with how `updateTransactionApprover` already receives it. [3](#0-2) 

### Proof of Concept

**Setup:**
- User A creates Transaction 1 (id=1). No approvers needed.
- User B creates Transaction 2 (id=2) and adds User C as an approver (approver record id=7).

**Attack:**
```http
DELETE /transactions/1/approvers/7
Authorization: Bearer <User_A_JWT>
```

**Expected (correct) behavior:** 403/401 — approver 7 does not belong to transaction 1.

**Actual behavior:** 200 — approver 7 is soft-deleted from Transaction 2. User C is silently removed from the approval chain of a transaction they never interacted with. If approver 7 was the sole pending approver, `emitTransactionStatusUpdate` fires and may advance Transaction 2's status. [1](#0-0) [2](#0-1)

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

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L20-22)
```typescript
export class TransactionApprover {
  @PrimaryGeneratedColumn()
  id: number;
```
