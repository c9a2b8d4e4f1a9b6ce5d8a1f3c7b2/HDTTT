The code confirms the vulnerability. Here is the audit report:

---

Audit Report

## Title
Cross-Transaction Approver Removal via Authorization Check Mismatch in `removeTransactionApprover`

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint authorizes the request by verifying the caller is the creator of `:transactionId`, but then deletes the approver identified by `:id` without verifying that approver belongs to `:transactionId`. Any authenticated user who owns at least one transaction can remove approvers from any other transaction in the system.

## Finding Description

**Root Cause:**

In `approvers.controller.ts`, the `removeTransactionApprover` handler performs two independent, uncorrelated operations:

```typescript
await this.approversService.getCreatorsTransaction(transactionId, user); // checks ownership of transactionId
await this.approversService.removeTransactionApprover(id);               // deletes approver by id — no cross-check
``` [1](#0-0) 

The service-level `removeTransactionApprover` fetches the approver by `id` and deletes it unconditionally, with no check that `approver.transactionId` matches the URL-supplied `transactionId`: [2](#0-1) 

**Contrast with the update path**, which correctly validates ownership before proceeding by fetching the root node and asserting `rootNode.transactionId === transactionId`: [3](#0-2) 

The delete path is entirely missing this guard.

## Impact Explanation
- An attacker can silently remove approvers from any transaction they do not own, undermining the multi-signature approval workflow.
- Approval thresholds can be reduced or eliminated on victim transactions, allowing them to proceed without required organizational sign-off.
- Removing all approvers from a transaction that requires approval can permanently block it from reaching `WAITING_FOR_EXECUTION` status, causing a denial-of-service on that transaction's lifecycle.
- The attacker's own transaction is unaffected; the damage is recorded only on the victim's transaction.

## Likelihood Explanation
- **Preconditions**: The attacker only needs a valid, verified account and must have created at least one transaction — both are normal user actions.
- **Approver ID discovery**: Approver IDs are sequential auto-increment integers, trivially enumerable by brute-force or by observing IDs from any transaction the attacker legitimately participates in.
- **No privileged access required**: Fully exploitable by a normal authenticated user with no admin or operator role.

## Recommendation
In the `removeTransactionApprover` controller handler, after fetching the approver (or inside the service), assert that the approver's root transaction matches the URL-supplied `transactionId` before deletion — mirroring the guard already present in `updateTransactionApprover`:

```typescript
// After getCreatorsTransaction passes:
const approver = await this.approversService.getTransactionApproverById(id);
const rootNode = await this.approversService.getRootNodeFromNode(approver.id);
if (rootNode.transactionId !== transactionId) {
  throw new UnauthorizedException('Approver does not belong to this transaction');
}
await this.approversService.removeTransactionApprover(id);
```

Alternatively, refactor `removeTransactionApprover` in the service to accept and enforce `transactionId`, consistent with how `updateTransactionApprover` is structured.

## Proof of Concept

1. Attacker registers as a verified user and creates **Transaction A** (attacker is its creator; attacker's `transactionId = A`).
2. Victim has **Transaction B** with approver records (approver IDs are sequential integers).
3. Attacker sends:
   ```
   DELETE /transactions/{A_id}/approvers/{victim_approver_id}
   ```
4. `getCreatorsTransaction(A_id, attacker)` passes — attacker is creator of A.
5. `removeTransactionApprover(victim_approver_id)` executes — fetches the approver by `victim_approver_id`, finds it exists (belonging to Transaction B), and deletes it with no ownership check.
6. Transaction B's approver is silently removed. The attacker's Transaction A is untouched. [4](#0-3)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L385-394)
```typescript
        /* Gets the root approver */
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
