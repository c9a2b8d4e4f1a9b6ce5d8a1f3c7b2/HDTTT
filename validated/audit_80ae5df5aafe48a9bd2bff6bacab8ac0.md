The controller code at line 108 **does** call `getCreatorsTransaction(transactionId, user)` before deleting — so the claim that there is *no* ownership check is inaccurate. However, a real vulnerability exists: the ownership check is against the URL's `transactionId`, but `removeTransactionApprover(id)` never verifies that the approver `id` actually belongs to that `transactionId`. An attacker who owns *any* transaction can delete approvers from *any other* transaction.

---

Audit Report

## Title
Cross-Transaction Approver Deletion via Missing Approver-to-Transaction Binding Check

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the caller owns the transaction identified by `:transactionId` in the URL, but never checks that the approver identified by `:id` actually belongs to that same transaction. An authenticated user who owns any transaction can delete approvers belonging to transactions they do not own by supplying their own `transactionId` in the URL path alongside a victim's approver `id`.

## Finding Description

**Controller-level ownership check is scoped to the wrong resource.**

In `approvers.controller.ts`, the `removeTransactionApprover` handler calls `getCreatorsTransaction(transactionId, user)` to verify the caller owns the transaction in the URL, then immediately calls `removeTransactionApprover(id)` with no further binding: [1](#0-0) 

The service method `removeTransactionApprover` fetches the approver by `id` and deletes it with no check that `approver.transactionId` matches the `transactionId` the caller was verified against: [2](#0-1) 

**Contrast with `updateTransactionApprover`, which correctly cross-references the approver's root transaction against the URL parameter and the caller's identity:** [3](#0-2) 

`updateTransactionApprover` retrieves the root node from the approver, then verifies `rootNode.transactionId === transactionId` and that the caller is the creator of *that* transaction. `removeTransactionApprover` performs neither step.

## Impact Explanation

An attacker who owns any transaction can delete approvers from any other transaction in the system:
- Removes required signers from multi-signature workflows, potentially reducing the approval threshold below the creator's intended security level.
- Can allow a transaction to advance to `WAITING_FOR_EXECUTION` with fewer approvals than required.
- Permanently corrupts the approval audit trail.
- In an organizational context (Hedera Council use case), this could allow an attacker to unilaterally strip approval requirements from high-value network transactions.

## Likelihood Explanation

- Precondition: attacker needs only a valid, verified account and ownership of *any* transaction (even a self-created throwaway).
- Approver IDs are sequential integers, enumerable via `GET /transactions/:id/approvers` for any transaction the attacker can view.
- The attack is a single authenticated HTTP `DELETE` request.
- No rate limiting or anomaly detection is described for this endpoint.

## Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver being deleted belongs to the transaction the caller was authorized against. The same pattern used in `updateTransactionApprover` should be applied:

1. Fetch the root node of the approver via `getRootNodeFromNode(approver.id)`.
2. Assert `rootNode.transactionId === transactionId` (the URL parameter).
3. Assert the caller is the creator of that transaction via `getCreatorsTransaction(rootNode.transactionId, user)`.

This mirrors the existing guard in `updateTransactionApprover`: [3](#0-2) 

## Proof of Concept

1. Attacker registers and verifies account A. Creates transaction `T_attacker` (attacker is creator).
2. Victim creates transaction `T_victim` with approver record `X` (approver ID, e.g., `42`).
3. Attacker discovers approver ID `42` (via enumeration or the `GET /transactions/T_victim/approvers` endpoint if accessible).
4. Attacker sends:
   ```
   DELETE /transactions/{T_attacker}/approvers/42
   Authorization: Bearer <attacker_jwt>
   ```
5. Controller calls `getCreatorsTransaction(T_attacker, attacker)` → passes (attacker owns `T_attacker`).
6. Controller calls `removeTransactionApprover(42)` → fetches approver `42` (which belongs to `T_victim`) and soft-deletes it with no further check.
7. Approver `42` is deleted from `T_victim`'s approval workflow. The attacker never needed any relationship to `T_victim`. [1](#0-0) [2](#0-1)

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
