After thorough investigation of the codebase, I found a valid analog vulnerability.

---

### Title
Cross-Transaction Approver Removal via Authorization Check Mismatch in `removeTransactionApprover`

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint authorizes the request by verifying the caller is the creator of `:transactionId`, but then deletes the approver identified by `:id` without verifying that approver belongs to `:transactionId`. Any authenticated user who owns at least one transaction can remove approvers from any other transaction in the system by supplying their own `transactionId` for the authorization check and a victim's approver `id` for the deletion target.

### Finding Description

**Root Cause:**

In `approvers.controller.ts`, the `removeTransactionApprover` handler performs two independent operations:

1. `getCreatorsTransaction(transactionId, user)` — verifies the caller is the creator of the URL-supplied `transactionId`
2. `removeTransactionApprover(id)` — deletes the approver row identified by the URL-supplied `id`

There is no cross-reference check confirming that approver `id` belongs to `transactionId`. [1](#0-0) 

The service-level `removeTransactionApprover` function also performs no ownership check — it fetches the approver by `id` and deletes it unconditionally: [2](#0-1) 

**Contrast with the update path**, which correctly validates that the approver's root transaction matches the URL parameter before proceeding: [3](#0-2) 

The delete path is missing this exact guard.

**Exploit Flow:**

1. Attacker registers as a verified user and creates Transaction A (attacker is its creator).
2. Victim has Transaction B with approver records (approver IDs are sequential integers, discoverable by brute-force or via any endpoint the attacker has legitimate access to).
3. Attacker sends: `DELETE /transactions/{A_id}/approvers/{victim_approver_id}`
4. `getCreatorsTransaction(A_id, attacker)` passes — attacker is creator of A.
5. `removeTransactionApprover(victim_approver_id)` executes — deletes the approver from Transaction B without any ownership check.

### Impact Explanation

An attacker can silently remove approvers from any transaction they do not own. This directly undermines the multi-signature approval workflow:

- Approval thresholds can be reduced or eliminated on victim transactions, allowing them to proceed without the required organizational sign-off.
- Alternatively, removing all approvers from a transaction that requires approval can permanently block it from reaching `WAITING_FOR_EXECUTION` status, causing a denial-of-service on that transaction's lifecycle.
- The attacker leaves no trace on their own transaction; the damage is recorded only on the victim's transaction.

### Likelihood Explanation

- **Preconditions**: The attacker only needs a valid, verified account (standard registration) and must have created at least one transaction. Both are normal user actions.
- **Approver ID discovery**: Approver IDs are sequential auto-increment integers. An attacker can enumerate them trivially, or observe them from any transaction they legitimately participate in (as observer, signer, or approver).
- **No privileged access required**: This is fully exploitable by a normal authenticated user with no admin or operator role.

### Recommendation

In the controller's `removeTransactionApprover` handler, after verifying the caller is the creator of `transactionId`, verify that the approver being deleted actually belongs to that transaction before calling `removeTransactionApprover`. Mirror the guard already present in `updateTransactionApprover`:

```typescript
// In the controller, before removeTransactionApprover(id):
const approver = await this.approversService.getTransactionApproverById(id);
const rootNode = await this.approversService.getRootNodeFromNode(approver.id);
if (rootNode.transactionId !== transactionId) {
  throw new UnauthorizedException('Approver does not belong to this transaction');
}
await this.approversService.removeTransactionApprover(id);
```

Alternatively, move this ownership check into `removeTransactionApprover` itself and require `transactionId` as a parameter, making it impossible to call without the cross-reference.

### Proof of Concept

**Setup:**
- User A (attacker): registered, verified, has created Transaction #10 (their own).
- User B (victim): has Transaction #20 with approver record ID #55.

**Request:**
```
DELETE /transactions/10/approvers/55
Authorization: Bearer <attacker_jwt>
```

**Step-by-step execution:**
1. `getCreatorsTransaction(10, attacker)` → finds Transaction #10, confirms `creatorKey.userId === attacker.id` → **passes**.
2. `removeTransactionApprover(55)` → fetches approver #55 (belongs to Transaction #20), calls `removeNode(55)` → **approver #55 is deleted**.
3. Response: `200 true`.

**Expected (correct) behavior:** Request should be rejected with `401 Unauthorized` because approver #55 does not belong to Transaction #10.

**Observed behavior:** Approver #55 is permanently deleted from Transaction #20, bypassing all ownership checks on that transaction.

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
