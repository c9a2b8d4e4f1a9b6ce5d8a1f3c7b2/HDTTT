### Title
Missing Association Check Between `transactionId` and Approver `id` in `removeTransactionApprover` Enables Cross-Transaction Approver Deletion

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the authenticated user is the creator of `transactionId`, but then deletes the approver record identified solely by `id` without confirming that approver belongs to `transactionId`. A malicious transaction creator can supply their own valid `transactionId` to pass the ownership check while targeting an approver `id` from a completely different transaction, deleting it without authorization.

### Finding Description
In `back-end/apps/api/src/transactions/approvers/approvers.controller.ts`, the `removeTransactionApprover` handler performs two independent operations:

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user);
  await this.approversService.removeTransactionApprover(id);
  return true;
}
``` [1](#0-0) 

Step 1 (`getCreatorsTransaction`) validates that the caller owns `transactionId`. Step 2 (`removeTransactionApprover(id)`) deletes the approver row by its primary key `id` alone. There is no check that the approver record with `id` has `transactionId` as its foreign key. The two parameters are never cross-validated against each other.

The route is nested under `transactions/:transactionId?/approvers`, so the URL structure implies the approver must belong to the given transaction — but this invariant is never enforced in code. [2](#0-1) 

### Impact Explanation
An authenticated user who owns any transaction (even a trivial one they created themselves) can delete approvers from any other transaction in the system by:

1. Discovering or enumerating an approver `id` belonging to a victim transaction (auto-increment integer IDs are trivially enumerable via the `GET /transactions/:transactionId/approvers` endpoint on transactions they can observe).
2. Issuing `DELETE /transactions/{own_transactionId}/approvers/{victim_approver_id}`.
3. The ownership check passes (they own `own_transactionId`), and the victim approver is permanently deleted.

**Concrete impacts:**
- Removal of required approvers from pending multi-signature transactions, bypassing the approval threshold and allowing transactions to proceed without proper authorization.
- Permanent corruption of approval trees for any transaction in the organization.
- Denial of service against specific transactions by stripping all their approvers, making them unexecutable or forcing re-creation.

This directly violates the multi-signature integrity guarantee that is the core security property of Organization Mode.

### Likelihood Explanation
The attacker only needs to be a normal authenticated user who has created at least one transaction — a baseline capability for any organization member. Approver IDs are sequential integers exposed through standard GET endpoints. No privileged access, leaked credentials, or cryptographic breaks are required. The exploit is a single crafted HTTP DELETE request.

### Recommendation
In `approversService.removeTransactionApprover`, before deleting, verify that the approver record's `transactionId` foreign key matches the `transactionId` supplied in the URL. Concretely, fetch the approver by `id` and assert `approver.transactionId === transactionId`; throw a `NotFoundException` or `ForbiddenException` if they do not match. This check should live at the service layer so it is enforced regardless of which controller calls the method. [3](#0-2) 

### Proof of Concept

**Preconditions:**
- Attacker is an authenticated organization member (normal user, no admin role needed).
- Attacker has created Transaction A (ID = 10) — they pass `getCreatorsTransaction`.
- Victim's Transaction B (ID = 99) has an approver with ID = 47 (discoverable via `GET /transactions/99/approvers` if the attacker can observe that transaction, or by sequential enumeration).

**Steps:**
1. Attacker sends:
   ```
   DELETE /transactions/10/approvers/47
   Authorization: Bearer <attacker_jwt>
   ```
2. Server calls `getCreatorsTransaction(10, attacker)` → passes (attacker owns transaction 10).
3. Server calls `removeTransactionApprover(47)` → deletes approver 47, which belongs to transaction 99.
4. Transaction 99's approval tree is now corrupted; its required approver is gone.

**Expected (correct) behavior:** The server should reject the request with 403/404 because approver 47 does not belong to transaction 10.

**Actual behavior:** Approver 47 is deleted unconditionally.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L31-33)
```typescript
@ApiTags('Transaction Approvers')
@Controller('transactions/:transactionId?/approvers')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
```

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
