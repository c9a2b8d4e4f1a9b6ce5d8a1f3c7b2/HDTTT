### Title
Cross-Transaction Approver Deletion Authorization Bypass

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the requesting user is the creator of the transaction identified by `:transactionId`, but then deletes the approver identified by `:id` without verifying that the approver actually belongs to that transaction. Any authenticated user who owns at least one transaction can delete approvers from any other transaction in the system, bypassing the approval workflow and enabling unauthorized transaction execution.

### Finding Description

**Root cause:** In `approvers.controller.ts`, the `removeTransactionApprover` handler performs two independent operations:

1. `getCreatorsTransaction(transactionId, user)` — verifies the caller is the creator of the transaction at `:transactionId` in the URL.
2. `removeTransactionApprover(id)` — deletes the approver row by `:id` with **no check** that the approver belongs to the transaction from step 1. [1](#0-0) 

The service-level `removeTransactionApprover` simply fetches the approver by its primary key and deletes it: [2](#0-1) 

There is no assertion that `approver.transactionId === transactionId`. The `transactionId` URL parameter is used only as an ownership gate for the caller, not as a scope constraint on which approver can be deleted.

**Exploit path:**
1. Attacker (Alice) registers and creates any transaction → she becomes its creator (satisfies `getCreatorsTransaction`).
2. Alice discovers the numeric `id` of an approver belonging to Bob's transaction (IDs are sequential integers; the approver list endpoint `GET /transactions/:transactionId/approvers` leaks IDs to any participant, and IDs are globally sequential).
3. Alice sends: `DELETE /transactions/{alice_tx_id}/approvers/{bob_approver_id}`.
4. `getCreatorsTransaction(alice_tx_id, alice)` passes.
5. `removeTransactionApprover(bob_approver_id)` deletes Bob's approver with no further check.
6. Bob's transaction now has a missing approver, potentially dropping below its required threshold and allowing the transaction to proceed to execution without the required approval.

### Impact Explanation

An attacker can silently remove required approvers from any transaction in the organization. This breaks the multi-signature approval workflow: a transaction that required N approvals can be forced into `WAITING_FOR_EXECUTION` state with fewer approvals than intended. This constitutes unauthorized state mutation of another user's transaction and can lead to unauthorized execution of high-value Hedera transactions (token transfers, account updates, system file changes, etc.).

### Likelihood Explanation

The precondition is minimal: the attacker must be an authenticated organization member who has created at least one transaction. Approver IDs are sequential integers and are exposed through the `GET /transactions/:transactionId/approvers` endpoint to any participant. No privileged access, leaked secrets, or cryptographic breaks are required.

### Recommendation

Inside `removeTransactionApprover` (or before calling it in the controller), assert that the fetched approver's `transactionId` matches the `transactionId` URL parameter:

```typescript
// In approvers.controller.ts, after getCreatorsTransaction:
const approver = await this.approversService.getTransactionApproverById(id);
if (!approver || approver.transactionId !== transactionId) {
  throw new BadRequestException(ErrorCodes.ANF);
}
await this.approversService.removeTransactionApprover(id);
```

Alternatively, scope the deletion query to `WHERE id = :id AND "transactionId" = :transactionId` so the database enforces the constraint atomically.

### Proof of Concept

1. Alice registers, logs in, creates `TransactionA` (id=10). She is its creator.
2. Bob creates `TransactionB` (id=20) with an approver entry (approver id=55, `transactionId=20`).
3. Alice calls:
   ```
   DELETE /transactions/10/approvers/55
   Authorization: Bearer <alice_jwt>
   ```
4. Server executes `getCreatorsTransaction(10, alice)` → passes (Alice owns tx 10).
5. Server executes `removeTransactionApprover(55)` → deletes approver 55 (Bob's approver on tx 20).
6. `TransactionB` now has one fewer approver; if the threshold was 1-of-1, it may advance to `WAITING_FOR_EXECUTION` without Bob's approval, or the approval structure is corrupted. [1](#0-0) [2](#0-1)

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
