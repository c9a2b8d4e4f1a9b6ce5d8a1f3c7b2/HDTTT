### Title
Any Authenticated User Can Delete Approvers Belonging to Any Transaction via Broken Cross-Resource Authorization in `removeTransactionApprover`

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the requesting user is the creator of `:transactionId`, but then passes the approver `:id` directly to `removeTransactionApprover(id)` without verifying that the approver actually belongs to that transaction. An attacker who owns any one transaction can delete approvers from any other transaction in the system by supplying their own `transactionId` (to pass the creator check) alongside an arbitrary victim approver `id`.

### Finding Description

**Root cause — controller decouples the creator check from the deletion target:**

In `approvers.controller.ts`, the `removeTransactionApprover` handler performs two independent calls:

```typescript
// back-end/apps/api/src/transactions/approvers/approvers.controller.ts  lines 102-113
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user);  // checks user owns transactionId
  await this.approversService.removeTransactionApprover(id);                // deletes approver by id — no cross-check
  return true;
}
``` [1](#0-0) 

Step 1 (`getCreatorsTransaction`) confirms the caller is the creator of `transactionId`. Step 2 (`removeTransactionApprover`) deletes the approver identified by `id`. **No code ever checks that `approver.transactionId === transactionId`.**

**Service method accepts any approver ID with no ownership binding:**

```typescript
// back-end/apps/api/src/transactions/approvers/approvers.service.ts  lines 534-544
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);   // deletes the entire subtree
  emitTransactionStatusUpdate(...);
  return result;
}
``` [2](#0-1) 

The `transactionId` URL parameter is never forwarded to this method, so the binding between "transaction the user owns" and "approver being deleted" is never enforced.

**Contrast with `updateTransactionApprover`, which does the check correctly:**

```typescript
// approvers.service.ts  lines 386-394
const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
``` [3](#0-2) 

The update path verifies the approver's root transaction matches the URL parameter and that the user owns it. The delete path has no equivalent check.

### Impact Explanation

An attacker can silently delete any approver (or an entire approver subtree via `removeNode`) from any transaction in the organization. This:

- Removes required approval gates from transactions the attacker does not own, allowing those transactions to advance to execution without the intended approvals.
- Permanently corrupts the approval workflow state for victim transactions (soft-delete via `deletedAt`).
- Affects the multi-signature trust model that is the core security guarantee of Organization Mode. [4](#0-3) 

### Likelihood Explanation

- **Precondition**: The attacker must be an authenticated, verified organization user — the lowest privilege level above anonymous.
- **No special knowledge required**: Approver IDs are sequential integers. The attacker can enumerate them trivially.
- **Trigger**: Create one transaction (normal user action), then issue `DELETE /transactions/{own_tx_id}/approvers/{victim_approver_id}` for any approver ID.
- **No rate limiting or anomaly detection** is present on this endpoint.

### Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver being deleted belongs to the transaction the user was authorized against:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Resolve the root node and confirm it belongs to the expected transaction
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to the specified transaction');

  await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
}
```

This mirrors the pattern already used correctly in `updateTransactionApprover`. [5](#0-4) 

### Proof of Concept

1. Attacker registers and logs in as a verified organization user (User A).
2. Victim (User B, admin or any other user) creates Transaction B with an approver tree. Note the approver IDs returned (e.g., `approver_id = 42`).
3. Attacker creates their own Transaction A. Note its ID (e.g., `tx_id = 99`).
4. Attacker sends:
   ```
   DELETE /transactions/99/approvers/42
   Authorization: Bearer <attacker_jwt>
   ```
5. `getCreatorsTransaction(99, attackerUser)` passes — attacker owns transaction 99.
6. `removeTransactionApprover(42)` executes — approver 42 (belonging to Transaction B) is soft-deleted with its entire subtree.
7. Transaction B's approval workflow is now broken; the deleted approver(s) no longer appear and the threshold logic is disrupted. [1](#0-0) [2](#0-1)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L204-231)
```typescript
  /* Soft deletes approvers' tree */
  async removeNode(listId: number): Promise<void> {
    if (!listId || typeof listId !== 'number') return null;

    await this.repo.query(
      `
      with recursive approversToDelete AS
        (
          select "id", "listId", "deletedAt"
          from transaction_approver
          where "id" = $1
  
            union all
              select transaction_approver."id", transaction_approver."listId", transaction_approver."deletedAt"
              from transaction_approver, approversToDelete     
              where approversToDelete."id" = transaction_approver."listId"
      
        )
      update transaction_approver
      set "deletedAt" = now()
      from approversToDelete
      where approversToDelete."id" = transaction_approver."listId" or transaction_approver."id" = $1;
    `,
      [listId],
    );

    // notifyTransactionAction(this.notificationsService);
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L366-395)
```typescript
  /* Updates an approver of a transaction */
  async updateTransactionApprover(
    id: number,
    dto: UpdateTransactionApproverDto,
    transactionId: number,
    user: User,
  ): Promise<TransactionApprover> {
    try {
      let updated = false;

      const approver = await this.dataSource.transaction(async transactionalEntityManager => {
        /* Check if the dto updates only one thing */
        if (Object.keys(dto).length > 1 || Object.keys(dto).length === 0)
          throw new Error(this.INVALID_UPDATE_APPROVER);

        /* Verifies that the approver exists */
        const approver = await this.getTransactionApproverById(id, transactionalEntityManager);
        if (!approver) throw new BadRequestException(ErrorCodes.ANF);

        /* Gets the root approver */
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
