### Title
Unauthorized Cross-Transaction Approver Deletion via Missing Ownership Binding in `removeTransactionApprover`

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the requesting user is the creator of `:transactionId`, but then passes the unrelated `:id` (approver ID) directly to `removeTransactionApprover()` without verifying that the approver actually belongs to the verified transaction. Any authenticated user who owns at least one transaction can delete approvers from any other transaction in the system by supplying their own `transactionId` and a victim's approver `id`.

### Finding Description

**Vulnerability type**: Authorization bypass (auth).

The controller's `removeTransactionApprover` handler performs an ownership check on `transactionId`, then calls the service with a completely independent `id`:

```typescript
// approvers.controller.ts lines 102-113
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // ✓ checks user owns transactionId
  await this.approversService.removeTransactionApprover(id);               // ✗ no check that id ∈ transactionId
  return true;
}
``` [1](#0-0) 

The service method `removeTransactionApprover` accepts only the approver `id` and performs no cross-transaction ownership validation:

```typescript
// approvers.service.ts lines 533-544
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(...);
  return result;
}
``` [2](#0-1) 

The binding between the verified `transactionId` and the approver `id` is never enforced. Contrast this with `updateTransactionApprover`, which correctly validates both:

```typescript
// approvers.service.ts lines 389-394
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
``` [3](#0-2) 

The `removeNode` function recursively soft-deletes the entire approver subtree rooted at the given `id`, amplifying the impact: [4](#0-3) 

### Impact Explanation

An attacker can silently destroy the entire approver tree of any transaction they do not own. This directly undermines the multi-signature approval workflow: once approvers are deleted, a transaction that required organizational approval can proceed without it, or the approval state is corrupted. The `removeNode` recursive deletion means a single request can wipe an entire threshold-approver tree, not just a leaf node. [4](#0-3) 

### Likelihood Explanation

The preconditions are minimal: the attacker must be an authenticated, verified user who is the creator of **any** transaction (even one they created themselves). Approver IDs are sequential integers assigned by the database, making enumeration trivial. No privileged access, leaked credentials, or physical access is required. [1](#0-0) 

### Recommendation

Inside `removeTransactionApprover` (or in the controller before calling it), verify that the approver's root transaction matches the `transactionId` parameter, mirroring the check already present in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, transactionId: number, user: User): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Verify the approver belongs to the claimed transaction
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
``` [5](#0-4) 

### Proof of Concept

1. Attacker (User A) creates Transaction T_A and obtains its `transactionId` = 10.
2. Victim (User B) creates Transaction T_B with `transactionId` = 20 and adds approvers; one approver gets `id` = 99 (discoverable by enumeration via `GET /transactions/20/approvers` if the attacker has any read access, or by brute-forcing sequential IDs).
3. Attacker sends:
   ```
   DELETE /transactions/10/approvers/99
   Authorization: Bearer <attacker_token>
   ```
4. The server verifies User A is the creator of transaction 10 ✓, then calls `removeTransactionApprover(99)` which deletes approver 99 (belonging to transaction 20) and its entire subtree without any further check.
5. Transaction T_B's approval workflow is now corrupted or bypassed. [1](#0-0) [2](#0-1)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L366-394)
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
