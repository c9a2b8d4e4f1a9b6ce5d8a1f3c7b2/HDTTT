The code has been verified. All claims check out against the actual source.

---

Audit Report

## Title
Unauthorized Cross-Transaction Approver Deletion via Missing Ownership Binding in `removeTransactionApprover`

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint authenticates the requesting user as the creator of `:transactionId`, but never verifies that the approver `:id` belongs to that transaction before deleting it. Any authenticated user who owns at least one transaction can delete approvers from any other transaction in the system.

## Finding Description

In `approvers.controller.ts`, the `removeTransactionApprover` handler performs an ownership check on `transactionId`, then calls the service with a completely independent `id`: [1](#0-0) 

`getCreatorsTransaction` only verifies the user owns `transactionId`. It does not return or bind any approver scope. The subsequent call to `removeTransactionApprover(id)` accepts any approver ID in the database: [2](#0-1) 

The service checks only that the approver record exists (`ErrorCodes.ANF`), then immediately calls `removeNode`. There is no check that `approver.transactionId` (or its root's `transactionId`) matches the `transactionId` the user was authorized against.

This is a direct omission compared to `updateTransactionApprover`, which correctly enforces the binding: [3](#0-2) 

`removeNode` performs a recursive SQL soft-delete of the entire subtree rooted at the given `id`, amplifying the impact of a single request: [4](#0-3) 

## Impact Explanation

An attacker can silently destroy the entire approver tree of any transaction they do not own. Because `removeNode` recursively soft-deletes all descendants, a single crafted request can wipe an entire threshold-approver tree. This directly undermines the multi-signature approval workflow: once approvers are deleted, a transaction that required organizational approval can proceed without it, or the approval state is permanently corrupted. [5](#0-4) 

## Likelihood Explanation

Preconditions are minimal: the attacker must be an authenticated, verified user who is the creator of **any** transaction (including one they created themselves). Approver IDs are sequential integers assigned by the database, making enumeration trivial. No privileged access, leaked credentials, or physical access is required. [6](#0-5) 

## Recommendation

In `removeTransactionApprover` (service), after fetching the approver, resolve its root node and assert that `rootNode.transactionId === transactionId` before proceeding — exactly as `updateTransactionApprover` does:

```typescript
const rootNode = await this.getRootNodeFromNode(approver.id);
if (!rootNode || rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
``` [3](#0-2) 

Alternatively, the controller can pass `transactionId` into `removeTransactionApprover` and enforce the check there, consistent with how `updateTransactionApprover` receives and validates both parameters. [7](#0-6) 

## Proof of Concept

1. Attacker (user A) creates their own transaction → `transactionId = 1`. This satisfies `getCreatorsTransaction`.
2. Attacker enumerates approver IDs (sequential integers) and identifies victim approver `id = 99`, which belongs to `transactionId = 42` owned by user B.
3. Attacker sends:
   ```
   DELETE /transactions/1/approvers/99
   Authorization: Bearer <attacker_token>
   ```
4. Server executes `getCreatorsTransaction(1, userA)` → passes (user A owns transaction 1).
5. Server executes `removeTransactionApprover(99)` → fetches approver 99, calls `removeNode(99)`, recursively soft-deletes the entire approver subtree of transaction 42.
6. Transaction 42's approval requirements are silently destroyed without user B's knowledge. [6](#0-5) [8](#0-7)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L125-133)
```typescript
  @Patch('/:id')
  async updateTransactionApprover(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Param('id', ParseIntPipe) id: number,
    @Body() body: UpdateTransactionApproverDto,
  ): Promise<TransactionApprover> {
    return this.approversService.updateTransactionApprover(id, body, transactionId, user);
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L205-231)
```typescript
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
