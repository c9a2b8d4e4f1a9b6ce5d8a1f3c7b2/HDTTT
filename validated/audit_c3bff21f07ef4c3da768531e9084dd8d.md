All code references verified against the actual source. The vulnerability is confirmed.

---

Audit Report

## Title
IDOR in `removeTransactionApprover`: Any Transaction Creator Can Delete Approvers Belonging to Other Transactions

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller owns `:transactionId`, then passes the unrelated `:id` directly to `removeTransactionApprover()` with no check that the targeted approver actually belongs to that transaction. Any authenticated user who owns at least one transaction can exploit this to soft-delete approvers from any other transaction in the system.

## Finding Description

**Root cause:** The authorization check and the destructive action operate on two different, unlinked objects.

In `approvers.controller.ts` lines 102–113:

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // checks ownership of transactionId only
  await this.approversService.removeTransactionApprover(id);               // deletes by id — no cross-check
  return true;
}
``` [1](#0-0) 

`getCreatorsTransaction` only confirms the caller created the transaction identified by `:transactionId`. It says nothing about `:id`.

`removeTransactionApprover` in `approvers.service.ts` lines 533–544 then fetches the approver by `:id` alone and soft-deletes it with no ownership verification:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  ...
}
``` [2](#0-1) 

**Contrast with `updateTransactionApprover`**, which correctly validates the cross-reference at lines 389–391:

```typescript
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
``` [3](#0-2) 

The delete path is missing this exact guard. The `removeNode` function performs a recursive soft-delete of the entire approver subtree rooted at the given ID, amplifying the damage. [4](#0-3) 

## Impact Explanation
An attacker can silently remove any approver (or entire approver subtree) from any transaction they do not own. Depending on the approval tree structure, this can:
- Reduce the threshold quorum below the intended level, allowing a transaction to execute with fewer approvals than required.
- Completely remove all approvers from a transaction, making it impossible to satisfy the approval condition and permanently blocking execution.
- Disrupt multi-signature governance workflows for the entire organization.

This is permanent state corruption — soft-deleted approvers are not automatically restored.

## Likelihood Explanation
The attacker only needs to be a normal authenticated user who has created at least one transaction (a standard product action). Approver IDs are sequential integers (`id: number` primary key), making enumeration trivial. No admin privileges, leaked secrets, or internal access are required. The endpoint is a standard REST `DELETE` call.

## Recommendation
In `removeTransactionApprover` (service), after fetching the approver, resolve its root node and verify that `rootNode.transactionId === transactionId` before proceeding — exactly as `updateTransactionApprover` does at lines 386–391:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

  // Guard: ensure the approver belongs to the transaction being modified
  if (rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

  const result = await this.removeNode(approver.id);
  ...
}
```

The controller must also pass `transactionId` to the service method. [5](#0-4) 

## Proof of Concept

1. Attacker registers and creates **Transaction A** (`transactionId = 1`) — they are its creator.
2. Attacker enumerates or guesses an approver ID (`id = 99`) that belongs to **Transaction B** (`transactionId = 2`), owned by a different user.
3. Attacker sends:
   ```
   DELETE /transactions/1/approvers/99
   Authorization: Bearer <attacker_jwt>
   ```
4. `getCreatorsTransaction(1, attacker)` passes — attacker owns Transaction 1.
5. `removeTransactionApprover(99)` executes — approver 99 (belonging to Transaction B) is soft-deleted with no further check.
6. Transaction B's approval tree is now corrupted or incomplete, with no indication to its owner. [6](#0-5)

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
