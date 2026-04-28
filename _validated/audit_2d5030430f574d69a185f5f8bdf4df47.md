All code references are confirmed. The vulnerability is real.

---

Audit Report

## Title
Unauthorized Approver Deletion via Missing Ownership Validation in `removeTransactionApprover`

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller is the creator of `:transactionId` but never validates that the approver identified by `:id` belongs to that transaction. Any authenticated user who has created at least one transaction can delete approvers from any other user's transaction by supplying their own `transactionId` and an arbitrary approver `id`.

## Finding Description

**Root cause — two-step authorization that checks the wrong object:**

In `approvers.controller.ts`, the delete handler is:

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // checks user owns transactionId
  await this.approversService.removeTransactionApprover(id);               // deletes approver id — no ownership check
  return true;
}
``` [1](#0-0) 

`getCreatorsTransaction` only confirms the caller is the creator of the URL-supplied `transactionId` — it says nothing about whether approver `id` belongs to that transaction:

```typescript
if (transaction.creatorKey?.userId !== user.id)
  throw new UnauthorizedException('Only the creator of the transaction is able to modify it');
``` [2](#0-1) 

`removeTransactionApprover` in the service then deletes whatever approver matches `id` with no cross-check against `transactionId`:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  ...
}
``` [3](#0-2) 

`getTransactionApproverById` fetches by `id` alone with no `transactionId` filter: [4](#0-3) 

By contrast, `updateTransactionApprover` **does** perform the ownership check:

```typescript
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
``` [5](#0-4) 

The delete path is unprotected; the update path is not. The failed assumption is that passing `getCreatorsTransaction` on the URL's `transactionId` is sufficient to authorize deletion of approver `id` — it is not, because `id` is an independent parameter with no binding to `transactionId`.

`removeNode` performs a recursive CTE soft-delete of the target approver and its entire subtree: [6](#0-5) 

## Impact Explanation

- **Approval workflow bypass**: Removing approvers from a transaction that requires a threshold of approvals can reduce or eliminate that threshold requirement, allowing the transaction to proceed without proper multi-party authorization.
- **Unauthorized state mutation**: An attacker modifies another user's transaction state without being the creator of that transaction.
- **Irreversible disruption**: `removeNode` soft-deletes the approver and its entire child subtree. The approval tree is permanently altered and cannot be trivially restored.
- **Scope**: Any approver in the system — root or child node — is reachable by enumerating sequential integer IDs.

Severity: **High**

## Likelihood Explanation

- **Precondition**: The attacker must be an authenticated, verified user who has created at least one transaction (to pass `getCreatorsTransaction`). This is a normal user capability requiring no special privilege.
- **Discovery**: Approver IDs are sequential integers assigned by the database. An attacker can enumerate them or observe IDs from their own approvers via the `GET /transactions/:transactionId/approvers` endpoint.
- **No special privilege required**: No admin, operator, or leaked credentials needed.
- **Realistic**: Any malicious organization member can exploit this against any other member's pending transactions.

## Recommendation

In `removeTransactionApprover` (service), after fetching the approver, resolve its root node and verify that `rootNode.transactionId === transactionId` before proceeding — exactly as `updateTransactionApprover` already does:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Add this ownership check (mirrors updateTransactionApprover)
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);
  if (rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

  const result = await this.removeNode(approver.id);
  ...
}
```

Pass `transactionId` from the controller into `removeTransactionApprover`. This mirrors the existing protection in `updateTransactionApprover`. [7](#0-6) 

## Proof of Concept

**Setup:**
- Attacker is authenticated user A, creator of transaction `T_A` (id = 1).
- Victim is user B, creator of transaction `T_B` (id = 2) with approver `APR` (id = 5) required for execution.

**Exploit:**
```
DELETE /transactions/1/approvers/5
Authorization: Bearer <attacker_token>
```

**Step-by-step execution:**
1. `getCreatorsTransaction(1, userA)` — passes, because user A is the creator of transaction 1.
2. `removeTransactionApprover(5)` — fetches approver with id=5 (belongs to transaction 2), finds it exists, calls `removeNode(5)`.
3. `removeNode(5)` — recursively soft-deletes approver 5 and all its children via the CTE UPDATE query.
4. Transaction `T_B`'s approval tree is permanently mutated. If approver 5 was the sole required approver, `T_B` can now proceed without any approval.

**Result:** User A has deleted an approver from user B's transaction without being the creator of that transaction, bypassing the multi-signature approval workflow. [8](#0-7) [9](#0-8)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L66-82)
```typescript
  getTransactionApproverById(
    id: number,
    entityManager?: EntityManager,
  ): Promise<TransactionApprover> {
    if (!id) return null;

    const find: FindOneOptions<TransactionApprover> = {
      relations: ['approvers'],
      where: { id },
    };

    if (entityManager) {
      return entityManager.findOne(TransactionApprover, find);
    }

    return this.repo.findOne(find);
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L640-641)
```typescript
    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to modify it');
```
