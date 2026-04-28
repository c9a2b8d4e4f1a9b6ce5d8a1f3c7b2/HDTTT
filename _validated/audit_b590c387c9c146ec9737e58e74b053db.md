The code confirms the vulnerability. Here is the audit report:

---

Audit Report

## Title
Cross-Transaction Approver Deletion: Missing Ownership Binding in `removeTransactionApprover`

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller owns the transaction identified by `:transactionId`, but then deletes the approver identified by `:id` without verifying that the approver actually belongs to `:transactionId`. Any authenticated user who owns at least one transaction can delete approvers from any other user's transaction.

## Finding Description

**Root cause — missing cross-entity ownership binding in the delete path**

The controller handler at `approvers.controller.ts` lines 102–113 performs two independent, unbound calls:

```typescript
await this.approversService.getCreatorsTransaction(transactionId, user); // verifies caller owns transactionId
await this.approversService.removeTransactionApprover(id);               // deletes by id — no binding check
``` [1](#0-0) 

The service method `removeTransactionApprover` only checks that the approver record exists; it never validates that `approver.transactionId === transactionId`:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  ...
}
``` [2](#0-1) 

`getTransactionApproverById` queries only by `id` with no `transactionId` filter, so it will return any approver regardless of which transaction it belongs to. [3](#0-2) 

**Contrast with `updateTransactionApprover`**, which correctly enforces the binding by walking to the root node and asserting `rootNode.transactionId === transactionId` before proceeding:

```typescript
const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
``` [4](#0-3) 

The delete path skips this binding entirely.

**`removeNode` performs a cascading recursive soft-delete** of the entire approver subtree rooted at the targeted `id`, meaning a single request can wipe an entire threshold-key tree: [5](#0-4) 

## Impact Explanation

An attacker with a valid account (no admin privileges required) can silently delete any approver — or an entire approver subtree — from any other user's transaction. This:

- Breaks multi-signature approval workflows: a transaction requiring N-of-M approvals may become permanently unable to reach threshold.
- Constitutes unauthorized state mutation on another user's transaction, violating the integrity of the approval model.
- Can be used to selectively sabotage high-value or time-sensitive organizational transactions.
- Because `removeNode` cascades, a single request targeting a root approver node wipes the entire threshold-key tree of the victim transaction.

## Likelihood Explanation

- **Attacker precondition:** valid JWT (registered user). No admin key, no leaked secret, no privileged role required.
- **Discovery:** approver IDs are sequential integers. An attacker can enumerate them via `GET /transactions/:id/approvers` on any transaction they have read access to, or by brute-forcing small integers.
- **Detectability:** `removeTransactionApprover` emits a `transactionStatusUpdate` event keyed to `approver.transactionId` (the victim's transaction), but there is no alert to the victim's creator that an approver was removed by a third party. For child nodes, `approver.transactionId` is `null`, so even this notification is suppressed.

## Recommendation

In the `removeTransactionApprover` controller handler, add the same root-node ownership binding that `updateTransactionApprover` already performs before calling `getCreatorsTransaction`:

1. Fetch the approver by `id`.
2. Walk to the root node via `getRootNodeFromNode`.
3. Assert `rootNode.transactionId === transactionId` (throw `UnauthorizedException` if not).
4. Only then call `getCreatorsTransaction(transactionId, user)` and proceed with deletion.

Alternatively, refactor `removeTransactionApprover(id)` in the service to accept `transactionId` as a required parameter and enforce the binding internally, mirroring the pattern already used in `updateTransactionApprover`.

## Proof of Concept

1. **Bob** registers as a normal user and creates transaction `txA` (`id = 10`). Bob is its creator.
2. **Alice** creates transaction `txB` (`id = 20`) and adds a threshold approver tree; the root approver has `id = 99` and `transactionId = 20`.
3. Bob sends:
   ```
   DELETE /transactions/10/approvers/99
   ```
4. `getCreatorsTransaction(10, Bob)` passes — Bob owns `txA`.
5. `removeTransactionApprover(99)` fetches approver `99` (which belongs to `txB`), finds it exists, and calls `removeNode(99)`.
6. `removeNode` recursively soft-deletes approver `99` and its entire child subtree via the recursive CTE UPDATE.
7. Alice's entire approver tree is gone. Her transaction `txB` can no longer reach the required approval threshold. [1](#0-0) [2](#0-1)

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
