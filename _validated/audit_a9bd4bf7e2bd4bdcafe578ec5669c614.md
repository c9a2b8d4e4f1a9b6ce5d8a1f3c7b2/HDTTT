The code confirms the vulnerability. Let me verify the exact line references before writing the report.

The controller at lines 102-113 performs two independent operations with no cross-validation: [1](#0-0) 

`removeTransactionApprover` in the service fetches by `id` only and calls `removeNode` with no `transactionId` scope check: [2](#0-1) 

`getTransactionApproverById` has no `transactionId` filter: [3](#0-2) 

`updateTransactionApprover` has the cross-check that `removeTransactionApprover` is missing: [4](#0-3) 

`removeNode` recursively soft-deletes the entire tree: [5](#0-4) 

---

# Audit Report

## Title
Cross-Transaction Approver Deletion via Missing Ownership Validation in `removeTransactionApprover`

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the authenticated user owns `:transactionId`, but then deletes approver `:id` without verifying that `:id` belongs to `:transactionId`. Any verified user who owns at least one transaction can delete approvers — including entire approval trees — from any other transaction in the system.

## Finding Description

**Root cause — controller performs no cross-validation:**

In `approvers.controller.ts` lines 102–113, the `removeTransactionApprover` handler executes two independent steps:

```typescript
await this.approversService.getCreatorsTransaction(transactionId, user); // confirms user owns transactionId
await this.approversService.removeTransactionApprover(id);               // deletes approver `id` — no cross-check
```

`getCreatorsTransaction` returns the transaction but its return value is discarded and never used to constrain the deletion. [6](#0-5) 

**Root cause — service deletes by approver ID alone:**

`removeTransactionApprover` fetches the approver by `id` only and immediately calls `removeNode` with no check that `approver.transactionId` matches the authorized `transactionId`: [2](#0-1) 

`getTransactionApproverById` applies no transaction scope: [7](#0-6) 

**Contrast with `updateTransactionApprover`**, which correctly resolves the root node and validates cross-ownership before proceeding: [8](#0-7) 

The `delete` path has no equivalent guard.

**`removeNode` recursively soft-deletes the entire approver tree** via a recursive CTE, so targeting a root approver of another transaction wipes its entire approval structure: [5](#0-4) 

## Impact Explanation

- **Unauthorized state mutation:** Any verified user can delete approvers from any transaction they did not create, bypassing the "only creator can modify" invariant enforced by `getCreatorsTransaction`.
- **Multi-signature bypass:** Deleting all root approvers from a target transaction eliminates the approval requirement entirely, allowing the transaction to proceed without the required signatures.
- **Recursive destruction:** Because `removeNode` uses a recursive CTE, a single request targeting a root approver deletes the entire approval tree for the victim's transaction.
- **Permanent corruption:** Soft-deleted approvers are removed from the active approval workflow. The transaction's approval state cannot be recovered without direct database intervention.
- **System-wide scope:** All transactions in the system are affected, not just the attacker's own.

## Likelihood Explanation

- **Low attacker preconditions:** The attacker only needs to be a registered, verified user with at least one created transaction — the normal user baseline. No admin access is required.
- **Approver ID discovery:** The `GET /transactions/:transactionId/approvers` endpoint returns approver IDs for any transaction the user has access to (as observer, signer, or approver). IDs are sequential integers and may be guessable even without direct read access.
- **Trivially exploitable:** A single crafted `DELETE` request is sufficient.
- **No anomaly detection** is visible on this endpoint.

## Recommendation

In `removeTransactionApprover` (service), after fetching the approver, resolve its root node and verify that `rootNode.transactionId` matches the authorized `transactionId` — exactly as `updateTransactionApprover` does:

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Cross-validate: ensure the approver belongs to the authorized transaction
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to the specified transaction');

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);
  return result;
}
```

Pass `transactionId` from the controller into `removeTransactionApprover`. This mirrors the existing guard in `updateTransactionApprover` at lines 386–394. [8](#0-7) 

## Proof of Concept

1. Attacker (user A) creates transaction `T_A` and adds at least one approver (to satisfy `getCreatorsTransaction`).
2. Attacker discovers approver ID `X` belonging to victim's transaction `T_B` (via `GET /transactions/T_B/approvers` if they have any access, or by guessing sequential IDs).
3. Attacker sends:
   ```
   DELETE /transactions/T_A/approvers/X
   Authorization: Bearer <attacker_jwt>
   ```
4. Server executes:
   - `getCreatorsTransaction(T_A, userA)` → passes (attacker owns `T_A`)
   - `removeTransactionApprover(X)` → fetches approver `X` (belongs to `T_B`), calls `removeNode(X)`, recursively soft-deletes the entire approval tree of `T_B`
5. Transaction `T_B`'s approval requirements are permanently destroyed. The attacker never needed any relationship to `T_B`.

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
