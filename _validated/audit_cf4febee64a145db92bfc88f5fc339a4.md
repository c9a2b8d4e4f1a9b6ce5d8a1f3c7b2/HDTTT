The code is confirmed. Let me verify the `removeNode` behavior and the `TransactionApprover` entity for completeness.

Audit Report

## Title
Cross-Transaction Approver Deletion via Missing ID-to-Transaction Binding Check in `removeTransactionApprover`

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the requesting user is the creator of `:transactionId`, but then deletes the approver record identified solely by `:id` without confirming that approver belongs to `:transactionId`. Any authenticated user who has created at least one transaction can delete approvers from any other transaction by supplying their own `transactionId` and a victim approver's `id`.

## Finding Description

The controller handler performs two independent, unbound operations:

```typescript
// Step 1: only confirms caller owns transactionId
await this.approversService.getCreatorsTransaction(transactionId, user);
// Step 2: deletes by id alone — no binding to transactionId
await this.approversService.removeTransactionApprover(id);
``` [1](#0-0) 

`removeTransactionApprover` fetches the approver record and immediately soft-deletes it without any cross-check:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  ...
}
``` [2](#0-1) 

`getTransactionApproverById` queries only by `id` with no `transactionId` filter:

```typescript
const find: FindOneOptions<TransactionApprover> = {
  relations: ['approvers'],
  where: { id },
};
``` [3](#0-2) 

The entity schema confirms that only root nodes carry a non-null `transactionId`; child nodes have `transactionId = null` and a non-null `listId`. [4](#0-3) 

By contrast, `updateTransactionApprover` correctly performs the binding check before acting:

```typescript
const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
``` [5](#0-4) 

The delete path is missing this exact guard. The `removeNode` function performs a recursive SQL soft-delete of the entire subtree rooted at the target `id`: [6](#0-5) 

## Impact Explanation
An attacker can silently remove any approver — or an entire approval subtree — from any transaction they did not create. Because `removeNode` recursively soft-deletes all descendants, a single request can wipe an entire multi-level approval tree from a victim transaction. This allows a transaction to proceed to execution without the intended authorization quorum, directly undermining the multi-signature coordination model that is the core security guarantee of the system. [6](#0-5) 

## Likelihood Explanation
Preconditions are minimal:
1. The attacker must be a registered, verified user — no admin or operator role required.
2. The attacker must have created at least one transaction (to pass `getCreatorsTransaction`). This is a normal product action.
3. The attacker must know a victim approver's integer `id`. Approver IDs are sequential database integers discoverable via `GET /transactions/:transactionId/approvers` for any transaction the attacker has read access to, or by enumeration.

The attack is a single crafted HTTP DELETE request with no race condition or timing dependency. [1](#0-0) 

## Recommendation
Apply the same root-node binding check that `updateTransactionApprover` already uses inside `removeTransactionApprover` (or in the controller before calling it):

```typescript
async removeTransactionApprover(id: number, transactionId: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Add the missing binding check:
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);
  if (rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

  const result = await this.removeNode(approver.id);
  ...
}
```

Pass `transactionId` from the controller into `removeTransactionApprover` and enforce the check before `removeNode` is called. [7](#0-6) 

## Proof of Concept

**Setup:**
- Attacker (User A) creates Transaction T_A and obtains its `transactionId` (e.g., `1`).
- Victim (User B) creates Transaction T_B with a required approver having `id = 99`.

**Attack request:**
```
DELETE /transactions/1/approvers/99
Authorization: Bearer <User A's JWT>
```

**Execution trace:**
1. `getCreatorsTransaction(1, UserA)` — passes because User A owns transaction `1`.
2. `removeTransactionApprover(99)` — fetches approver `99` (which belongs to T_B) by `id` alone, finds it, calls `removeNode(99)`.
3. `removeNode(99)` — recursively soft-deletes approver `99` and all its descendants from T_B.
4. Response: `true`.

Approver `99` (and its entire subtree) is now deleted from T_B. User B's transaction can proceed without the intended approval quorum. [2](#0-1)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L72-75)
```typescript
    const find: FindOneOptions<TransactionApprover> = {
      relations: ['approvers'],
      where: { id },
    };
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

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L24-42)
```typescript
  /* If the approver has a listId, then transactionId should be null */
  @ManyToOne(() => Transaction, transaction => transaction.approvers, {
    nullable: true,
  })
  @JoinColumn({ name: 'transactionId' })
  transaction?: Transaction;

  @Column({ nullable: true })
  transactionId?: number;

  @ManyToOne(() => TransactionApprover, approverList => approverList.approvers, {
    nullable: true,
  })
  @JoinColumn({ name: 'listId' })
  list?: TransactionApprover;

  @Column({ nullable: true })
  listId?: number;

```
