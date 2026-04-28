The code has been verified against the exact lines cited. The vulnerability is confirmed.

---

Audit Report

## Title
Creator of Any Transaction Can Delete Approvers Belonging to Other Transactions (IDOR)

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies only that the caller is the creator of `:transactionId`, then deletes the approver identified by `:id` without confirming that approver belongs to `:transactionId`. Any authenticated user who has created at least one transaction can delete approvers from any other transaction in the system.

## Finding Description

The controller performs a two-step authorization with a broken ownership chain: [1](#0-0) 

Step 1 (`getCreatorsTransaction`) only validates that the authenticated user created the transaction referenced by `:transactionId` in the URL: [2](#0-1) 

Step 2 (`removeTransactionApprover`) fetches the approver by its own primary key and deletes it with no check that `approver.transactionId` matches the `:transactionId` URL parameter: [3](#0-2) 

The recursive `removeNode` soft-deletes the entire subtree rooted at the given approver ID, regardless of which transaction it belongs to: [4](#0-3) 

**The fix already exists in the codebase for the update path** — `updateTransactionApprover` correctly fetches the root node and verifies `rootNode.transactionId !== transactionId` before proceeding: [5](#0-4) 

This cross-check was simply never applied to the delete path.

## Impact Explanation

An attacker who is the creator of **any** transaction (Transaction A) can:

1. Enumerate approver IDs belonging to Transaction B (owned by another user) — approver IDs are sequential integers.
2. Call `DELETE /transactions/A/approvers/<B_approver_id>`.
3. The authorization check passes (attacker is creator of A), and the approver from Transaction B is deleted along with its entire subtree.

Concrete consequences:
- Required approvers are silently removed from transactions the attacker does not own.
- If the remaining approvers satisfy the threshold, the transaction advances to `WAITING_FOR_EXECUTION` without the intended signatories having approved it.
- For high-value Hedera transactions (e.g., system file updates, large HBAR transfers), this can cause unauthorized execution.

## Likelihood Explanation

- **Attacker precondition**: any registered user who has created at least one transaction — no admin role required.
- **Approver ID enumeration**: IDs are sequential integers, trivially brute-forceable.
- **No anomaly detection** is visible on this endpoint.
- The flaw is reachable via a standard authenticated HTTP DELETE request.

## Recommendation

In `removeTransactionApprover` (or in the controller before calling it), add the same ownership cross-check already present in `updateTransactionApprover`:

1. After fetching the approver by `id`, traverse to its root node via `getRootNodeFromNode`.
2. Assert that `rootNode.transactionId === transactionId` (the URL parameter).
3. Throw `UnauthorizedException` if they do not match.

This mirrors the existing pattern at `approvers.service.ts` lines 386–391 and closes the ownership gap.

## Proof of Concept

```
# Attacker owns Transaction A (id=1), victim owns Transaction B (id=2)
# Transaction B has an approver with id=99

DELETE /transactions/1/approvers/99
Authorization: Bearer <attacker_jwt>

# Flow:
# 1. getCreatorsTransaction(1, attacker) → passes (attacker created tx 1)
# 2. removeTransactionApprover(99) → fetches approver 99 (belongs to tx 2),
#    calls removeNode(99) → soft-deletes approver 99 and its entire subtree
# 3. Returns HTTP 200 true

# Result: approver 99 (and all its children) are deleted from Transaction B
# without the victim's knowledge or consent.
```

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L624-644)
```typescript
  async getCreatorsTransaction(
    transactionId: number,
    user: User,
    entityManager?: EntityManager,
  ): Promise<Transaction> {
    const find: FindOneOptions<Transaction> = {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user'],
    };

    const transaction = await (entityManager
      ? entityManager.findOne(Transaction, find)
      : this.dataSource.manager.findOne(Transaction, find));

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to modify it');

    return transaction;
  }
```
