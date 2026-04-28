### Title
IDOR in `removeTransactionApprover`: Any Transaction Creator Can Delete Approvers from Arbitrary Transactions

### Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller is the creator of the `:transactionId` URL parameter, but then passes the approver `:id` directly to `removeTransactionApprover()` without ever confirming that approver belongs to that transaction. An attacker who is the creator of any transaction can delete approvers from any other transaction in the system by substituting a foreign approver ID in the URL.

### Finding Description

**Root cause:** The controller and service have a split-responsibility design where the ownership check and the deletion act on two different objects with no binding between them.

In `approvers.controller.ts` lines 102–113:

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // checks T1
  await this.approversService.removeTransactionApprover(id);               // deletes approver from T2
  return true;
}
``` [1](#0-0) 

`getCreatorsTransaction(transactionId, user)` only verifies the caller is the creator of the transaction identified by the URL's `:transactionId`. It says nothing about the approver identified by `:id`.

`removeTransactionApprover(id)` in `approvers.service.ts` lines 533–544 accepts only the approver `id`, fetches it, and deletes it — with zero check that the approver's `transactionId` matches the URL parameter:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(...);
  return result;
}
``` [2](#0-1) 

**Contrast with `updateTransactionApprover`**, which correctly performs the binding check before acting:

```typescript
const rootNode = await this.getRootNodeFromNode(approver.id, ...);
if (rootNode.transactionId !== transactionId)          // ← binding check
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, ...); // ← ownership check
``` [3](#0-2) 

The `removeTransactionApprover` service method is missing both of these checks entirely. The code quality issue (split logic between controller and service, with the service accepting only a bare `id`) is the direct analog of the DSTContract complexity problem: the authorization invariant is not enforced at the point of mutation.

**Exploit flow:**
1. Attacker (User A) creates Transaction T1 — they are its creator.
2. Victim (User B) creates Transaction T2 with required approvers (approver IDs are sequential integers, enumerable via the `GET /transactions/:id/approvers` endpoint which returns approver IDs to any participant).
3. Attacker sends: `DELETE /transactions/T1/approvers/{approver_id_from_T2}`
4. Controller calls `getCreatorsTransaction(T1, userA)` → passes (A is creator of T1).
5. Controller calls `removeTransactionApprover(approver_id_from_T2)` → service fetches the approver, confirms it exists, and soft-deletes it and its entire subtree via `removeNode()`.
6. The approver belonging to T2 is now deleted. T2's approval workflow is corrupted. [4](#0-3) 

### Impact Explanation
An attacker can silently remove required approvers from any transaction they do not own. This directly undermines the multi-signature approval workflow: a transaction that required N approvals can be reduced to require fewer (or zero) approvals, allowing it to proceed to execution without the intended governance controls. The `removeNode` function performs a recursive soft-delete of the entire approver subtree, so a single request can wipe an entire threshold-approval tree from a victim's transaction. [4](#0-3) 

### Likelihood Explanation
The precondition is minimal: the attacker must be an authenticated, verified user who is the creator of at least one transaction (a normal product action). Approver IDs are sequential integers and are returned by the `GET /transactions/:transactionId/approvers` endpoint to any participant of a transaction, making enumeration straightforward. No privileged access, leaked credentials, or cryptographic break is required. [5](#0-4) 

### Recommendation
Move the binding and ownership check into `removeTransactionApprover` itself (mirroring `updateTransactionApprover`). The service method should accept `transactionId` and `user` in addition to `id`, then:

1. Fetch the approver by `id`.
2. Walk to its root node via `getRootNodeFromNode`.
3. Assert `rootNode.transactionId === transactionId` — throw `UnauthorizedException` if not.
4. Assert the caller is the creator of that transaction via `getCreatorsTransaction`.
5. Only then call `removeNode`.

This ensures the authorization invariant is enforced at the point of mutation, regardless of how the service method is called.

### Proof of Concept

**Setup:**
- User A authenticates and creates Transaction T1 (A is creator). Note T1's `id`.
- User B authenticates and creates Transaction T2 with an approver tree. Note the approver's `id` (e.g., `42`) from the `GET /transactions/T2/approvers` response.

**Attack request (as User A):**
```
DELETE /transactions/{T1_id}/approvers/42
Authorization: Bearer <User_A_JWT>
```

**Expected (broken) behavior:**
- HTTP 200 `true`
- Approver `42` (belonging to T2) is soft-deleted from the database along with its entire subtree.
- T2's approval workflow is now missing the required approver.

**Expected (correct) behavior:**
- HTTP 401 Unauthorized — approver `42` does not belong to transaction T1. [1](#0-0) [2](#0-1)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L85-91)
```typescript
  @Get()
  getTransactionApproversByTransactionId(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
  ): Promise<TransactionApprover[]> {
    return this.approversService.getVerifiedApproversByTransactionId(transactionId, user);
  }
```

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
