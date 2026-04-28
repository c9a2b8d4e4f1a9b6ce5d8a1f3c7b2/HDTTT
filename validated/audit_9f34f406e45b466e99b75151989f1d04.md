### Title
Any Authenticated User Can Remove Any Transaction Approver Without Authorization

### Summary

`removeTransactionApprover()` in `approvers.service.ts` accepts only an approver `id` and performs no caller-identity check before soft-deleting the entire approver subtree. Every other mutating operation in the same service (`createTransactionApprovers`, `updateTransactionApprover`) calls `getCreatorsTransaction()` to verify the caller is the transaction creator. `removeTransactionApprover` skips this check entirely, so any authenticated user can silently strip all approvers from any transaction they did not create, bypassing the approval gate.

### Finding Description

**Root cause — missing authorization in `removeTransactionApprover`:** [1](#0-0) 

The function signature is `async removeTransactionApprover(id: number): Promise<void>` — no `user` parameter is accepted, so no caller-identity check is possible inside the function.

Compare to `updateTransactionApprover`, which correctly gates on creator identity: [2](#0-1) 

And `createTransactionApprovers`, which also gates on creator identity: [3](#0-2) 

The analogous `removeTransactionObserver` in the observers service correctly passes `user` and calls `getUpdateableObserver`, which enforces `transaction.creatorKey?.userId !== user.id`: [4](#0-3) [5](#0-4) 

The `ObserversController` DELETE endpoint passes `user` to the service; the approvers controller DELETE endpoint calls `removeTransactionApprover(id)` without a user argument, making authorization structurally impossible at the service layer.

The `removeNode` helper then soft-deletes the entire approver subtree rooted at the supplied `id`: [6](#0-5) 

Additionally, for child-node approvers whose `transactionId` column is `null` (they carry a `listId` instead), the subsequent notification emit fires with `entityId: null`: [7](#0-6) 

**Exploit flow:**

1. Attacker registers as a normal authenticated user (no privilege required).
2. Attacker learns a target transaction ID (e.g., from their own transaction list, or from any transaction they are an observer/signer of).
3. Attacker calls `GET /transactions/:transactionId/approvers` (or any read endpoint) to enumerate approver IDs.
4. Attacker calls `DELETE /transactions/:transactionId/approvers/:id` for each approver ID.
5. `removeTransactionApprover(id)` executes with no creator check; the entire approver tree is soft-deleted.
6. The transaction now has zero approvers; the approval gate is gone and the transaction can advance to `WAITING_FOR_EXECUTION` without any approval.

### Impact Explanation

Removing all approvers from a transaction eliminates the approval requirement entirely. A transaction that was gated behind a multi-user approval workflow (e.g., a high-value Hedera transfer, a node admin-key rotation, or a system-delete) can now be executed by its creator without any approver sign-off. This is an unauthorized state change that breaks the core multi-signature governance model of the platform.

### Likelihood Explanation

The attacker only needs a valid JWT (any registered user). Approver IDs are integers returned by standard read endpoints that any participant in the system can reach. No brute-forcing or privileged access is required. The DELETE endpoint is a standard REST call. The missing check is a single omission that is easy to exploit programmatically.

### Recommendation

Add the `user` parameter to `removeTransactionApprover` and call `getCreatorsTransaction` (or the equivalent inline check) before invoking `removeNode`, mirroring the pattern already used in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, user: User): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Resolve the root node to get the transactionId
  const root = await this.getRootNodeFromNode(approver.id);
  if (!root) throw new BadRequestException(ErrorCodes.RANF);

  // Enforce creator-only access
  await this.getCreatorsTransaction(root.transactionId, user);

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: root.transactionId }]);
  return result;
}
```

Update the approvers controller DELETE handler to pass `user` to the service, matching the pattern of `ObserversController`.

### Proof of Concept

**Preconditions:** Two accounts — `creator` (owns transaction T with approver A) and `attacker` (any authenticated user).

```
# Step 1 – attacker lists approvers for transaction T
GET /transactions/{T}/approvers
Authorization: Bearer <attacker_jwt>
# Response: [{ "id": 42, ... }]

# Step 2 – attacker deletes approver 42
DELETE /transactions/{T}/approvers/42
Authorization: Bearer <attacker_jwt>
# Response: 200 OK  (no authorization error)

# Step 3 – verify approver is gone
GET /transactions/{T}/approvers
# Response: []

# Result: transaction T now has no approvers;
# creator can advance it to execution without any approval.
```

Expected behavior: Step 2 should return `401 Unauthorized` because the attacker is not the creator of transaction T. Actual behavior: the approver is deleted successfully.

### Citations

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L239-239)
```typescript
    await this.getCreatorsTransaction(transactionId, user);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L393-394)
```typescript
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

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L133-140)
```typescript
  async removeTransactionObserver(id: number, user: User): Promise<boolean> {
    const observer = await this.getUpdateableObserver(id, user);

    await this.repo.remove(observer);

    emitTransactionUpdate(this.notificationsPublisher, [{ entityId: observer.transactionId }]);

    return true;
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L156-157)
```typescript
    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to update it');
```
