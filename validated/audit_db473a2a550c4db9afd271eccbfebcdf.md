### Title
Creator Can Manipulate Approver List During Active Approval Phase, Bypassing Organizational Approval Requirements

### Summary
The transaction creator can add or remove approvers from a transaction at any time — including after the transaction has entered `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` status — because neither `getCreatorsTransaction` nor the approver mutation endpoints enforce any transaction-status guard. A malicious creator can remove rejecting approvers, add themselves as the sole approver, and self-approve, fully circumventing the organizational multi-party approval process.

### Finding Description

**Root cause — missing status guard in `getCreatorsTransaction`**

`getCreatorsTransaction` is the shared authorization gate called before every approver mutation (create, update, delete). It only verifies creator identity; it never checks the transaction's current status:

```typescript
// back-end/apps/api/src/transactions/approvers/approvers.service.ts
async getCreatorsTransaction(transactionId, user, entityManager?) {
    // ...
    if (transaction.creatorKey?.userId !== user.id)
        throw new UnauthorizedException('Only the creator of the transaction is able to modify it');
    return transaction;   // ← no status check whatsoever
}
``` [1](#0-0) 

**Approver removal path — no status guard**

The `DELETE /:id` controller calls `getCreatorsTransaction` (identity only) then `removeTransactionApprover`, which calls `removeNode` — a raw SQL soft-delete that also does **not** update the parent threshold:

```typescript
// controller
await this.approversService.getCreatorsTransaction(transactionId, user);
await this.approversService.removeTransactionApprover(id);
``` [2](#0-1) 

```typescript
async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);
    const result = await this.removeNode(approver.id);   // ← no status check
    emitTransactionStatusUpdate(...);
}
``` [3](#0-2) 

**Approver creation path — no status guard**

`createTransactionApprovers` also calls only `getCreatorsTransaction` before inserting new approvers, with no status check: [4](#0-3) 

**Secondary issue — `removeNode` does not adjust parent threshold**

When a child approver is soft-deleted via `removeNode`, the parent's `threshold` column is never decremented. If a tree had `threshold=2, children=[A,B]` and B is deleted, the parent retains `threshold=2` with only one child, making the threshold permanently unreachable — a direct analog to the DAO "quorum can never be reached" sidenote in the external report: [5](#0-4) 

(Compare: `updateTransactionApprover` *does* adjust the parent threshold when a child is detached via `listId=null`, but `removeNode` — used by `removeTransactionApprover` — does not.) [6](#0-5) 

**Exploit flow**

1. Creator submits a transaction and sets approvers `[A, B]` with `threshold=2`.
2. Transaction enters `WAITING_FOR_SIGNATURES`; A and B both reject (`approved=false`).
3. Creator calls `DELETE /transactions/:txId/approvers/:A_id` and `DELETE /transactions/:txId/approvers/:B_id` — both succeed because `getCreatorsTransaction` only checks identity.
4. Creator calls `POST /transactions/:txId/approvers` to add themselves as the sole approver (`threshold=null`, `userId=creator`).
5. Creator calls `POST /transactions/:txId/approvers/approve` — `approveTransaction` finds the creator in the approver list and records approval.
6. Transaction proceeds toward execution with zero genuine third-party approvals.

### Impact Explanation
The organizational approval workflow — the primary trust mechanism in Organization Mode — is completely bypassable by the transaction creator. Any transaction requiring multi-party sign-off can be self-approved by the creator, enabling unauthorized movement of funds or unauthorized account/file changes on Hedera. This is a critical integrity failure in the system's trust model.

### Likelihood Explanation
The attacker is a **normal authenticated user** (the transaction creator) abusing documented, reachable API endpoints (`DELETE /transactions/:id/approvers/:id`, `POST /transactions/:id/approvers`, `POST /transactions/:id/approvers/approve`). No privileged credentials, leaked secrets, or cryptographic breaks are required. Any creator who faces rejection can trivially execute this sequence.

### Recommendation
Add a transaction-status guard inside `getCreatorsTransaction` (or as a dedicated guard called before every approver mutation) that rejects modifications once the transaction has left the `NEW` status:

```typescript
const IMMUTABLE_STATUSES = [
  TransactionStatus.WAITING_FOR_SIGNATURES,
  TransactionStatus.WAITING_FOR_EXECUTION,
  TransactionStatus.EXECUTED,
  TransactionStatus.FAILED,
  TransactionStatus.EXPIRED,
  TransactionStatus.CANCELED,
];
if (IMMUTABLE_STATUSES.includes(transaction.status))
  throw new BadRequestException('Approvers cannot be modified after approval has started');
```

Additionally, fix `removeNode` to decrement (or cap) the parent's `threshold` when a child is deleted, mirroring the logic already present in `updateTransactionApprover`. [1](#0-0) 

### Proof of Concept

```
# Step 1 – Creator creates transaction and sets threshold-2 approvers
POST /transactions
→ { id: 42, status: "NEW" }

POST /transactions/42/approvers
body: { approversArray: [{ threshold: 2, approvers: [{ userId: 10 }, { userId: 11 }] }] }

# Step 2 – Transaction enters WAITING_FOR_SIGNATURES; users 10 and 11 reject
POST /transactions/42/approvers/approve  (as user 10, approved: false)
POST /transactions/42/approvers/approve  (as user 11, approved: false)

# Step 3 – Creator removes both rejecting approvers (no status check blocks this)
DELETE /transactions/42/approvers/1   → 200 OK
DELETE /transactions/42/approvers/2   → 200 OK

# Step 4 – Creator adds themselves as sole approver
POST /transactions/42/approvers
body: { approversArray: [{ userId: <creator_id> }] }

# Step 5 – Creator self-approves
POST /transactions/42/approvers/approve  (as creator, approved: true)
→ Transaction proceeds with zero legitimate third-party approvals
```

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-239)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L417-428)
```typescript
            if (parent) {
              const newParentApproversLength = parent.approvers.length - 1;

              /* Soft delete the parent if there are no more children */
              if (newParentApproversLength === 0) {
                await transactionalEntityManager.softRemove(TransactionApprover, parent);
              } else if (newParentApproversLength < parent.threshold) {
                /* Update the parent threshold if the current one is more than the children */
                await transactionalEntityManager.update(TransactionApprover, parent.id, {
                  threshold: newParentApproversLength,
                });
              }
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L623-644)
```typescript
  /* Get the transaction by id and verifies that the user is the creator */
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
