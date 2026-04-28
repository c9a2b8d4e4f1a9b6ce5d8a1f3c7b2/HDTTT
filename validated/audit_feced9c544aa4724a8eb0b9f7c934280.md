### Title
Missing Transaction Status Check in Approver Mutation Endpoints Allows Bypassing Multi-Party Approval Requirements

### Summary
The `createTransactionApprovers`, `updateTransactionApprover`, and `removeTransactionApprover` functions in `ApproversService` do not validate the transaction's current status before mutating the approver set. A transaction creator (a normal authenticated user) can add, remove, or replace approvers on a transaction that is already in `WAITING_FOR_EXECUTION` state — after all required approvals have been collected — causing the transaction to execute on the Hedera network without the originally required multi-party authorization.

### Finding Description

The root cause is in `getCreatorsTransaction` (the only guard called before approver mutations), which exclusively checks creator ownership and never inspects `transaction.status`: [1](#0-0) 

All three mutation paths call this guard and nothing else for status validation:

**`createTransactionApprovers`** — line 239 calls `getCreatorsTransaction`, then immediately inserts new approvers with no status check: [2](#0-1) 

**`removeTransactionApprover`** — no status check at all, soft-deletes the approver node unconditionally: [3](#0-2) 

**`updateTransactionApprover`** — when `dto.userId` is supplied, it clears `signature`, `userKeyId`, and `approved` from the existing approver record with no status check: [4](#0-3) 

The controller wires these directly with only a creator-ownership check: [5](#0-4) 

**Exploit flow (bypass approval requirement):**

1. Creator creates a transaction requiring approval from users A and B (threshold 2).
2. A and B both approve → the scheduler promotes the transaction to `WAITING_FOR_EXECUTION`.
3. Before the chain service executes it, the creator calls `DELETE /transactions/:id/approvers/:approverId` to remove approver B.
4. `removeTransactionApprover` soft-deletes B's approval record with no status guard.
5. The transaction remains in `WAITING_FOR_EXECUTION` and the chain service submits it to the Hedera network — now with only one approval on record.

**Exploit flow (wipe an existing approval):**

1. Same setup: transaction in `WAITING_FOR_EXECUTION` after A approved.
2. Creator calls `PATCH /transactions/:id/approvers/:approverId` with `{ userId: newUserId }`.
3. `updateTransactionApprover` clears `signature`, `userKeyId`, and `approved` for the approver record (lines 501–506), then emits a status-update event.
4. The transaction executes with zero valid approvals on record.

### Impact Explanation

The multi-party approval workflow is the primary authorization control preventing a single user from unilaterally executing a transaction that requires organizational sign-off. Bypassing it means:

- A transaction creator can execute any transaction on the Hedera network (account updates, node operations, file mutations, etc.) after obtaining the required approvals and then immediately stripping them, leaving no audit trail of valid authorization.
- The approval records stored in the database no longer reflect the actual authorization state at execution time, corrupting the integrity of the audit log.
- This is a **critical integrity failure in the trust model** of the system.

### Likelihood Explanation

The attacker is the transaction creator — a normal authenticated user with no elevated privileges. The attack requires:
1. Creating a transaction with an approval requirement (normal workflow).
2. Waiting for approvers to approve (normal workflow).
3. Calling a standard REST endpoint (`DELETE` or `PATCH` on `/approvers`) before the chain service picks up the transaction.

The window between `WAITING_FOR_EXECUTION` promotion and chain-service execution is non-zero (scheduler polling interval). No special tooling is needed — a standard HTTP client suffices. Likelihood is **high**.

### Recommendation

Add a terminal/active-state guard inside `getCreatorsTransaction` (or as a dedicated helper called at the top of each mutation method) that rejects modifications when the transaction is in `WAITING_FOR_EXECUTION`, `EXECUTED`, `EXPIRED`, `CANCELED`, `FAILED`, or `ARCHIVED` states:

```typescript
const IMMUTABLE_STATUSES = [
  TransactionStatus.WAITING_FOR_EXECUTION,
  TransactionStatus.EXECUTED,
  TransactionStatus.EXPIRED,
  TransactionStatus.CANCELED,
  TransactionStatus.FAILED,
  TransactionStatus.ARCHIVED,
];

if (IMMUTABLE_STATUSES.includes(transaction.status)) {
  throw new BadRequestException('Cannot modify approvers: transaction is no longer in a mutable state');
}
```

Apply this check in `createTransactionApprovers`, `updateTransactionApprover`, and `removeTransactionApprover` (or centrally in `getCreatorsTransaction` with an optional flag).

### Proof of Concept

```
# Step 1 – Create transaction with 2-approver threshold
POST /transactions
→ { id: 42, status: "WAITING FOR SIGNATURES" }

# Step 2 – Add approvers A (userId=10) and B (userId=11) with threshold 2
POST /transactions/42/approvers
Body: { approversArray: [{ threshold: 2, approvers: [{ userId: 10 }, { userId: 11 }] }] }

# Step 3 – User 10 approves, User 11 approves
# Scheduler promotes transaction to WAITING_FOR_EXECUTION (status = "WAITING FOR EXECUTION")

# Step 4 – Creator removes approver B (approverId=7) — NO status check blocks this
DELETE /transactions/42/approvers/7
→ 200 OK, true

# Result: transaction executes on Hedera with only 1 approval on record,
# bypassing the 2-of-2 approval requirement.
``` [3](#0-2) [6](#0-5) [4](#0-3) [5](#0-4)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-244)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);

    const approvers: TransactionApprover[] = [];

    try {
      await this.dataSource.transaction(async transactionalEntityManager => {
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L489-517)
```typescript
        } else if (typeof dto.userId === 'number') {
          /* Check if the approver is a tree */
          if (typeof approver.threshold === 'number') throw new Error(this.APPROVER_IS_TREE);

          /* Check if the user exists */
          const userCount = await transactionalEntityManager.count(User, {
            where: { id: dto.userId },
          });
          if (userCount === 0) throw new Error(this.USER_NOT_FOUND(dto.userId));

          /* Update the user */
          if (approver.userId !== dto.userId) {
            const data: DeepPartial<TransactionApprover> = {
              userId: dto.userId,
              userKeyId: undefined,
              signature: undefined,
              approved: undefined,
            };

            approver.userKeyId = undefined;
            approver.signature = undefined;
            approver.approved = undefined;

            await transactionalEntityManager.update(TransactionApprover, approver.id, data);
            approver.userId = dto.userId;
            updated = true;

            return approver;
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
