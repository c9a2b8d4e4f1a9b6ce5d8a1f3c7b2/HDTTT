### Title
Unbounded Observer and Approver Arrays Enable Resource-Exhaustion DoS

### Summary
A transaction creator can add an arbitrarily large number of observers (and approvers) to any transaction they own. Because no maximum array size is enforced at the service layer, a malicious authenticated user can issue a single API call that triggers thousands of database writes and NATS notification emissions. When the transaction group is later fetched with `full=true`, the server must load all observers and approvers for every group item — an unbounded, attacker-controlled read.

### Finding Description
The external report describes a DoS where a malicious user adds as many *actions* as possible to each *proposal*, making iteration over those actions expensive and potentially blocking the system. The direct analog in this codebase is the **unbounded `userIds` array** accepted by `createTransactionObservers` and the **unbounded `approversArray`** (with recursive nesting) accepted by `createTransactionApprovers`.

**Observer path — `observers.service.ts`:**

```typescript
// observers.service.ts lines 49-53
for (const userId of dto.userIds) {
  if (!transaction.observers.some(o => o.userId === userId)) {
    const observer = this.repo.create({ userId, transactionId, role: Role.FULL });
    observers.push(observer);
  }
}
``` [1](#0-0) 

There is no `@ArrayMaxSize()` guard, no service-level length check, and no database-level constraint on the number of observers per transaction. A creator can pass `userIds: [1, 2, 3, …, 10000]` in a single POST and the loop will attempt to persist every entry.

**Approver path — `approvers.service.ts`:**

The `createApprover` inner function is called recursively for every element of `dtoApprover.approvers`, and that array is itself unbounded. There is no depth limit or total-node limit enforced before the recursive descent begins. [2](#0-1) 

**Expensive read path — `transaction-groups.service.ts`:**

When `getTransactionGroup` is called with `full=true`, it fetches signers, approvers, and observers for *every* transaction in the group in parallel, then maps them back. If a group has many items and each item has many observers/approvers, this becomes an O(n × m) database fan-out with no cap. [3](#0-2) 

### Impact Explanation
A malicious but authenticated organization member who is the creator of a transaction can:
1. Issue a single `POST /transactions/:id/observers` with thousands of `userIds`, causing thousands of DB inserts and NATS `emitTransactionUpdate` calls in one request.
2. Repeat this across many transactions, filling the `transaction_observer` table and degrading query performance for all users.
3. Force expensive reads every time any user fetches a full transaction group, because the server loads all observers/approvers for all group items without pagination or limits.

This degrades or denies service to all other organization members without requiring any special privilege beyond being a transaction creator.

### Likelihood Explanation
Any authenticated user in an organization can create transactions and is therefore the creator of those transactions. The attack requires only a crafted HTTP request — no special tooling, no token accumulation, and no race condition. The entry point is a standard REST endpoint reachable by any organization member.

### Recommendation
1. Add an `@ArrayMaxSize(N)` class-validator decorator to the `userIds` field of `CreateTransactionObserversDto` and to the `approversArray` field of `CreateTransactionApproversArrayDto` (e.g., max 50 observers, max 20 approvers).
2. Add a maximum recursion depth / total-node guard inside `createTransactionApprovers` before the recursive `createApprover` call begins.
3. Add a maximum group-item count check in the transaction group creation path.
4. Apply per-user rate limiting on the observer/approver creation endpoints using the existing `throttlers` infrastructure already present in the API service.

### Proof of Concept
```
POST /transactions/42/observers
Authorization: Bearer <valid_creator_token>
Content-Type: application/json

{
  "userIds": [1,2,3,4,...,5000]   // 5 000 entries, all valid user IDs
}
```

The server enters the loop at `observers.service.ts:49`, creates 5 000 `TransactionObserver` entities, calls `this.repo.save(observers)` (a single bulk insert of 5 000 rows), and then calls `emitTransactionUpdate` — all within one request. Repeating this across dozens of transactions saturates the PostgreSQL write path and the NATS event bus, blocking legitimate users from receiving timely transaction-status updates. [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L32-68)
```typescript
  async createTransactionObservers(
    user: User,
    transactionId: number,
    dto: CreateTransactionObserversDto,
  ): Promise<TransactionObserver[]> {
    const transaction = await this.entityManager.findOne(Transaction, {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user', 'observers'],
    });

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to delete it');

    const observers: TransactionObserver[] = [];

    for (const userId of dto.userIds) {
      if (!transaction.observers.some(o => o.userId === userId)) {
        const observer = this.repo.create({ userId, transactionId, role: Role.FULL });
        observers.push(observer);
      }
    }

    if (observers.length === 0) {
      return [];
    }

    try {
      const result = await this.repo.save(observers);

      emitTransactionUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);

      return result;
    } catch (error) {
      throw new BadRequestException(error.message);
    }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-250)
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
        const createApprover = async (dtoApprover: CreateTransactionApproverDto) => {
          /* Validate Approver's DTO */
          this.validateApprover(dtoApprover);

          /* Check if the approver already exists */
          if (await this.isNode(dtoApprover, transactionId, transactionalEntityManager))
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L145-167)
```typescript
    const transactionIds = group.groupItems.map(item => item.transactionId);

    const [
      transactionSigners,
      transactionApprovers,
      transactionObservers,
    ] = await Promise.all([
      this.transactionsService.getTransactionSignersForTransactions(transactionIds),
      this.transactionsService.getTransactionApproversForTransactions(transactionIds),
      this.transactionsService.getTransactionObserversForTransactions(transactionIds),
    ]);

    const signerMap = this.groupBy(transactionSigners, s => s.transactionId);
    const approverMap = this.groupBy(transactionApprovers, a => a.transactionId);
    const observerMap = this.groupBy(transactionObservers, o => o.transactionId);

    for (const groupItem of group.groupItems) {
      const txId = groupItem.transactionId;

      groupItem.transaction.signers = signerMap.get(txId) ?? [];
      groupItem.transaction.approvers = approverMap.get(txId) ?? [];
      groupItem.transaction.observers = observerMap.get(txId) ?? [];
    }
```
