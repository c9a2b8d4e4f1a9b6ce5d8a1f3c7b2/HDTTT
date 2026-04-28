All referenced code has been verified against the actual repository. Here is the audit result:

---

Audit Report

## Title
Manual Transaction Permanently Locked When Creator Account Is Removed — Overly Strict Access Control on `executeTransaction`

## Summary
`getTransactionForCreator` enforces a hard creator-only identity check with no admin bypass. All three lifecycle-management operations — `executeTransaction`, `archiveTransaction`, and `cancelTransaction` — call this function unconditionally. When an admin removes the creator user (a routine operation), the creator's `UserKey` is soft-deleted, causing `getTransactionForCreator` to throw `UnauthorizedException` for every caller. A fully-signed manual transaction in `WAITING_FOR_EXECUTION` state can no longer be executed, canceled, or archived through the API by anyone, including admins.

## Finding Description

**Root cause — `getTransactionForCreator` has no admin bypass:** [1](#0-0) 

The check `transaction.creatorKey?.userId !== user?.id` is unconditional. When `removeUser` soft-deletes the `UserKey` via `softDelete(UserKey, { userId: id })`, TypeORM stops loading the soft-deleted relation, so `transaction.creatorKey` becomes `null` on subsequent loads. `null?.userId` is `undefined`, which never equals any authenticated user's numeric `id`, so the `UnauthorizedException` fires for every caller. [2](#0-1) 

All three lifecycle operations call `getTransactionForCreator` unconditionally:

- `executeTransaction` — [3](#0-2) 
- `archiveTransaction` — [4](#0-3) 
- `cancelTransactionWithOutcome` — [5](#0-4) 

The controller exposes these as standard `PATCH` endpoints with no admin-override path: [6](#0-5) 

The scheduler explicitly skips manual transactions, so they are never auto-executed: [7](#0-6) 

**Partial natural resolution — expiry cron:** The chain service does run a cron every 10 seconds that transitions `WAITING_FOR_EXECUTION` transactions to `EXPIRED` once their `validStart` is more than 3 minutes in the past: [8](#0-7) 

This means the transaction is **not permanently stuck indefinitely** — it will eventually expire. However, the execution window (the period during which the transaction could be submitted to Hedera) is irrecoverably lost, and no admin can intervene to execute or cleanly cancel/archive it before expiry.

## Impact Explanation
A fully-signed manual transaction that has collected signatures from multiple organization members cannot be submitted to Hedera if the creator is removed before execution. The transaction will eventually auto-expire via the scheduler cron, but the execution opportunity is permanently lost. All signing effort is wasted. In organizations using manual transactions for time-sensitive Hedera operations (treasury transfers, account updates), this constitutes an operational disruption with no in-system recovery path for the execution window. No on-chain funds are directly locked since the transaction was never submitted.

## Likelihood Explanation
The trigger is a normal, expected admin operation: removing a departed employee or a compromised account (`DELETE /users/:id` guarded by `AdminGuard`). No attacker capability is required. Any organization that uses manual transactions and ever removes a user who created one will silently hit this. The admin has no warning that removing the user will prevent execution of their pending manual transactions. [9](#0-8) 

## Recommendation
1. **Add an admin bypass to `getTransactionForCreator`** (or create a separate `getTransactionForAdmin` variant): if the requesting user has `admin: true`, skip the creator identity check and return the transaction directly.
2. **Alternatively**, decouple the authorization check from the data-fetch in `executeTransaction`, `archiveTransaction`, and `cancelTransaction` so that admins can call a separate admin-scoped endpoint (e.g., `PATCH /admin/transactions/execute/:id`) that uses `getTransactionWithVerifiedAccess` or a role-checked variant instead.
3. **Consider cascading cleanup**: when `removeUser` is called, check for pending manual transactions owned by that user and either notify admins or automatically reassign creator ownership to an admin key before deletion.

## Proof of Concept
1. Admin creates User A; User A registers a key and creates a manual transaction (`isManual: true`) via `POST /transactions`.
2. Other org members sign the transaction; it transitions to `WAITING_FOR_EXECUTION`.
3. Admin calls `DELETE /users/:userAId` — `removeUser` soft-deletes User A's `UserKey` and the user record.
4. Any user (including admins) calls `PATCH /transactions/execute/:id`. `getTransactionById` loads the transaction; the `creatorKey` relation is `null` (soft-deleted). `null?.userId` is `undefined`; `undefined !== admin.id` → `UnauthorizedException` thrown.
5. Same result for `PATCH /transactions/cancel/:id` and `PATCH /transactions/archive/:id`.
6. The transaction sits in `WAITING_FOR_EXECUTION` until the `validStart` window passes, at which point the expiry cron marks it `EXPIRED`. The Hedera transaction is never submitted. [10](#0-9) [11](#0-10)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L110-124)
```typescript
  async getTransactionById(id: number | TransactionId): Promise<Transaction> {
    if (!id) return null;

    const transactions = await this.repo.find({
      where: typeof id == 'number' ? { id } : { transactionId: id.toString() },
      relations: [
        'creatorKey',
        'creatorKey.user',
        'observers',
        'comments',
        'groupItem',
        'groupItem.group',
      ],
      order: { id: 'DESC' },
    });
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L659-663)
```typescript
  async cancelTransactionWithOutcome(
    id: number,
    user: User,
  ): Promise<CancelTransactionOutcome> {
    const transaction = await this.getTransactionForCreator(id, user);
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L708-709)
```typescript
  async archiveTransaction(id: number, user: User): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L736-737)
```typescript
  async executeTransaction(id: number, user: User): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L879-891)
```typescript
  async getTransactionForCreator(id: number, user: User) {
    const transaction = await this.getTransactionById(id);

    if (!transaction) {
      throw new BadRequestException(ErrorCodes.TNF);
    }

    if (transaction.creatorKey?.userId !== user?.id) {
      throw new UnauthorizedException('Only the creator has access to this transaction');
    }

    return transaction;
  }
```

**File:** back-end/apps/api/src/users/users.service.ts (L156-170)
```typescript
  async removeUser(id: number): Promise<boolean> {
    const user = await this.getUser({ id });

    if (!user) {
      throw new BadRequestException(ErrorCodes.UNF);
    }

    // Soft-delete all user keys first
    await this.repo.manager.softDelete(UserKey, { userId: id });

    // Then soft-delete the user
    await this.repo.softRemove(user);

    return true;
  }
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L264-286)
```typescript
  @Patch('/archive/:id')
  async archiveTransaction(
    @GetUser() user,
    @Param('id', ParseIntPipe) id: number,
  ): Promise<boolean> {
    return this.transactionsService.archiveTransaction(id, user);
  }

  @ApiOperation({
    summary: 'Send a transaction for execution',
    description: 'Send a manual transaction to the chain service that will execute it',
  })
  @ApiResponse({
    status: 200,
    type: Boolean,
  })
  @Patch('/execute/:id')
  async executeTransaction(
    @GetUser() user,
    @Param('id', ParseIntPipe) id: number,
  ): Promise<boolean> {
    return this.transactionsService.executeTransaction(id, user);
  }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L100-128)
```typescript
  @Cron(CronExpression.EVERY_10_SECONDS, {
    name: 'status_update_expired_transactions',
  })
  async handleExpiredTransactions() {
    const result = await this.transactionRepo
      .createQueryBuilder()
      .update(Transaction)
      .set({ status: TransactionStatus.EXPIRED })
      .where('status IN (:...statuses) AND validStart < :before', {
        statuses: [
          TransactionStatus.NEW,
          TransactionStatus.REJECTED,
          TransactionStatus.WAITING_FOR_EXECUTION,
          TransactionStatus.WAITING_FOR_SIGNATURES,
        ],
        before: this.getThreeMinutesBefore(),
      })
      .returning(['id'])
      .execute();

    if (result.raw.length > 0) {
      emitTransactionStatusUpdate(
        this.notificationsPublisher,
        result.raw.map(t => ({
          entityId: t.id,
        })),
      );
    }
  }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L352-358)
```typescript
  addExecutionTimeout(transaction: Transaction) {
    const name = `execution_timeout_${transaction.id}`;

    if (this.schedulerRegistry.doesExist('timeout', name)) return;

    if (transaction.isManual) return;

```

**File:** back-end/apps/api/src/users/users.controller.ts (L118-123)
```typescript
  @UseGuards(AdminGuard)
  @Delete('/:id')
  removeUser(@GetUser() user: User, @Param('id', ParseIntPipe) id: number): Promise<boolean> {
    if (user.id === id) throw new BadRequestException(ErrorCodes.CRYFO);
    return this.usersService.removeUser(id);
  }
```
