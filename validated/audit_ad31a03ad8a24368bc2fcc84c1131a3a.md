### Title
Any Authenticated User Can Destroy Any Transaction Group via Missing Ownership Check and Non-Atomic Deletion in `removeTransactionGroup`

### Summary
`removeTransactionGroup` in `transaction-groups.service.ts` performs no upfront ownership check on the group itself. It deletes each `TransactionGroupItem` row from the database **before** calling `removeTransaction`, which is where the per-transaction ownership check lives. Because the entire operation is not wrapped in a database transaction, each failed ownership check leaves the already-deleted group items permanently gone. By repeating the call N+1 times (where N is the number of items), any authenticated user can drain all group items and then delete the group entity itself — destroying a transaction group they do not own.

### Finding Description

**Entry point** — `DELETE /transaction-groups/:id`, controller: [1](#0-0) 

The controller passes the request directly to `removeTransactionGroup(user, groupId)` with no additional guard beyond JWT authentication and email-verification status.

**Root cause** — `removeTransactionGroup` in the service: [2](#0-1) 

Three compounding flaws:

1. **No group-level ownership check.** The function fetches the group by ID (`findOneBy(TransactionGroup, { id })`) and proceeds without verifying that `user` created or owns it. Compare this with `cancelTransactionGroup`, which explicitly checks `item.transaction?.creatorKey?.userId === user.id` for every item before touching anything. [3](#0-2) 

2. **Group item is deleted before the ownership check fires.** Inside the loop, `this.dataSource.manager.remove(TransactionGroupItem, groupItem)` executes and commits to the database. Only then is `removeTransaction` called, which internally calls `getTransactionForCreator` and throws `UnauthorizedException` if the caller is not the creator. [4](#0-3) [5](#0-4) 

3. **No wrapping database transaction.** The deletions are not inside a `dataSource.transaction(...)` block, so the `remove(TransactionGroupItem, ...)` call that already committed cannot be rolled back when `removeTransaction` throws.

**Group ID enumeration** — A live `GET /transaction-groups` endpoint (commented "TESTING ONLY" but fully reachable) returns every group in the system to any authenticated user, giving the attacker the IDs needed to target victims. [6](#0-5) [7](#0-6) 

### Impact Explanation

**Per-call effect:** Each `DELETE /transaction-groups/:id` call removes exactly one `TransactionGroupItem` row from the victim's group (the first one returned by the `find` query) and then throws, leaving the group in a progressively more broken state.

**Full destruction after N+1 calls:** Once all N group items have been individually stripped away, the N+1th call finds an empty `groupItems` array, skips the loop entirely, and executes `this.dataSource.manager.remove(TransactionGroup, group)` — permanently deleting the group entity. [8](#0-7) 

Impact categories:
- **Unauthorized state change / data destruction**: An attacker can permanently delete any other user's transaction group and all its group items without owning any of the underlying transactions.
- **Integrity failure**: The underlying `Transaction` records survive (because `removeTransaction` throws before deleting them), but their `TransactionGroupItem` linkage is gone, orphaning them from the group workflow.

### Likelihood Explanation

- **Attacker preconditions**: A valid JWT (any registered, verified user). No admin role, no leaked secrets, no special network access required.
- **Group ID discovery**: Trivially obtained from the unauthenticated-by-design `GET /transaction-groups` endpoint.
- **Exploit complexity**: Sending N+1 sequential HTTP DELETE requests. Automatable with a single script loop.
- **No rate-limiting or anomaly detection** is visible in the codebase for this endpoint.

### Recommendation

1. **Add an upfront ownership check** before touching any data. Verify that every transaction in the group belongs to the requesting user (mirroring the pattern in `cancelTransactionGroup`).

2. **Wrap the entire deletion in a single database transaction** so that any failure rolls back all prior deletes atomically:
   ```typescript
   await this.dataSource.transaction(async manager => {
     // ownership check first, then remove items and transactions
   });
   ```

3. **Remove or properly guard `GET /transaction-groups`**. The "TESTING ONLY" endpoint must not be reachable in production. Apply at minimum an `AdminGuard` or remove the route entirely.

### Proof of Concept

**Setup**: Victim (user B) creates a transaction group with 2 items. Attacker (user A) is a separate verified user.

**Step 1 — Enumerate group IDs:**
```
GET /transaction-groups
Authorization: Bearer <attacker_jwt>
→ 200 OK  [{ "id": 7, ... }, ...]   # victim's group id = 7, has 2 items
```

**Step 2 — Strip item 1 (call 1):**
```
DELETE /transaction-groups/7
Authorization: Bearer <attacker_jwt>
→ 401 Unauthorized   (removeTransaction throws, but TransactionGroupItem #1 is already deleted)
```

**Step 3 — Strip item 2 (call 2):**
```
DELETE /transaction-groups/7
Authorization: Bearer <attacker_jwt>
→ 401 Unauthorized   (TransactionGroupItem #2 is now deleted)
```

**Step 4 — Delete the group (call 3):**
```
DELETE /transaction-groups/7
Authorization: Bearer <attacker_jwt>
→ 200 true   (groupItems array is empty, loop is skipped, group entity is removed)
```

**Result**: Victim's transaction group (id=7) is permanently deleted. The underlying `Transaction` records are orphaned. The attacker never owned any of the transactions.

### Citations

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L52-57)
```typescript
  /* TESTING ONLY: Get all transactions groups */
  @Get()
  @Serialize(TransactionGroupDto)
  getTransactionGroups(): Promise<TransactionGroup[]> {
    return this.transactionGroupsService.getTransactionGroups();
  }
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L107-113)
```typescript
  @Delete('/:id')
  removeTransactionGroup(
    @GetUser() user: User,
    @Param('id', ParseIntPipe) groupId: number,
  ): Promise<boolean> {
    return this.transactionGroupsService.removeTransactionGroup(user, groupId);
  }
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L36-38)
```typescript
  getTransactionGroups(): Promise<TransactionGroup[]> {
    return this.dataSource.manager.find(TransactionGroup);
  }
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L172-198)
```typescript
  async removeTransactionGroup(user: User, id: number): Promise<boolean> {
    const group = await this.dataSource.manager.findOneBy(TransactionGroup, { id });
    if (!group) {
      throw new Error('group not found');
    }
    const groupItems = await this.dataSource.manager.find(TransactionGroupItem, {
      relations: {
        group: true,
      },
      where: {
        group: {
          id: group.id,
        },
      },
    });
    for (const groupItem of groupItems) {
      const transactionId = groupItem.transactionId;
      await this.dataSource.manager.remove(TransactionGroupItem, groupItem);
      await this.transactionsService.removeTransaction(transactionId, user, false);
    }

    await this.dataSource.manager.remove(TransactionGroup, group);

    emitTransactionUpdate(this.notificationsPublisher, groupItems.map(gi => ({ entityId: gi.transactionId })));

    return true;
  }
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L206-212)
```typescript
    // Verify the user is the creator of all transactions in the group
    const allOwnedByUser = group.groupItems.every(
      item => item.transaction?.creatorKey?.userId === user.id,
    );
    if (!allOwnedByUser) {
      throw new UnauthorizedException('Only the creator can cancel all transactions in a group.');
    }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L628-631)
```typescript
  /* Remove the transaction for the given transaction id. */
  async removeTransaction(id: number, user: User, softRemove: boolean = true): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);

```
