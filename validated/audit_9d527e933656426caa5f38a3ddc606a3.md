### Title
Missing Ownership Check in `removeTransactionGroup` Allows Any Authenticated User to Corrupt Any Transaction Group's State

### Summary

`removeTransactionGroup` in `transaction-groups.service.ts` accepts a `user` parameter but performs no ownership or authorization check on the target `TransactionGroup` before beginning destructive operations. Any authenticated, verified user can call `DELETE /transaction-groups/:id` against a group they do not own. Because `TransactionGroupItem` records are deleted **before** the per-transaction ownership check fires, the function always commits partial deletions — permanently corrupting the group's database state — even when the caller has no right to touch it.

### Finding Description

**Root cause:** `removeTransactionGroup` fetches the group by raw ID with no user filter and immediately begins deleting its items, relying on a downstream check inside `removeTransaction` that fires too late.

**Code path:**

`DELETE /transaction-groups/:id` → `TransactionGroupsController.removeTransactionGroup` → `TransactionGroupsService.removeTransactionGroup`

```
// transaction-groups.service.ts lines 172-198
async removeTransactionGroup(user: User, id: number): Promise<boolean> {
    const group = await this.dataSource.manager.findOneBy(TransactionGroup, { id });
    // ❌ No ownership check here — any group ID is accepted
    if (!group) { throw new Error('group not found'); }

    const groupItems = await this.dataSource.manager.find(TransactionGroupItem, { ... });

    for (const groupItem of groupItems) {
      const transactionId = groupItem.transactionId;
      await this.dataSource.manager.remove(TransactionGroupItem, groupItem); // ❌ deleted first
      await this.transactionsService.removeTransaction(transactionId, user, false); // ownership check fires here — too late
    }
    await this.dataSource.manager.remove(TransactionGroup, group);
    ...
}
```

`removeTransaction` delegates to `getTransactionForCreator`, which does enforce ownership:

```
// transactions.service.ts lines 879-891
if (transaction.creatorKey?.userId !== user?.id) {
    throw new UnauthorizedException('Only the creator has access to this transaction');
}
```

But by the time this check throws, the `TransactionGroupItem` row has already been hard-deleted from the database. There is no wrapping database transaction, so the deletion is committed immediately and cannot be rolled back.

**Contrast with `cancelTransactionGroup`** (lines 200–212), which correctly calls `getTransactionGroup(user, groupId, false)` — a query that filters results by user visibility — and then explicitly asserts `allOwnedByUser` before touching any data. `removeTransactionGroup` skips both of these steps entirely. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation

An attacker who is a legitimate, verified organization member (no admin role required) can:

1. Enumerate any group ID (integer-sequential, discoverable via `GET /transaction-groups/:id`).
2. Call `DELETE /transaction-groups/:id` against a group owned by another user.
3. For each `TransactionGroupItem` in the target group, the item is **permanently hard-deleted** from the database before the ownership check fires.
4. The `TransactionGroup` record and the underlying `Transaction` records survive (because `removeTransaction` throws), but all `TransactionGroupItem` linking rows are gone.
5. The legitimate owner's group is now in an unrecoverable inconsistent state: the group shell exists but has no items, making it invisible to the owner (since `getTransactionGroup` returns 401 when `groupItems.length === 0`) and impossible to cancel or manage.

This is **permanent, unrecoverable data corruption** of another user's transaction group — a critical integrity failure. [4](#0-3) [5](#0-4) 

### Likelihood Explanation

- **Attacker precondition**: A valid JWT for any verified organization user. No admin role, no leaked secrets, no special privileges.
- **Entry point**: `DELETE /transaction-groups/:id` — a standard REST endpoint, reachable by any authenticated client.
- **Discovery**: Group IDs are sequential integers. An attacker can probe IDs they did not create. `GET /transaction-groups` (marked "TESTING ONLY" but unguarded by any role check) returns all groups, making enumeration trivial.
- **Effort**: A single HTTP DELETE request per target group. [6](#0-5) [7](#0-6) 

### Recommendation

Apply the same ownership-first pattern used by `cancelTransactionGroup`:

1. **Before touching any data**, call `getTransactionGroup(user, id, false)`. This method already enforces user-scoped visibility — it returns 401 if the user has no items in the group — providing an implicit ownership gate.
2. **Wrap all deletions in a single database transaction** so that a mid-loop failure cannot leave `TransactionGroupItem` rows partially deleted while the `TransactionGroup` and `Transaction` records survive.
3. **Explicitly assert** that all transactions in the group belong to the requesting user (mirroring the `allOwnedByUser` check in `cancelTransactionGroup`) before any `remove` call.

```typescript
async removeTransactionGroup(user: User, id: number): Promise<boolean> {
  // Step 1: ownership-scoped fetch (throws 401 if user has no items)
  const group = await this.getTransactionGroup(user, id, false);

  // Step 2: assert full ownership
  const allOwnedByUser = group.groupItems.every(
    item => item.transaction?.creatorKey?.userId === user.id,
  );
  if (!allOwnedByUser) {
    throw new UnauthorizedException('Only the creator can delete a transaction group.');
  }

  // Step 3: wrap in a DB transaction
  await this.dataSource.transaction(async manager => {
    for (const groupItem of group.groupItems) {
      await manager.remove(TransactionGroupItem, groupItem);
      await manager.remove(Transaction, { id: groupItem.transactionId });
    }
    await manager.remove(TransactionGroup, group);
  });

  emitTransactionUpdate(...);
  return true;
}
``` [1](#0-0) 

### Proof of Concept

**Setup:**
- User A (victim) creates a transaction group → group ID = 5, containing transactions T1 and T2 (both owned by User A).
- User B (attacker) is a separate verified organization member.

**Steps:**
1. User B authenticates and obtains a valid JWT.
2. User B calls `GET /transaction-groups` (no role guard) to enumerate group IDs and discovers group ID 5.
3. User B sends: `DELETE /transaction-groups/5` with their JWT.
4. Server executes `removeTransactionGroup(userB, 5)`:
   - Fetches group 5 — succeeds (no ownership check).
   - Fetches `TransactionGroupItem` rows for group 5 — finds items for T1 and T2.
   - **Iteration 1**: Deletes `TransactionGroupItem` for T1 (committed). Calls `removeTransaction(T1, userB)` → `getTransactionForCreator` finds `T1.creatorKey.userId === userA.id !== userB.id` → throws `UnauthorizedException`.
5. Server returns HTTP 401 to User B.

**Observed state after the request:**
- `TransactionGroupItem` for T1: **permanently deleted**.
- `TransactionGroupItem` for T2: still exists.
- `TransactionGroup` (id=5): still exists.
- `Transaction` T1 and T2: still exist.

**Effect on User A:**
- `GET /transaction-groups/5` now returns only one item (T2). If T1 was the only item, the group returns 401 ("You don't have permission to view this group") — the group is effectively invisible and unmanageable by its legitimate owner. [4](#0-3) [8](#0-7) [5](#0-4)

### Citations

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L139-141)
```typescript
    if (group.groupItems.length === 0) {
      throw new UnauthorizedException("You don't have permission to view this group.");
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

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L200-212)
```typescript
  async cancelTransactionGroup(
    user: User,
    groupId: number,
  ): Promise<CancelGroupResultDto> {
    const group = await this.getTransactionGroup(user, groupId, false);

    // Verify the user is the creator of all transactions in the group
    const allOwnedByUser = group.groupItems.every(
      item => item.transaction?.creatorKey?.userId === user.id,
    );
    if (!allOwnedByUser) {
      throw new UnauthorizedException('Only the creator can cancel all transactions in a group.');
    }
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
