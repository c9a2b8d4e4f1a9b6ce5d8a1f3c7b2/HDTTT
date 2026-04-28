All referenced code has been verified directly in the repository. The vulnerability is confirmed.

---

Audit Report

## Title
Any Authenticated User Can Corrupt Another User's Transaction Group via Missing Ownership Check in `removeTransactionGroup`

## Summary
`TransactionGroupsService#removeTransactionGroup` fetches a `TransactionGroup` by ID with no ownership verification. It then deletes `TransactionGroupItem` rows inside a loop before the per-transaction ownership check in `removeTransaction` can reject the request. Because no database transaction wraps the loop, already-deleted `TransactionGroupItem` rows are never rolled back, permanently corrupting the victim's group.

## Finding Description

**Missing ownership gate on the group**

`removeTransactionGroup` at line 173 fetches the group purely by ID:

```typescript
const group = await this.dataSource.manager.findOneBy(TransactionGroup, { id });
```

No check is made that `user` owns or has any relation to this group. [1](#0-0) 

**Premature deletion before the ownership check fires**

Inside the loop, `TransactionGroupItem` is removed from the database *before* `removeTransaction` is called:

```typescript
for (const groupItem of groupItems) {
  const transactionId = groupItem.transactionId;
  await this.dataSource.manager.remove(TransactionGroupItem, groupItem); // deleted here
  await this.transactionsService.removeTransaction(transactionId, user, false); // ownership checked here
}
``` [2](#0-1) 

When the attacker does not own the transactions in the target group, `removeTransaction` (which delegates to `getTransactionForCreator`) throws `UnauthorizedException`. The loop aborts, but the `TransactionGroupItem` row already removed is **not restored** — there is no wrapping database transaction.

**Contrast with `cancelTransactionGroup`**

The sibling method `cancelTransactionGroup` correctly calls `getTransactionGroup(user, groupId, false)` first, which runs a user-scoped SQL query and throws `UnauthorizedException` if the user has no access to any item in the group. `removeTransactionGroup` skips this gate entirely. [3](#0-2) 

**Exposed endpoint**

The `DELETE /transaction-groups/:id` controller route passes the caller's user object directly to `removeTransactionGroup` with no additional ownership guard beyond JWT authentication and email verification: [4](#0-3) 

## Impact Explanation
An attacker can permanently corrupt any other user's transaction group by severing the `TransactionGroupItem` links between the group and its transactions. The `TransactionGroup` and `Transaction` records remain, but the join records are gone, making the group appear incomplete or broken to its owner. The corruption is irreversible without direct database intervention.

## Likelihood Explanation
Any authenticated, verified user can exploit this. The attacker needs only:
1. A valid JWT (normal login).
2. A guessable or enumerable group ID — the `id` column is a sequential integer (standard auto-increment primary key).

No privileged role, leaked credential, or social engineering is required.

## Recommendation
1. **Add an ownership check before any mutation.** Call `getTransactionGroup(user, id, false)` at the top of `removeTransactionGroup`, exactly as `cancelTransactionGroup` does. This will throw `UnauthorizedException` if the requesting user has no access to any item in the group.
2. **Wrap the entire deletion loop in a database transaction.** Use `this.dataSource.transaction(async manager => { ... })` so that if any step fails (e.g., `removeTransaction` throws), all prior deletions within that call are rolled back atomically.
3. **Delete `TransactionGroupItem` after, not before, the ownership check.** Reorder the loop so `removeTransaction` (which validates ownership) is called first, and the `TransactionGroupItem` row is only removed after the ownership check passes.

## Proof of Concept
```
1. Attacker (user A) logs in and obtains a valid JWT.
2. Attacker sends: DELETE /transaction-groups/42
   (where group 42 belongs to victim user B)
3. Server enters removeTransactionGroup with id=42.
4. Group is fetched with no ownership check (line 173).
5. Loop begins over groupItems of group 42.
6. First iteration: TransactionGroupItem row is deleted (line 189).
7. removeTransaction is called; getTransactionForCreator detects
   user A is not the creator → throws UnauthorizedException.
8. Loop aborts. No DB transaction wraps the loop.
9. The deleted TransactionGroupItem row is NOT restored.
10. Victim's group 42 now has one fewer item — permanently corrupted.
11. Attacker repeats with different group IDs (1, 2, 3, ...) to
    corrupt all groups on the platform.
``` [5](#0-4)

### Citations

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

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L200-204)
```typescript
  async cancelTransactionGroup(
    user: User,
    groupId: number,
  ): Promise<CancelGroupResultDto> {
    const group = await this.getTransactionGroup(user, groupId, false);
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
