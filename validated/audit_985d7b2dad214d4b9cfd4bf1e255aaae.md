### Title
Any Authenticated User Can Corrupt Another User's Transaction Group via Missing Ownership Check in `removeTransactionGroup`

### Summary

`TransactionGroupsService#removeTransactionGroup` fetches a `TransactionGroup` by ID without verifying the requesting user owns it. It then deletes `TransactionGroupItem` records before the per-transaction ownership check in `removeTransaction` can reject the request. Because there is no database transaction wrapping the loop, the already-deleted `TransactionGroupItem` rows are never rolled back, leaving the victim's group in a permanently corrupted state.

### Finding Description

**Root cause — missing ownership gate on the group itself**

`removeTransactionGroup` at line 172 of `back-end/apps/api/src/transactions/groups/transaction-groups.service.ts` fetches the group purely by ID:

```typescript
const group = await this.dataSource.manager.findOneBy(TransactionGroup, { id });
```

No check is made that `user` owns this group. [1](#0-0) 

**Premature deletion before the ownership check fires**

Inside the loop, `TransactionGroupItem` is removed from the database *before* `removeTransaction` is called:

```typescript
for (const groupItem of groupItems) {
  const transactionId = groupItem.transactionId;
  await this.dataSource.manager.remove(TransactionGroupItem, groupItem); // deleted here
  await this.transactionsService.removeTransaction(transactionId, user, false); // ownership checked here
}
``` [2](#0-1) 

`removeTransaction` delegates to `getTransactionForCreator`, which correctly enforces that only the creator may delete a transaction:

```typescript
if (transaction.creatorKey?.userId !== user?.id) {
  throw new UnauthorizedException('Only the creator has access to this transaction');
}
``` [3](#0-2) 

When the attacker does not own the transactions in the target group, `removeTransaction` throws `UnauthorizedException`. The loop aborts, but the `TransactionGroupItem` row that was already removed is **not restored** — there is no wrapping database transaction.

**Contrast with `cancelTransactionGroup`**

The sibling method `cancelTransactionGroup` correctly calls `getTransactionGroup(user, groupId, false)` first, which runs a user-scoped SQL query and throws `UnauthorizedException` if the user has no access to any item in the group. `removeTransactionGroup` skips this gate entirely. [4](#0-3) 

**Exposed endpoint**

The `DELETE /transaction-groups/:id` controller route passes the caller's user object directly to `removeTransactionGroup` with no additional guard: [5](#0-4) 

### Impact Explanation

An attacker can permanently corrupt any other user's transaction group by severing the `TransactionGroupItem` links between the group and its transactions. The `TransactionGroup` and `Transaction` records remain, but the join records are gone, making the group appear incomplete or broken to its owner. Because group IDs are sequential integers, no prior knowledge of the victim's data is required beyond a valid session token.

### Likelihood Explanation

Any authenticated, verified user can exploit this. The attacker needs only:
1. A valid JWT (normal login).
2. A guessable or enumerable group ID (sequential integers starting from 1).

No privileged role, leaked credential, or social engineering is required.

### Recommendation

1. **Add an ownership check at the top of `removeTransactionGroup`** — mirror the pattern used in `cancelTransactionGroup`: call `getTransactionGroup(user, id, false)` first, which already throws `UnauthorizedException` when the user has no access to the group's transactions.

2. **Wrap the entire deletion loop in a database transaction** so that a mid-loop failure rolls back all already-deleted `TransactionGroupItem` rows atomically.

```typescript
async removeTransactionGroup(user: User, id: number): Promise<boolean> {
  // Step 1: verify access (throws if user has no access)
  const group = await this.getTransactionGroup(user, id, false);

  // Step 2: perform all mutations atomically
  await this.dataSource.transaction(async manager => {
    const groupItems = await manager.find(TransactionGroupItem, {
      where: { group: { id: group.id } },
      relations: { group: true },
    });
    for (const groupItem of groupItems) {
      await manager.remove(TransactionGroupItem, groupItem);
      await this.transactionsService.removeTransaction(groupItem.transactionId, user, false);
    }
    await manager.remove(TransactionGroup, group);
  });

  emitTransactionUpdate(...);
  return true;
}
```

### Proof of Concept

**Setup**
- User A (victim) is authenticated and creates a transaction group (ID = 5) containing transactions T1, T2, T3, all owned by User A.
- User B (attacker) is authenticated but owns no transactions in group 5.

**Exploit**
```
DELETE /transaction-groups/5
Authorization: Bearer <User B's JWT>
```

**Execution trace**

| Step | Code | Result |
|------|------|--------|
| 1 | `findOneBy(TransactionGroup, { id: 5 })` | Group 5 found — no ownership check |
| 2 | `find(TransactionGroupItem, ...)` | Returns [GI1→T1, GI2→T2, GI3→T3] |
| 3 | `manager.remove(TransactionGroupItem, GI1)` | **GI1 deleted from DB** |
| 4 | `removeTransaction(T1.id, userB, false)` | Throws `UnauthorizedException` — User B is not creator |
| 5 | Loop aborts; GI2, GI3 untouched; Group 5 and T1–T3 remain | — |

**Outcome**: User A's group 5 now permanently lacks GI1. The group is in an inconsistent state. User A observes a corrupted group with a missing transaction link. The attacker can repeat this for GI2 and GI3 in subsequent requests, eventually stripping all group items from the group.

### Citations

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L172-176)
```typescript
  async removeTransactionGroup(user: User, id: number): Promise<boolean> {
    const group = await this.dataSource.manager.findOneBy(TransactionGroup, { id });
    if (!group) {
      throw new Error('group not found');
    }
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L187-191)
```typescript
    for (const groupItem of groupItems) {
      const transactionId = groupItem.transactionId;
      await this.dataSource.manager.remove(TransactionGroupItem, groupItem);
      await this.transactionsService.removeTransaction(transactionId, user, false);
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L886-888)
```typescript
    if (transaction.creatorKey?.userId !== user?.id) {
      throw new UnauthorizedException('Only the creator has access to this transaction');
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
