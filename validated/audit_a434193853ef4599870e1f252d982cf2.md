### Title
Any Authenticated User Can Permanently Corrupt Another User's Transaction Group via Missing Ownership Check in `removeTransactionGroup`

### Summary
`removeTransactionGroup` in `back-end/apps/api/src/transactions/groups/transaction-groups.service.ts` fetches a `TransactionGroup` by ID with no ownership check, then deletes all associated `TransactionGroupItem` records before delegating to `removeTransaction` (which does check ownership). Because the item deletions are committed outside any database transaction, an attacker who supplies a victim's group ID causes all group items to be permanently deleted while the group shell remains, making the group forever inaccessible to its owner.

### Finding Description

**Root cause — missing ownership gate before destructive mutation:**

`removeTransactionGroup` (lines 172–198) opens with a bare `findOneBy` that accepts any group ID:

```typescript
const group = await this.dataSource.manager.findOneBy(TransactionGroup, { id });
``` [1](#0-0) 

It then iterates over every `TransactionGroupItem` and removes each one **before** the ownership check:

```typescript
for (const groupItem of groupItems) {
  const transactionId = groupItem.transactionId;
  await this.dataSource.manager.remove(TransactionGroupItem, groupItem); // committed immediately
  await this.transactionsService.removeTransaction(transactionId, user, false); // ownership check here
}
``` [2](#0-1) 

`removeTransaction` calls `getTransactionForCreator`, which throws `UnauthorizedException` when the caller is not the creator: [3](#0-2) 

Because there is no wrapping database transaction around the loop, each `remove(TransactionGroupItem, …)` is committed to the database before `removeTransaction` throws. The loop aborts on the first item, but the `TransactionGroupItem` row for that item is already gone.

**Contrast with `cancelTransactionGroup`**, which correctly calls `getTransactionGroup(user, groupId, false)` first — a method that filters results through a user-scoped SQL query and throws `UnauthorizedException` when the group returns no visible items: [4](#0-3) 

`getTransactionGroup` enforces access by throwing when `groupItems.length === 0`: [5](#0-4) 

`removeTransactionGroup` never calls `getTransactionGroup`; it uses the unfiltered `findOneBy` instead.

**The controller exposes this endpoint to any verified user with no additional guard:** [6](#0-5) 

### Impact Explanation

After the attack, the victim's `TransactionGroup` row still exists in the database but has zero `TransactionGroupItem` rows. Every subsequent call to `getTransactionGroup` for that group returns the "You don't have permission to view this group" error because the item list is empty. The group is permanently inaccessible to its owner — the underlying transactions still exist but are no longer reachable through the group. This is an irreversible denial-of-service against the victim's group and the multi-signature workflow it coordinates.

### Likelihood Explanation

The attacker needs only a valid, verified account on the organization server — the same precondition as any normal user. `TransactionGroup` IDs are sequential integers, making them trivially enumerable. The attacker sends `DELETE /transaction-groups/<id>` for IDs 1, 2, 3 … until one belonging to another user is hit. No privileged access, no leaked credentials, and no special knowledge are required.

### Recommendation

Apply the same ownership gate used by `cancelTransactionGroup`: replace the bare `findOneBy` at the start of `removeTransactionGroup` with a call to `getTransactionGroup(user, id, false)`. This call already enforces user-scoped visibility and throws `UnauthorizedException` for groups the caller cannot see. Additionally, wrap the entire loop (item removal + transaction removal) in a single `dataSource.transaction(…)` block so that any mid-loop failure rolls back all deletions atomically.

### Proof of Concept

**Preconditions:**
- Victim (user A) has created a transaction group with ID `42` containing transactions they own.
- Attacker (user B) has a valid, verified session token.

**Steps:**
1. Attacker sends:
   ```
   DELETE /transaction-groups/42
   Authorization: Bearer <attacker_token>
   ```
2. `removeTransactionGroup` fetches group 42 (no ownership check).
3. For the first `TransactionGroupItem`, `remove(TransactionGroupItem, groupItem)` commits the deletion.
4. `removeTransaction(transactionId, attackerUser, false)` calls `getTransactionForCreator`, which throws `UnauthorizedException` because the attacker is not the creator.
5. The loop aborts. The `TransactionGroup` row for group 42 remains. The `TransactionGroupItem` row is gone.

**Expected outcome:** Victim calls `GET /transaction-groups/42` and receives `"You don't have permission to view this group"` permanently. The multi-signature workflow for that group is destroyed.

### Citations

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L139-141)
```typescript
    if (group.groupItems.length === 0) {
      throw new UnauthorizedException("You don't have permission to view this group.");
    }
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L172-173)
```typescript
  async removeTransactionGroup(user: User, id: number): Promise<boolean> {
    const group = await this.dataSource.manager.findOneBy(TransactionGroup, { id });
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L629-630)
```typescript
  async removeTransaction(id: number, user: User, softRemove: boolean = true): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);
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
