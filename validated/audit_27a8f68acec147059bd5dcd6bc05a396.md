All code references check out. Here is the audit report:

---

Audit Report

## Title
`removeTransactionGroup` Deletes `TransactionGroupItem` Rows Before Enforcing Creator Authorization, Enabling Partial State Corruption

## Summary
`removeTransactionGroup` in `transaction-groups.service.ts` performs no ownership check on the group before beginning deletion. It permanently removes each `TransactionGroupItem` row first, then calls `removeTransaction`, which enforces a creator-only check. Because the item deletions are committed outside any database transaction, a non-creator attacker can permanently orphan group items from a victim's group before the authorization check fires, leaving the group in an unrecoverable corrupted state.

## Finding Description

**Entry point — unauthenticated group enumeration**

`GET /transaction-groups` is guarded only by JWT + `VerifiedUserGuard` and returns every `TransactionGroup` in the database with no per-user filtering: [1](#0-0) [2](#0-1) 

**Entry point — unguarded delete**

`DELETE /transaction-groups/:id` carries no ownership guard beyond JWT + `VerifiedUserGuard`: [3](#0-2) [4](#0-3) 

**Destructive write before authorization check**

Inside `removeTransactionGroup`, the loop at lines 187–191 removes the `TransactionGroupItem` row on line 189 *before* calling `removeTransaction` on line 190. There is no wrapping database transaction: [5](#0-4) 

**Creator check fires too late**

`removeTransaction` immediately delegates to `getTransactionForCreator`, which throws `UnauthorizedException` when the caller is not the creator — but only after the item row has already been committed to the database: [6](#0-5) [7](#0-6) 

**Contrast with `cancelTransactionGroup`**

`cancelTransactionGroup` correctly calls `getTransactionGroup(user, groupId, false)` first, which filters items by the requesting user and then explicitly verifies `allOwnedByUser` before any mutation: [8](#0-7) 

`removeTransactionGroup` has no equivalent guard.

## Impact Explanation

For each loop iteration, the attacker causes one `TransactionGroupItem` row to be permanently deleted from the victim's group before `UnauthorizedException` is thrown and the loop aborts. The `TransactionGroup` record and the underlying `Transaction` records survive, but the group is now missing one or more of its items. Because no database transaction wraps the loop, there is no rollback. The victim's group-based workflow (sequential/atomic execution, signing coordination) is permanently broken for those items.

## Likelihood Explanation

- **Attacker preconditions**: any registered, verified user account — no admin or privileged role required.
- **Group ID discovery**: `GET /transaction-groups` returns all groups with no per-user filtering, making victim group IDs trivially enumerable.
- **Attack complexity**: a single HTTP `DELETE /transaction-groups/:id` request with a known group ID.
- **No rate limiting or confirmation** is required.
- The attack is fully deterministic and repeatable.

## Recommendation

1. **Wrap the entire deletion loop in a database transaction** so that any `UnauthorizedException` thrown by `removeTransaction` causes a full rollback of all item deletions.
2. **Add an ownership check at the entry of `removeTransactionGroup`**, analogous to `cancelTransactionGroup`, before any mutation begins — verify that the requesting user is the creator of all transactions in the group.
3. **Filter `getTransactionGroups`** to return only groups visible to the requesting user, eliminating the group-ID enumeration vector.

## Proof of Concept

```
# Step 1: Attacker (user B) enumerates all groups
GET /transaction-groups
Authorization: Bearer <attacker_jwt>
# Response includes victim's group with id=42

# Step 2: Attacker sends delete request for victim's group
DELETE /transaction-groups/42
Authorization: Bearer <attacker_jwt>

# Server execution path:
# 1. removeTransactionGroup finds group id=42 (no ownership check)
# 2. Loads all TransactionGroupItems for group 42
# 3. Loop iteration 1:
#    a. DELETE TransactionGroupItem row → COMMITTED to DB (no wrapping tx)
#    b. removeTransaction → getTransactionForCreator → UnauthorizedException thrown
# 4. Loop aborts; group 42 now has one fewer item permanently

# Result: victim's TransactionGroup exists but is missing a GroupItem row,
# leaving it in an unrecoverable corrupted state.
```

### Citations

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L36-38)
```typescript
  getTransactionGroups(): Promise<TransactionGroup[]> {
    return this.dataSource.manager.find(TransactionGroup);
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

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L204-212)
```typescript
    const group = await this.getTransactionGroup(user, groupId, false);

    // Verify the user is the creator of all transactions in the group
    const allOwnedByUser = group.groupItems.every(
      item => item.transaction?.creatorKey?.userId === user.id,
    );
    if (!allOwnedByUser) {
      throw new UnauthorizedException('Only the creator can cancel all transactions in a group.');
    }
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L27-27)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L53-57)
```typescript
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L629-630)
```typescript
  async removeTransaction(id: number, user: User, softRemove: boolean = true): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L879-888)
```typescript
  async getTransactionForCreator(id: number, user: User) {
    const transaction = await this.getTransactionById(id);

    if (!transaction) {
      throw new BadRequestException(ErrorCodes.TNF);
    }

    if (transaction.creatorKey?.userId !== user?.id) {
      throw new UnauthorizedException('Only the creator has access to this transaction');
    }
```
