Audit Report

## Title
Missing Group Ownership Check in `removeTransactionGroup` Enables Permanent Hard-Deletion of Any Transaction Group's Items by Any Authenticated User

## Summary
`DELETE /transaction-groups/:id` performs no ownership check on the target `TransactionGroup`. Inside `removeTransactionGroup`, each `TransactionGroupItem` is **hard-deleted** from the database before the per-transaction creator check runs. An attacker who is not the creator of the transactions can permanently corrupt the structure of any transaction group by destroying its `TransactionGroupItem` records, one per request, with no recovery path.

## Finding Description

The controller applies only `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — no `AdminGuard` and no group-ownership assertion. [1](#0-0) [2](#0-1) 

Inside `removeTransactionGroup`, the group is fetched with no ownership assertion: [3](#0-2) 

The loop then **hard-deletes** each `TransactionGroupItem` first, and only afterwards calls `removeTransaction`, which is where the creator check lives: [4](#0-3) 

`removeTransaction` delegates to `getTransactionForCreator`, which throws `UnauthorizedException` if the caller is not the creator: [5](#0-4) [6](#0-5) 

Because the `TransactionGroupItem` row is removed **before** `removeTransaction` is called, the exception arrives too late — the row is already gone. The `Transaction` record itself survives (the creator check blocks its deletion), and the `TransactionGroup` record also survives (the exception unwinds the loop before line 193 is reached). The net result is a permanently orphaned group: its `TransactionGroupItem` link is destroyed while the `Transaction` and `TransactionGroup` rows remain.

Contrast this with `cancelTransactionGroup`, which correctly calls `getTransactionGroup` (which enforces visibility) and then checks `allOwnedByUser` before touching any data: [7](#0-6) 

## Impact Explanation
Each call to `DELETE /transaction-groups/:id` by a non-owner permanently deletes exactly one `TransactionGroupItem` row (the first one in the iteration) before the exception fires. By repeating the call N times (where N is the number of items in the group), an attacker can strip all `TransactionGroupItem` records from any group. The `Transaction` rows are not deleted, but the group's structural integrity is permanently destroyed with no soft-delete or audit trail. There is no recovery path because `dataSource.manager.remove` issues a hard `DELETE`.

## Likelihood Explanation
The attack requires only a valid, verified user account — the same level of access needed to create a transaction group. No elevated privileges, no leaked credentials, and no race condition are required. The endpoint is publicly documented via Swagger. Any verified user in the system can target any group ID.

## Recommendation
Add an ownership check immediately after the group is fetched, before any mutation occurs. The pattern already used in `cancelTransactionGroup` is the correct model: load the group through `getTransactionGroup` (which enforces visibility) and verify that all transactions belong to the requesting user before issuing any deletes. Additionally, the entire loop should be wrapped in a database transaction so that a mid-loop failure cannot leave the database in a partially-mutated state.

## Proof of Concept

```
# Attacker (user B) targets a group owned by user A (groupId = 42, which has 3 items)

# Call 1: deletes TransactionGroupItem #1, then throws 401 (not creator of tx)
DELETE /transaction-groups/42   [Authorization: Bearer <user_B_token>]
→ HTTP 401 Unauthorized
→ DB: TransactionGroupItem for seq=1 is permanently gone

# Call 2: deletes TransactionGroupItem #2 (seq=1 is already gone, loop starts at seq=2)
DELETE /transaction-groups/42   [Authorization: Bearer <user_B_token>]
→ HTTP 401 Unauthorized
→ DB: TransactionGroupItem for seq=2 is permanently gone

# Call 3: deletes TransactionGroupItem #3
DELETE /transaction-groups/42   [Authorization: Bearer <user_B_token>]
→ HTTP 401 Unauthorized
→ DB: TransactionGroupItem for seq=3 is permanently gone

# Result: TransactionGroup #42 and its Transactions still exist,
# but all TransactionGroupItem rows are gone — the group is permanently corrupted.
```

### Citations

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L27-27)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L629-631)
```typescript
  async removeTransaction(id: number, user: User, softRemove: boolean = true): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);

```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L879-890)
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
```
