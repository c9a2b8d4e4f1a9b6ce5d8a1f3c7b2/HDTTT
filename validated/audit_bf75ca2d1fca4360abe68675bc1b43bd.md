All three code paths are confirmed. Here is the audit report:

---

Audit Report

## Title
Any Authenticated User Can Destroy Any Transaction Group via Missing Ownership Check and Non-Atomic Deletion in `removeTransactionGroup`

## Summary
`removeTransactionGroup` in `transaction-groups.service.ts` performs no ownership check on the group before operating on it. Inside the deletion loop, each `TransactionGroupItem` row is permanently deleted from the database *before* the per-transaction ownership check fires in `removeTransaction`. Because the entire operation is not wrapped in a database transaction, the already-committed `TransactionGroupItem` deletion cannot be rolled back when `removeTransaction` throws `UnauthorizedException`. By repeating the `DELETE /transaction-groups/:id` call N+1 times (N = number of group items), any authenticated user can strip all group items one-by-one and then delete the group entity itself — destroying a transaction group they do not own.

## Finding Description

**Entry point** — `DELETE /transaction-groups/:id` [1](#0-0) 

The controller is guarded only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. No ownership or role check is applied before delegating to the service. [2](#0-1) 

**Root cause — `removeTransactionGroup`** [3](#0-2) 

Three compounding flaws:

**Flaw 1 — No group-level ownership check.** The function fetches the group by ID and proceeds immediately without verifying that the calling user created or owns it. [4](#0-3) 

Compare with `cancelTransactionGroup`, which explicitly checks `item.transaction?.creatorKey?.userId === user.id` for every item before touching anything: [5](#0-4) 

**Flaw 2 — `TransactionGroupItem` is deleted before the ownership check fires.** Inside the loop, `this.dataSource.manager.remove(TransactionGroupItem, groupItem)` executes and commits to the database. Only then is `removeTransaction` called, which internally calls `getTransactionForCreator` and throws `UnauthorizedException` if the caller is not the creator. [6](#0-5) [7](#0-6) 

**Flaw 3 — No wrapping database transaction.** The deletions are not inside a `dataSource.transaction(...)` block, so the `remove(TransactionGroupItem, ...)` call that already committed cannot be rolled back when `removeTransaction` throws.

**Group ID enumeration** — A `GET /transaction-groups` endpoint (commented "TESTING ONLY" but fully reachable under the same auth guards) returns every group in the system to any authenticated user, trivially supplying the attacker with victim group IDs. [8](#0-7) [9](#0-8) 

## Impact Explanation

**Per-call effect:** Each `DELETE /transaction-groups/:id` call removes exactly one `TransactionGroupItem` row from the victim's group (the first one returned by the `find` query), then throws `UnauthorizedException`, leaving the group in a progressively more broken state.

**Full destruction after N+1 calls:** Once all N group items have been individually stripped away, the N+1th call finds an empty `groupItems` array, skips the loop entirely, and executes `this.dataSource.manager.remove(TransactionGroup, group)` — permanently deleting the group entity. [10](#0-9) 

- **Unauthorized data destruction:** An attacker can permanently delete any other user's transaction group and all its `TransactionGroupItem` records without owning any of the underlying transactions.
- **Integrity failure:** The underlying `Transaction` records survive (because `removeTransaction` throws before deleting them), but their `TransactionGroupItem` linkage is permanently gone, orphaning them from the group workflow.

## Likelihood Explanation

- **Attacker preconditions:** A valid JWT (any registered, verified user). No admin role, no leaked secrets, no special network access required.
- **Group ID discovery:** Trivially obtained from the `GET /transaction-groups` endpoint, which returns all groups in the system to any authenticated user.
- **Exploit complexity:** Sending N+1 sequential HTTP DELETE requests. Fully automatable with a single script loop.
- **No rate-limiting or anomaly detection** is visible in the codebase for this endpoint.

## Recommendation

1. **Add an upfront group-level ownership check** in `removeTransactionGroup`, mirroring the pattern used in `cancelTransactionGroup`: verify that `user.id` matches the creator of all transactions in the group before performing any deletions.
2. **Wrap the entire deletion loop in a `dataSource.transaction(...)` block** so that any failure (including `UnauthorizedException` from `removeTransaction`) rolls back all previously deleted `TransactionGroupItem` rows atomically.
3. **Delete `TransactionGroupItem` rows after (or inside) `removeTransaction`**, not before, so the ownership check fires before any state is mutated.
4. **Restrict or remove the `GET /transaction-groups` endpoint** — it returns all groups to any authenticated user and is labeled "TESTING ONLY", meaning it should not be reachable in production.

## Proof of Concept

```
# Attacker: any registered, verified user with a valid JWT
# Victim: owner of transaction group with id=42 containing N items

# Step 1: Discover victim group IDs
GET /transaction-groups
Authorization: Bearer <attacker_jwt>
# Returns all groups including group id=42

# Steps 2 through N+1: Strip each TransactionGroupItem one by one
for i in $(seq 1 $((N+1))); do
  curl -X DELETE https://api.example.com/transaction-groups/42 \
    -H "Authorization: Bearer <attacker_jwt>"
  # Calls 1..N: returns 401 UnauthorizedException, but one TransactionGroupItem is deleted per call
  # Call N+1: groupItems is empty, loop is skipped, TransactionGroup is deleted — returns 200
done

# Result: victim's group and all its TransactionGroupItem rows are permanently destroyed.
# The underlying Transaction records survive but are orphaned from the group.
```

### Citations

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L25-29)
```typescript
@ApiTags('Transaction Groups')
@Controller('transaction-groups')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionGroupsController {
  constructor(private readonly transactionGroupsService: TransactionGroupsService) {}
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

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L207-212)
```typescript
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
