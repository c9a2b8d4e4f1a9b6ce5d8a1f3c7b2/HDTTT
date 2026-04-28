### Title
Missing Ownership Check in `removeTransactionGroup` Allows Any Authenticated User to Corrupt Other Users' Transaction Group State

### Summary
`removeTransactionGroup` in `TransactionGroupsService` performs no ownership verification before beginning destructive database mutations. Because `TransactionGroupItem` records are deleted before the per-transaction ownership check fires, any authenticated user can permanently orphan group items from a victim's transaction group. The operation is not wrapped in a database transaction, so the partial deletion is committed even when the subsequent authorization check throws.

### Finding Description

**Root cause — missing pre-authorization check:**

`cancelTransactionGroup` (the sibling operation) correctly verifies ownership before touching any data: [1](#0-0) 

`removeTransactionGroup` performs no equivalent check. It resolves the group by ID alone and immediately begins mutating state: [2](#0-1) 

**Execution order inside the loop (lines 187–191):**

1. `manager.remove(TransactionGroupItem, groupItem)` — deletes the join record **immediately and unconditionally** (line 189).
2. `transactionsService.removeTransaction(transactionId, user, false)` — calls `getTransactionForCreator`, which throws `UnauthorizedException` when the caller is not the creator (line 190). [3](#0-2) [4](#0-3) 

Because the entire loop is **not wrapped in a database transaction**, the `TransactionGroupItem` deletion at step 1 is committed to PostgreSQL before step 2 throws. The `TransactionGroup` row itself survives (line 193 is never reached), but it now has one fewer group item — permanently.

**Exposed endpoint:** [5](#0-4) 

The controller applies only `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — standard authenticated-user guards with no ownership enforcement. [6](#0-5) 

**Group ID discovery:** The `GET /transaction-groups` endpoint returns every group in the system with no user filter, giving the attacker a full list of target IDs. [7](#0-6) 

### Impact Explanation

An attacker can permanently delete `TransactionGroupItem` rows from any victim's transaction group. Each deleted item severs the link between a `Transaction` and its `TransactionGroup`. Because the system uses groups to coordinate sequential or atomic multi-signature workflows, removing items breaks the execution order, causes the group to appear incomplete, and prevents the remaining transactions from being processed as a coordinated unit. The underlying `Transaction` records are not deleted (the ownership check blocks that), but the group-level coordination is irreversibly corrupted. There is no recovery path short of manual database intervention.

### Likelihood Explanation

The attacker preconditions are minimal: a valid, verified account on the organization backend. No admin role, no leaked credentials, and no special knowledge beyond a target group ID (which is trivially enumerable via `GET /transaction-groups`). The exploit requires a single authenticated HTTP `DELETE` request. Any organization member can trigger this against any other member's group.

### Recommendation

1. **Add an ownership pre-check** in `removeTransactionGroup` before any mutations, mirroring the pattern already used in `cancelTransactionGroup`:

```typescript
async removeTransactionGroup(user: User, id: number): Promise<boolean> {
  const group = await this.dataSource.manager.findOneBy(TransactionGroup, { id });
  if (!group) throw new Error('group not found');

  const groupItems = await this.dataSource.manager.find(TransactionGroupItem, {
    relations: { group: true, transaction: { creatorKey: true } },
    where: { group: { id: group.id } },
  });

  // Ownership check BEFORE any mutation
  const allOwnedByUser = groupItems.every(
    item => item.transaction?.creatorKey?.userId === user.id,
  );
  if (!allOwnedByUser) {
    throw new UnauthorizedException('Only the creator can remove a transaction group.');
  }

  // Wrap all mutations in a single DB transaction
  await this.dataSource.transaction(async manager => {
    for (const groupItem of groupItems) {
      await manager.remove(TransactionGroupItem, groupItem);
      await manager.remove(Transaction, { id: groupItem.transactionId });
    }
    await manager.remove(TransactionGroup, group);
  });
  ...
}
```

2. **Wrap all mutations in a `dataSource.transaction` block** so that a mid-loop failure rolls back all prior deletions atomically.

3. **Restrict `GET /transaction-groups`** to admin users or filter results by the requesting user's membership, removing the trivial group-ID enumeration path.

### Proof of Concept

**Preconditions:** Attacker has a valid verified account (`attacker_token`). Victim has a transaction group with ID `42` containing transactions they created.

```
# Step 1 – enumerate all group IDs (no ownership filter)
GET /transaction-groups
Authorization: Bearer <attacker_token>
→ 200 OK, returns all groups including victim's group id=42

# Step 2 – trigger the delete
DELETE /transaction-groups/42
Authorization: Bearer <attacker_token>

# Expected server behavior:
# 1. group found (no ownership check)
# 2. groupItems fetched
# 3. first TransactionGroupItem deleted from DB  ← committed, no rollback
# 4. removeTransaction throws UnauthorizedException (attacker ≠ creator)
# 5. HTTP 401 returned to attacker

# Observed DB state after the request:
# - TransactionGroup id=42 still exists
# - First TransactionGroupItem is GONE (permanently deleted)
# - Victim's group is now structurally corrupted
```

Repeating the request for each group item progressively strips all items from the group, leaving an empty `TransactionGroup` shell that can never be executed.

### Citations

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

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L25-29)
```typescript
@ApiTags('Transaction Groups')
@Controller('transaction-groups')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionGroupsController {
  constructor(private readonly transactionGroupsService: TransactionGroupsService) {}
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
