### Title
Missing Ownership Validation in `removeTransactionGroup` Allows Any Authenticated User to Delete Another User's Transaction Group

### Summary
The `removeTransactionGroup()` function in `transaction-groups.service.ts` fetches a `TransactionGroup` by ID alone without verifying that the requesting user owns the group. Any authenticated user can supply an arbitrary `groupId` to permanently delete another user's transaction group and all its associated transactions. This is the direct analog of the external report's pattern: a state-mutating function uses a caller-supplied resource identifier without validating that the resource belongs to the caller's context.

### Finding Description

**Root cause — no ownership check before deletion:**

In `back-end/apps/api/src/transactions/groups/transaction-groups.service.ts`, `removeTransactionGroup` fetches the group with no user filter:

```typescript
// line 173 — only checks existence, not ownership
const group = await this.dataSource.manager.findOneBy(TransactionGroup, { id });
if (!group) {
  throw new Error('group not found');
}
``` [1](#0-0) 

The `user` argument is threaded into `removeTransaction` for each group item, but the group itself is fetched and deleted with no ownership assertion. There is no check equivalent to `group.creatorId === user.id` or any role-based guard before the destructive path executes.

**Contrast with `cancelTransactionGroup`**, which explicitly enforces ownership on the same resource type:

```typescript
// lines 207-212 — ownership check present in cancel but absent in remove
const allOwnedByUser = group.groupItems.every(
  item => item.transaction?.creatorKey?.userId === user.id,
);
if (!allOwnedByUser) {
  throw new UnauthorizedException('Only the creator can cancel all transactions in a group.');
}
``` [2](#0-1) 

**Entry point — unauthenticated users are blocked, but any verified user can reach this path:**

```typescript
// controller line 107-113
@Delete('/:id')
removeTransactionGroup(
  @GetUser() user: User,
  @Param('id', ParseIntPipe) groupId: number,
): Promise<boolean> {
  return this.transactionGroupsService.removeTransactionGroup(user, groupId);
}
``` [3](#0-2) 

The guards `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` only require a valid, non-blacklisted JWT — they do not enforce resource ownership. [4](#0-3) 

**Test evidence confirms no ownership check exists:**

The unit test for `removeTransactionGroup` only tests the "group not found" path. There is no test for "user does not own the group," confirming the check was never implemented. [5](#0-4) 

### Impact Explanation

Any authenticated user (no admin role required) can permanently delete any other user's `TransactionGroup` and all its child `TransactionGroupItem` and `Transaction` records by issuing:

```
DELETE /transaction-groups/<victim_group_id>
```

This causes **irreversible data loss**: the group, all group items, and all associated transactions are removed from the database. For an organization using the tool for multi-signature Hedera transaction workflows, this means an attacker can silently destroy pending or in-progress transaction batches belonging to any other user, disrupting financial operations and eliminating audit records.

### Likelihood Explanation

- **Precondition:** Attacker needs only a valid JWT (i.e., a registered, verified account on the same organization backend). No elevated privileges are required.
- **Discovery:** Transaction group IDs are sequential integers (`ParseIntPipe`). An attacker can enumerate valid IDs trivially.
- **Trigger:** A single authenticated HTTP `DELETE` request. No race condition or timing dependency.
- **Detectability:** The deletion is silent — no ownership error is raised, and the response is `true`.

### Recommendation

Add an ownership check in `removeTransactionGroup` before any deletion occurs, consistent with the pattern already used in `cancelTransactionGroup`:

```typescript
async removeTransactionGroup(user: User, id: number): Promise<boolean> {
  const group = await this.dataSource.manager.findOneBy(TransactionGroup, { id });
  if (!group) throw new Error('group not found');

  // Add: verify the requesting user owns the group
  if (group.creatorId !== user.id) {
    throw new UnauthorizedException('Only the creator can remove a transaction group.');
  }
  // ... rest of deletion logic
}
```

Alternatively, scope the initial `findOneBy` to include the user: `findOneBy(TransactionGroup, { id, creatorId: user.id })` and throw `UnauthorizedException` when `null` is returned.

### Proof of Concept

1. User A (attacker) registers and obtains a valid JWT.
2. User B (victim) creates a transaction group; the response includes `{ "id": 42, ... }`. Group ID 42 is also discoverable by enumeration.
3. Attacker sends:
   ```
   DELETE /transaction-groups/42
   Authorization: Bearer <attacker_jwt>
   ```
4. Server calls `removeTransactionGroup(attackerUser, 42)`.
5. `findOneBy(TransactionGroup, { id: 42 })` returns the group (no user filter).
6. No ownership check is performed.
7. All `TransactionGroupItem` records for group 42 are deleted, all associated `Transaction` records are removed via `removeTransaction`, and the `TransactionGroup` row is deleted.
8. Response: `true`. Victim's group and all its transactions are permanently gone.

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

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.spec.ts (L299-339)
```typescript
  describe('removeTransactionGroup', () => {
    beforeEach(() => {
      jest.resetAllMocks();
    });

    it('should throw an error if the group is not found', async () => {
      dataSource.manager.findOneBy.mockResolvedValue(undefined);
      await expect(service.removeTransactionGroup(user as User, 1)).rejects.toThrow(
        'group not found',
      );
    });

    it('should remove all group items and the group itself', async () => {
      const mockGroup = { id: 1 };
      const mockGroupItems = [
        { id: 1, transactionId: 101 },
        { id: 2, transactionId: 102 },
      ];

      dataSource.manager.findOneBy.mockResolvedValue(mockGroup);
      dataSource.manager.find.mockResolvedValue(mockGroupItems);
      dataSource.manager.remove
        //@ts-expect-error - typings
        .mockResolvedValueOnce(mockGroupItems[0])
        //@ts-expect-error - typings
        .mockResolvedValueOnce(mockGroupItems[1])
        //@ts-expect-error - typings
        .mockResolvedValueOnce(mockGroup);

      await service.removeTransactionGroup(user as User, 1);

      expect(dataSource.manager.remove).toHaveBeenCalledTimes(3); // Twice for group items, once for the group
      expect(transactionsService.removeTransaction).toHaveBeenCalledTimes(mockGroupItems.length);
      expect(emitTransactionUpdate).toHaveBeenCalledWith(
        notificationsPublisher,
        expect.arrayContaining([
          expect.objectContaining({ entityId: 101 }),
          expect.objectContaining({ entityId: 102 }),
        ]),
      );
    });
```
