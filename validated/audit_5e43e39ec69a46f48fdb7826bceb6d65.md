### Title
Any Authenticated User Can Delete Any Transaction Group Without Ownership Verification

### Summary
The `removeTransactionGroup` function in `TransactionGroupsService` performs no ownership or authorization check before permanently deleting a transaction group and all its associated transactions. Any authenticated organization member can supply an arbitrary group ID to `DELETE /transaction-groups/:id` and destroy another user's group. This is the direct analog of the external report's vulnerability class — missing access control on a state-mutating function that permanently corrupts another user's resources.

### Finding Description

**Root cause:** `removeTransactionGroup` fetches the group by ID and immediately proceeds to delete it without verifying that the requesting user owns or has any relationship to the group.

```typescript
// back-end/apps/api/src/transactions/groups/transaction-groups.service.ts
async removeTransactionGroup(user: User, id: number): Promise<boolean> {
    const group = await this.dataSource.manager.findOneBy(TransactionGroup, { id });
    if (!group) {
      throw new Error('group not found');
    }
    // ← NO ownership check here
    const groupItems = await this.dataSource.manager.find(TransactionGroupItem, { ... });
    for (const groupItem of groupItems) {
      await this.dataSource.manager.remove(TransactionGroupItem, groupItem);
      await this.transactionsService.removeTransaction(transactionId, user, false);
    }
    await this.dataSource.manager.remove(TransactionGroup, group);
    return true;
}
``` [1](#0-0) 

Contrast this with `cancelTransactionGroup`, which correctly enforces ownership before acting:

```typescript
const allOwnedByUser = group.groupItems.every(
  item => item.transaction?.creatorKey?.userId === user.id,
);
if (!allOwnedByUser) {
  throw new UnauthorizedException('Only the creator can cancel all transactions in a group.');
}
``` [2](#0-1) 

The `DELETE /:id` endpoint on the controller passes the authenticated user but applies no additional guard beyond `JwtAuthGuard` and `VerifiedUserGuard`: [3](#0-2) 

**Group ID enumeration:** The `GET /transaction-groups` endpoint returns all groups with no filtering, allowing an attacker to enumerate valid group IDs: [4](#0-3) 

**Exploit path:**
1. Attacker authenticates as any verified organization member.
2. Attacker calls `GET /transaction-groups` to enumerate all group IDs.
3. Attacker calls `DELETE /transaction-groups/<victim_group_id>` for any target group.
4. The service deletes all `TransactionGroupItem` rows, calls `removeTransaction` for each transaction, and removes the `TransactionGroup` — permanently destroying the victim's work.

### Impact Explanation
Permanent, irreversible deletion of any transaction group and all its constituent transactions belonging to any other user in the organization. A victim loses all pending multi-signature workflows, approver assignments, and transaction bytes stored in those groups. There is no recovery path once the rows are deleted. This satisfies the RESEARCHER.md criterion of "Permanent lock, freeze, or unrecoverable corruption of user/project state."

### Likelihood Explanation
The attacker requires only a valid JWT for any verified organization account — the lowest possible privilege bar. No admin keys, no leaked credentials, and no race condition are required. The group ID is an auto-incremented integer, trivially enumerable via the unauthenticated-equivalent `GET /transaction-groups` endpoint. The attack is a single HTTP `DELETE` request.

### Recommendation
Add an ownership check in `removeTransactionGroup` before any deletion occurs, mirroring the pattern already used in `cancelTransactionGroup`:

```typescript
async removeTransactionGroup(user: User, id: number): Promise<boolean> {
    const group = await this.dataSource.manager.findOneBy(TransactionGroup, { id });
    if (!group) throw new Error('group not found');

    const groupItems = await this.dataSource.manager.find(TransactionGroupItem, {
        relations: { transaction: { creatorKey: true } },
        where: { group: { id: group.id } },
    });

    const allOwnedByUser = groupItems.every(
        item => item.transaction?.creatorKey?.userId === user.id,
    );
    if (!allOwnedByUser) {
        throw new UnauthorizedException('Only the creator can remove a transaction group.');
    }
    // ... proceed with deletion
}
```

Additionally, restrict `GET /transaction-groups` to return only groups visible to the requesting user, or remove it from production builds as its own comment acknowledges ("TESTING ONLY").

### Proof of Concept

**Preconditions:** Two verified organization accounts — Alice (victim, group creator) and Bob (attacker).

1. Alice creates a transaction group:
   ```
   POST /transaction-groups
   Authorization: Bearer <alice_jwt>
   → 201 { "id": 7, ... }
   ```

2. Bob enumerates groups:
   ```
   GET /transaction-groups
   Authorization: Bearer <bob_jwt>
   → 200 [ { "id": 7, ... }, ... ]
   ```

3. Bob deletes Alice's group:
   ```
   DELETE /transaction-groups/7
   Authorization: Bearer <bob_jwt>
   → 200 true
   ```

4. Alice's group and all its transactions are permanently gone. Alice receives no error or notification. Any subsequent `GET /transaction-groups/7` by Alice returns 400 `TNF`.

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
