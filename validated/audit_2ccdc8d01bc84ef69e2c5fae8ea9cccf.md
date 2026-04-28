All four code claims check out against the actual source. Here is the audit report.

---

Audit Report

## Title
Soft-Deleted Users Remain as Active `TransactionApprover` Records, Permanently Freezing Transaction Execution

## Summary
When an admin removes a user via `removeUser()`, the user's `TransactionApprover` rows are never soft-deleted. Because the deleted user can no longer authenticate, any transaction that requires their approval is permanently stuck in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` with no automatic remediation.

## Finding Description

**1. `removeUser()` does not cascade to `TransactionApprover`**

`removeUser()` in `users.service.ts` soft-deletes `UserKey` records and the `User` row, but never touches `transaction_approver` rows that reference the deleted user's `userId`. [1](#0-0) 

**2. `getApproversByTransactionId()` does not filter by the associated user's `deletedAt`**

The recursive CTE only checks `approverList."deletedAt" is null` — the approver record's own soft-delete flag. It does not join the `user` table to exclude approvers whose user has been soft-deleted, so the orphaned record is returned as an active, pending approver. [2](#0-1) 

**3. `approveTransaction()` blocks on the orphaned record**

`approveTransaction()` calls `getVerifiedApproversByTransactionId()` (which internally calls `getApproversByTransactionId()`), then filters to `userApprovers` for the current user. The deleted user's record has `signature = null` and `approved = null` and can never be updated — the user cannot authenticate anymore — so the transaction status can never advance past the approval gate. [3](#0-2) 

**4. Contrast with the signing path, which correctly filters deleted users**

The notification/signing path explicitly filters soft-deleted users via `filterActiveUserKeys`, which checks both `key.deletedAt` and `key.user.deletedAt`. The approver path has no equivalent guard. [4](#0-3) 

**5. `TransactionApprover` entity has `deletedAt` but it is never set on user removal**

The `@DeleteDateColumn() deletedAt` field exists on the entity and is used for soft-deletes in other flows (e.g., `removeTransactionApprover()`), but `removeUser()` never invokes any equivalent cleanup. [5](#0-4) 

## Impact Explanation
Any transaction that has a soft-deleted user as a required approver is permanently frozen in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`. The transaction creator must manually discover the stale approver record and call `DELETE /transactions/:id/approvers/:approverId` to unblock it. [6](#0-5) 

There is no automatic notification, no system-level remediation, and no timeout specific to the approval gate (the transaction will only naturally terminate when its Hedera `validStart + validDuration` window expires). In a threshold-based approver tree, even a single deleted leaf approver can prevent the threshold from ever being met, blocking the entire transaction group.

## Likelihood Explanation
User deletion is a routine administrative operation (employee offboarding). Any time an admin removes a user who has outstanding pending approvals, all affected transactions are silently frozen. No special attacker capability is needed — the freeze is an automatic side-effect of a legitimate admin action. The admin does not need to know about pending approvals for the freeze to occur.

## Recommendation
In `removeUser()`, after soft-deleting the user and their keys, also soft-delete all `TransactionApprover` rows that reference the deleted `userId`:

```typescript
await this.repo.manager.softDelete(TransactionApprover, { userId: id });
```

Additionally, add a defensive join in `getApproversByTransactionId()` to exclude approvers whose associated user has been soft-deleted:

```sql
LEFT JOIN "user" u ON u."id" = approverList."userId"
WHERE approverList."deletedAt" IS NULL
  AND (approverList."userId" IS NULL OR u."deletedAt" IS NULL)
```

This mirrors the existing `filterActiveUserKeys` guard already used in the signing/notification path. [4](#0-3) 

## Proof of Concept

1. Admin creates a transaction requiring approval from User A and User B.
2. User A approves the transaction (their `TransactionApprover` row gets `signature` set).
3. Admin removes User B via `DELETE /organization/users/:id`, which calls `removeUser(userId)`.
   - `UserKey` rows for User B are soft-deleted.
   - The `User` row for User B is soft-deleted.
   - User B's `TransactionApprover` row is **not** touched; `deletedAt` remains `null`.
4. `getApproversByTransactionId(transactionId)` returns User B's approver row (its own `deletedAt` is `null`).
5. The transaction status evaluator sees one approver with `signature = null` and `approved = null`.
6. User B can no longer log in (soft-deleted), so their approver record can never be fulfilled.
7. The transaction remains permanently in `WAITING_FOR_SIGNATURES` until the creator manually calls `DELETE /transactions/:id/approvers/:approverId` for User B's approver record. [7](#0-6) [8](#0-7)

### Citations

**File:** back-end/apps/api/src/users/users.service.ts (L156-170)
```typescript
  async removeUser(id: number): Promise<boolean> {
    const user = await this.getUser({ id });

    if (!user) {
      throw new BadRequestException(ErrorCodes.UNF);
    }

    // Soft-delete all user keys first
    await this.repo.manager.softDelete(UserKey, { userId: id });

    // Then soft-delete the user
    await this.repo.softRemove(user);

    return true;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L92-108)
```typescript
    return (entityManager || this.repo).query(
      `
      with recursive approverList as
        (
          select * from transaction_approver 
          where "transactionId" = $1
            union all
              select approver.* from transaction_approver as approver
              join approverList on approverList."id" = approver."listId"
        )
      select * from approverList
      where approverList."deletedAt" is null
        ${userId ? 'and approverList."userId" = $2' : ''}
      `,
      userId ? [transactionId, userId] : [transactionId],
    );
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L534-544)
```typescript
  async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);

    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const result = await this.removeNode(approver.id);

    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);

    return result;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L547-563)
```typescript
  async approveTransaction(
    dto: ApproverChoiceDto,
    transactionId: number,
    user: User,
  ): Promise<boolean> {
    /* Get all the approvers */
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);

    /* If user is approver, filter the records that belongs to the user */
    const userApprovers = approvers.filter(a => a.userId === user.id);

    /* Check if the user is an approver */
    if (userApprovers.length === 0)
      throw new UnauthorizedException('You are not an approver of this transaction');

    /* Check if the user has already approved the transaction */
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
```

**File:** back-end/libs/common/src/utils/user/index.ts (L24-33)
```typescript
export const isActiveUserKey = (key: UserKeyWithUser): boolean => {
  return !key.deletedAt && key.user !== null && !key.user.deletedAt;
};

/**
 * Filters array to return only active UserKeys.
 */
export const filterActiveUserKeys = <T extends UserKeyWithUser>(keys: T[]): T[] => {
  return keys.filter(isActiveUserKey);
};
```

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L75-77)
```typescript
  @DeleteDateColumn()
  deletedAt: Date;
}
```
