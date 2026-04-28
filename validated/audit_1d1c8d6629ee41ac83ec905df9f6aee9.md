### Title
Soft-Deleted Users Remain as Active `TransactionApprover` Records, Permanently Freezing Transaction Execution

### Summary
When an admin removes a user from the organization via `removeUser()`, the user's `TransactionApprover` records are **not** soft-deleted. Because the deleted user can no longer authenticate, any transaction requiring their approval is permanently stuck in `WAITING_FOR_SIGNATURES` with no automatic remediation path. This is the direct analog of the external report's "inactive entity remains registered in a workflow" class.

### Finding Description

**Root cause — `users.service.ts` `removeUser()` does not cascade to `TransactionApprover`:** [1](#0-0) 

The function soft-deletes `UserKey` records and the `User` row, but never touches `transaction_approver` rows that reference the deleted user's `userId`.

**`getApproversByTransactionId()` does not filter by user's `deletedAt`:** [2](#0-1) 

The recursive SQL query only checks `approverList."deletedAt" is null` — the approver record's own soft-delete flag. It does **not** join the `user` table to exclude approvers whose associated user has been soft-deleted. So the deleted user's approver row is returned as an active, pending approver.

**`approveTransaction()` then blocks on that orphaned record:** [3](#0-2) 

The function fetches all approvers (including the deleted user's record), filters to `userApprovers` for the current user, and checks `userApprovers.every(a => a.signature)`. The deleted user's record has no signature and can never get one — the user cannot authenticate anymore — so the transaction is permanently blocked.

**Contrast with the signing path, which correctly filters deleted users:** [4](#0-3) 

The notification/signing path explicitly filters soft-deleted users via `filterActiveUserKeys`. The approver path has no equivalent guard.

**`TransactionApprover` entity has `deletedAt` but it is never set on user removal:** [5](#0-4) 

### Impact Explanation

Any transaction that has a soft-deleted user as a required approver is **permanently frozen** in `WAITING_FOR_SIGNATURES`. The transaction creator must manually discover the stale approver record and call `DELETE /transactions/:id/approvers/:approverId` to unblock it. There is no automatic notification, no system-level remediation, and no timeout. In a threshold-based approver tree, even a single deleted leaf approver can prevent the threshold from ever being met, blocking the entire transaction group.

### Likelihood Explanation

User deletion is a routine administrative operation (employee offboarding). Any time an admin removes a user who has outstanding pending approvals, all affected transactions are silently frozen. No special attacker capability is needed beyond the normal admin role that already has the "Remove user" button in the UI. The admin does not need to know about pending approvals — the freeze is an automatic side-effect of a legitimate action.

### Recommendation

In `users.service.ts` `removeUser()`, add a cascade soft-delete of all `TransactionApprover` records for the removed user before soft-deleting the user:

```typescript
await this.repo.manager.softDelete(TransactionApprover, { userId: id });
await this.repo.manager.softDelete(UserKey, { userId: id });
await this.repo.softRemove(user);
```

Alternatively, modify `getApproversByTransactionId()` to join the `user` table and add `AND (u."deletedAt" IS NULL OR ta."userId" IS NULL)` to the filter, consistent with how `filterActiveUserKeys` handles the signing path.

### Proof of Concept

1. Admin creates **User A** and **User B** on the organization server.
2. User B creates **Transaction T** (status: `WAITING_FOR_SIGNATURES`).
3. User B calls `POST /transactions/T/approvers` with `{ userId: A }` — User A is now a required approver.
4. Admin calls `DELETE /users/A` — `removeUser(A)` soft-deletes `UserKey` rows and the `User` row, but leaves the `transaction_approver` row for User A intact.
5. Verify: `SELECT * FROM transaction_approver WHERE "userId" = A AND "deletedAt" IS NULL` — returns 1 row.
6. User A can no longer authenticate (JWT guard rejects soft-deleted users).
7. Transaction T remains in `WAITING_FOR_SIGNATURES` indefinitely. No notification is sent. No automatic status transition occurs.
8. The only recovery is for User B to manually call `DELETE /transactions/T/approvers/:approverId`, which requires knowing the approver record ID.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L553-563)
```typescript
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);

    /* If user is approver, filter the records that belongs to the user */
    const userApprovers = approvers.filter(a => a.userId === user.id);

    /* Check if the user is an approver */
    if (userApprovers.length === 0)
      throw new UnauthorizedException('You are not an approver of this transaction');

    /* Check if the user has already approved the transaction */
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
```

**File:** back-end/apps/notifications/src/receiver/receiver.service.spec.ts (L174-185)
```typescript
  it('getUsersIdsRequiredToSign filters out soft-deleted users', async () => {
    (keysRequiredToSign as jest.Mock).mockResolvedValue([
      { userId: 10, user: { id: 10, deletedAt: null } },
      { userId: 11, user: { id: 11, deletedAt: new Date() } }, // deleted user
      { userId: 12, user: { id: 12, deletedAt: null } },
    ]);
    const tx = {} as any;

    const res = await (service as any).getUsersIdsRequiredToSign(em as any, tx, new Map());
    expect(res).toEqual([10, 12]);
    expect(res).not.toContain(11);
  });
```

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L75-76)
```typescript
  @DeleteDateColumn()
  deletedAt: Date;
```
