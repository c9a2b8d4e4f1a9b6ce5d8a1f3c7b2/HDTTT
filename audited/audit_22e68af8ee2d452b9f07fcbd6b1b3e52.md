### Title
User Key Deletion Without Active Transaction Guard Permanently Blocks Creator Operations on Pending Transactions

### Summary

`removeUserKey()` in `user-keys.service.ts` soft-deletes a `UserKey` without checking whether that key is the `creatorKey` for any active (non-terminal) transactions. After deletion, TypeORM excludes soft-deleted records from relation loading by default, so every function that calls `getTransactionForCreator()` receives a transaction with `creatorKey === null`. The authorization check `transaction.creatorKey?.userId !== user?.id` then evaluates to `undefined !== user.id → true`, throwing `UnauthorizedException`. All creator-only operations — `cancelTransaction`, `archiveTransaction`, `removeTransaction`, `executeTransaction` — become permanently unreachable for those transactions.

### Finding Description

**Vulnerability class:** State transition / accounting — entity deleted without checking active dependencies, blocking subsequent operations (direct analog of `removeSupportedToken()` / `adminWithdraw()` pattern).

**Root cause — `removeUserKey()` has no active-transaction guard:** [1](#0-0) 

The function only verifies ownership (`userKey.userId !== user.id`) and then immediately soft-deletes. There is no check for active transactions where this key is the `creatorKey`.

**Why soft-deletion breaks the creator check:**

TypeORM's default relation loading excludes soft-deleted rows (those with a non-null `deletedAt`). The `getTransactionForCreator` path in `transactions.service.ts` loads the transaction with `relations: ['creatorKey']` and no `withDeleted: true`: [2](#0-1) 

After the key is soft-deleted, `transaction.creatorKey` is `null`. The guard `transaction.creatorKey?.userId !== user?.id` evaluates to `undefined !== user.id`, which is always `true`, so `UnauthorizedException` is thrown for every creator-only operation.

The same pattern exists in `approvers.service.ts` `getCreatorsTransaction()`: [3](#0-2) 

**Affected operations (all call `getTransactionForCreator`):** [4](#0-3) [5](#0-4) [6](#0-5) 

**`UserKey` entity confirms the `creatorKey` relationship:** [7](#0-6) 

### Impact Explanation

1. **For `isManual` transactions** — these have no automatic on-chain expiry enforced by the chain service. After the creator key is deleted, the transaction is permanently stuck in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`. No API endpoint allows a non-creator (including admins) to cancel it. The transaction is an unrecoverable orphan in the database.

2. **For standard transactions** — the transaction is stuck until the Hedera network's validity window expires (typically minutes), after which the chain service marks it `EXPIRED`. During that window, required signers see a pending transaction they cannot dismiss, and the creator cannot cancel it.

3. **Collateral effect on signers/approvers** — other users assigned to sign or approve the transaction cannot remove it from their queue; only the creator can cancel, and that path is now blocked.

### Likelihood Explanation

- **Attacker preconditions:** None beyond a valid authenticated session. Any verified user can call `DELETE /user/:userId/keys/:id` on their own key.
- **Realistic trigger:** A user who rotates or cleans up old keys after creating a multi-sig transaction inadvertently deletes the creator key. No malicious intent is required; the API provides no warning.
- **No privileged access required:** `removeUserKey` is a standard user-facing endpoint protected only by `JwtAuthGuard` and `VerifiedUserGuard`. [8](#0-7) 

### Recommendation

In `removeUserKey()` (and `removeKey()`), before soft-deleting, query for active transactions where `creatorKeyId = id` and status is not in the terminal set (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `ARCHIVED`). If any exist, reject the deletion with a descriptive error:

```typescript
const activeCount = await this.transactionRepo.count({
  where: {
    creatorKeyId: id,
    status: Not(In([
      TransactionStatus.EXECUTED,
      TransactionStatus.FAILED,
      TransactionStatus.EXPIRED,
      TransactionStatus.CANCELED,
      TransactionStatus.ARCHIVED,
    ])),
  },
});
if (activeCount > 0) {
  throw new BadRequestException(ErrorCodes.KEY_HAS_ACTIVE_TRANSACTIONS);
}
```

Alternatively, load `creatorKey` with `withDeleted: true` in `getTransactionForCreator` and fall back to matching on `creatorKeyId` directly, so the creator can still cancel even after key deletion.

### Proof of Concept

1. Authenticate as a regular verified user (User A).
2. Upload a public key → receive `userKeyId = K`.
3. Create a multi-sig transaction using key `K` as `creatorKeyId`. Transaction enters `WAITING_FOR_SIGNATURES`.
4. Call `DELETE /user/A/keys/K` → returns `200 OK`. Key is soft-deleted (`deletedAt` set).
5. Call `PATCH /transactions/cancel/:transactionId` as User A.
6. **Expected (correct):** `200 OK`, transaction canceled.
7. **Actual (vulnerable):** `401 Unauthorized` — `getTransactionForCreator` loads `creatorKey: null` because the key is soft-deleted; the check `null?.userId !== A.id` → `true` → throws.
8. For a `isManual: true` transaction, repeat step 5 with `PATCH /transactions/archive/:transactionId` and `DELETE /transactions/:transactionId` — both return `401`. The transaction is now permanently unmanageable.

### Citations

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L95-109)
```typescript
  async removeUserKey(user: User, id: number): Promise<boolean> {
    const userKey = await this.getUserKey({ id });

    if (!userKey) {
      throw new BadRequestException(ErrorCodes.KNF);
    }

    if (userKey.userId !== user.id) {
      throw new BadRequestException(ErrorCodes.PNY);
    }

    await this.repo.softRemove(userKey);

    return true;
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L628-651)
```typescript
  /* Remove the transaction for the given transaction id. */
  async removeTransaction(id: number, user: User, softRemove: boolean = true): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);

    if (softRemove) {
      await this.repo.update(transaction.id, { status: TransactionStatus.CANCELED });
      await this.repo.softRemove(transaction);
    } else {
      await this.repo.remove(transaction);
    }

    emitTransactionStatusUpdate(
      this.notificationsPublisher,
      [{
        entityId: transaction.id,
        additionalData: {
          transactionId: transaction.transactionId,
          network: transaction.mirrorNetwork,
        },
      }],
    );

    return true;
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L707-733)
```typescript
  /* Archive the transaction if the transaction is sign only. */
  async archiveTransaction(id: number, user: User): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);

    if (
      ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
        transaction.status,
      ) &&
      !transaction.isManual
    ) {
      throw new BadRequestException(ErrorCodes.OMTIP);
    }

    await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
    emitTransactionStatusUpdate(
      this.notificationsPublisher,
      [{
        entityId: transaction.id,
        additionalData: {
          transactionId: transaction.transactionId,
          network: transaction.mirrorNetwork,
        },
      }],
    );

    return true;
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L736-751)
```typescript
  async executeTransaction(id: number, user: User): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);

    if (!transaction.isManual) {
      throw new BadRequestException(ErrorCodes.IO);
    }

    if (transaction.validStart.getTime() > Date.now()) {
      await this.repo.update({ id }, { isManual: false });
      emitTransactionUpdate(this.notificationsPublisher, [{ entityId: transaction.id }]);
    } else {
      await this.executeService.executeTransaction(transaction);
    }

    return true;
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L624-644)
```typescript
  async getCreatorsTransaction(
    transactionId: number,
    user: User,
    entityManager?: EntityManager,
  ): Promise<Transaction> {
    const find: FindOneOptions<Transaction> = {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user'],
    };

    const transaction = await (entityManager
      ? entityManager.findOne(Transaction, find)
      : this.dataSource.manager.findOne(Transaction, find));

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to modify it');

    return transaction;
  }
```

**File:** back-end/libs/common/src/database/entities/user-key.entity.ts (L38-48)
```typescript
  @DeleteDateColumn()
  deletedAt: Date;

  @OneToMany(() => Transaction, transaction => transaction.creatorKey)
  createdTransactions: Transaction[];

  @OneToMany(() => TransactionApprover, approver => approver.userKey)
  approvedTransactions: TransactionApprover[];

  @OneToMany(() => TransactionSigner, signer => signer.userKey)
  signedTransactions: TransactionSigner[];
```

**File:** back-end/apps/api/src/user-keys/user-keys.controller.ts (L67-71)
```typescript
  @Delete('/:id')
  async removeKey(@GetUser() user: User, @Param('id', ParseIntPipe) id: number): Promise<boolean> {
    // If this returns the result, the dto can't decode the id as things are null
    return this.userKeysService.removeUserKey(user, id);
  }
```
