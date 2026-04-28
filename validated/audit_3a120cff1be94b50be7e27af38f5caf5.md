All referenced code is confirmed. Here is the validation result:

---

Audit Report

## Title
`removeTransaction` Executes on Terminal-State Transactions, Enabling Audit Trail Corruption

## Summary
The `removeTransaction` function in `transactions.service.ts` performs no status check before soft-deleting a transaction. Any authenticated user who created a transaction can invoke `DELETE /transactions/{id}` against a transaction already in a terminal state (`EXECUTED`, `FAILED`, `EXPIRED`), causing the record to be overwritten to `CANCELED` and hidden from all normal API queries. This is a direct integrity failure in the state transition model of a governance tool.

## Finding Description

**Root cause — missing status guard in `removeTransaction`:**

`removeTransaction` delegates authorization entirely to `getTransactionForCreator`, which only verifies creator ownership: [1](#0-0) 

`getTransactionForCreator` checks only `creatorKey.userId !== user?.id` — no status validation is performed. `removeTransaction` then unconditionally:
1. Overwrites `status` → `CANCELED` via `repo.update`
2. Calls `repo.softRemove` (sets `deletedAt`) [2](#0-1) 

**Contrast with `cancelTransactionWithOutcome`, which explicitly guards terminal states:** [3](#0-2) 

`removeTransaction` has no equivalent guard.

**Defined terminal states:** [4](#0-3) 

`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `ARCHIVED`, and `REJECTED` are all terminal. `removeTransaction` allows transitioning any of them to `CANCELED` + soft-deleted.

**Effect on query visibility:**

`getTransactionById` uses `repo.find()` without `withDeleted: true`, so soft-deleted records are excluded from all normal lookups. The preference logic that favors non-inactive statuses further ensures the deleted record is never surfaced: [5](#0-4) 

**API entry point:** [6](#0-5) 

`deleteTransaction` calls `removeTransaction(id, user, true)` — the `softRemove=true` path — with no additional guards.

## Impact Explanation

- An `EXECUTED` transaction represents a Hedera network operation that has already been submitted and confirmed on-chain. Overwriting its status to `CANCELED` and hiding it from the database is a false representation of on-chain history.
- All other participants (observers, signers, approvers) lose visibility into a transaction they were party to, with no notification.
- For a governance tool used for multi-signature operations, audit trail integrity is a core security property. A creator can unilaterally erase evidence of any transaction they originated, regardless of its outcome.
- The soft-delete is not recoverable through any API endpoint — only direct database access can restore the record.

## Likelihood Explanation

- **Attacker precondition:** authenticated user who created at least one transaction. No elevated privileges required.
- **Attack path:** single authenticated `DELETE /transactions/{id}` API call after the transaction reaches a terminal state.
- The creator role is a standard user role reachable by any registered participant in the system.

## Recommendation

Add a status guard at the start of `removeTransaction` (mirroring the pattern in `cancelTransactionWithOutcome`) that rejects the operation if the transaction is in any terminal state:

```typescript
async removeTransaction(id: number, user: User, softRemove: boolean = true): Promise<boolean> {
  const transaction = await this.getTransactionForCreator(id, user);

  // Guard: prevent deletion of terminal-state transactions
  const nonRemovableStatuses = [
    TransactionStatus.EXECUTED,
    TransactionStatus.FAILED,
    TransactionStatus.EXPIRED,
  ];
  if (nonRemovableStatuses.includes(transaction.status)) {
    throw new BadRequestException(ErrorCodes.OTIP); // or a dedicated error code
  }

  if (softRemove) {
    await this.repo.update(transaction.id, { status: TransactionStatus.CANCELED });
    await this.repo.softRemove(transaction);
  } else {
    await this.repo.remove(transaction);
  }
  // ...
}
```

## Proof of Concept

1. Authenticate as a user who created a transaction (e.g., transaction ID `42`).
2. Wait for or observe the transaction reaching `EXECUTED` status.
3. Issue: `DELETE /transactions/42`
4. The server calls `removeTransaction(42, user, true)`.
5. `getTransactionForCreator` returns the transaction (creator check passes, no status check).
6. `repo.update(42, { status: 'CANCELED' })` overwrites the status.
7. `repo.softRemove(transaction)` sets `deletedAt`.
8. Subsequent calls to `GET /transactions/42` return 404/not-found because `getTransactionById` excludes soft-deleted rows.
9. The `EXECUTED` transaction has been erased from the audit trail with a single authenticated API call.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L98-105)
```typescript
  private readonly terminalStatuses = [
    TransactionStatus.EXECUTED,
    TransactionStatus.EXPIRED,
    TransactionStatus.FAILED,
    TransactionStatus.CANCELED,
    TransactionStatus.ARCHIVED,
    TransactionStatus.REJECTED,
  ];
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L113-132)
```typescript
    const transactions = await this.repo.find({
      where: typeof id == 'number' ? { id } : { transactionId: id.toString() },
      relations: [
        'creatorKey',
        'creatorKey.user',
        'observers',
        'comments',
        'groupItem',
        'groupItem.group',
      ],
      order: { id: 'DESC' },
    });

    if (!transactions.length) return null;

    const inactiveStatuses = [TransactionStatus.CANCELED, TransactionStatus.REJECTED, TransactionStatus.ARCHIVED];

    const transaction =
      transactions.find(t => !inactiveStatuses.includes(t.status)) ??
      transactions[0]; // most recent, since ordered by id DESC
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L629-651)
```typescript
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L659-671)
```typescript
  async cancelTransactionWithOutcome(
    id: number,
    user: User,
  ): Promise<CancelTransactionOutcome> {
    const transaction = await this.getTransactionForCreator(id, user);

    if (transaction.status === TransactionStatus.CANCELED) {
      return CancelTransactionOutcome.ALREADY_CANCELED;
    }

    if (!this.cancelableStatuses.includes(transaction.status)) {
      throw new BadRequestException(ErrorCodes.OTIP);
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

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L313-316)
```typescript
  @Delete('/:id')
  deleteTransaction(@GetUser() user, @Param('id', ParseIntPipe) id: number): Promise<boolean> {
    return this.transactionsService.removeTransaction(id, user, true);
  }
```
