All code references in the claim have been verified against the actual source. Here is the result:

---

Audit Report

## Title
`removeTransaction` Lacks Status Guard, Allowing Creator to Soft-Delete and Corrupt State of Executed Transactions

## Summary
The `removeTransaction` function in `back-end/apps/api/src/transactions/transactions.service.ts` performs no status validation before soft-deleting a transaction. Unlike `cancelTransactionWithOutcome`, which enforces a strict `cancelableStatuses` allowlist, `removeTransaction` accepts any transaction status — including terminal states like `EXECUTED`, `FAILED`, `EXPIRED`, `REJECTED`, and `ARCHIVED`. A malicious creator can call `DELETE /transactions/:id` on an already-executed transaction, overwriting its status to `CANCELED` and soft-deleting the record, permanently hiding it from all other participants and corrupting the audit trail.

## Finding Description

**Root cause — missing status guard in `removeTransaction`:**

`cancelTransactionWithOutcome` correctly enforces a status allowlist:

```typescript
private readonly cancelableStatuses = [
  TransactionStatus.NEW,
  TransactionStatus.WAITING_FOR_SIGNATURES,
  TransactionStatus.WAITING_FOR_EXECUTION,
];
...
if (!this.cancelableStatuses.includes(transaction.status)) {
  throw new BadRequestException(ErrorCodes.OTIP);
}
``` [1](#0-0) [2](#0-1) 

`removeTransaction`, however, has no such check. It only verifies the caller is the creator, then unconditionally sets `status = CANCELED` and soft-removes the record:

```typescript
async removeTransaction(id: number, user: User, softRemove: boolean = true): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user); // only checks ownership

    if (softRemove) {
      await this.repo.update(transaction.id, { status: TransactionStatus.CANCELED });
      await this.repo.softRemove(transaction);
    } else {
      await this.repo.remove(transaction);
    }
    ...
}
``` [3](#0-2) 

`getTransactionForCreator` only checks ownership, not status:

```typescript
async getTransactionForCreator(id: number, user: User) {
    const transaction = await this.getTransactionById(id);
    if (!transaction) { throw new BadRequestException(ErrorCodes.TNF); }
    if (transaction.creatorKey?.userId !== user?.id) {
      throw new UnauthorizedException('Only the creator has access to this transaction');
    }
    return transaction;
}
``` [4](#0-3) 

**Exposed endpoint:**

`DELETE /transactions/:id` directly calls `removeTransaction(id, user, true)` with no additional guards:

```typescript
@Delete('/:id')
deleteTransaction(@GetUser() user, @Param('id', ParseIntPipe) id: number): Promise<boolean> {
    return this.transactionsService.removeTransaction(id, user, true);
}
``` [5](#0-4) 

**Secondary path — `removeTransactionGroup`:**

`removeTransactionGroup` also calls `removeTransaction(transactionId, user, false)` (hard delete) for every transaction in a group, again with no status check, permanently deleting records regardless of their state:

```typescript
for (const groupItem of groupItems) {
    const transactionId = groupItem.transactionId;
    await this.dataSource.manager.remove(TransactionGroupItem, groupItem);
    await this.transactionsService.removeTransaction(transactionId, user, false);
}
``` [6](#0-5) 

The codebase explicitly defines `terminalStatuses` (including `EXECUTED`, `EXPIRED`, `FAILED`, `CANCELED`, `ARCHIVED`, `REJECTED`) but this array is never consulted inside `removeTransaction`: [7](#0-6) 

## Impact Explanation

- **Audit trail destruction**: A creator can permanently hide evidence of executed Hedera transactions from all other participants. The on-chain execution is irreversible, but the organizational record is erased. TypeORM's soft-delete mechanism excludes `deletedAt IS NOT NULL` rows from all default queries, making the record invisible to signers, observers, and approvers.
- **State integrity violation**: `EXECUTED` is a terminal state. Overwriting it to `CANCELED` via soft-delete breaks the invariant that terminal states are immutable, directly contradicting the explicit guard in `cancelTransactionWithOutcome`.
- **Participant access loss**: Signers, observers, and approvers who participated in the transaction lose all visibility into it after the soft-delete, with no recourse.
- **Hard-delete path**: Via `removeTransactionGroup`, the record is permanently and irrecoverably deleted from the database for any status, including `EXECUTED`.

## Likelihood Explanation

- **Attacker preconditions**: Only requires a valid authenticated session as the creator of any transaction — the lowest possible privilege level in the system.
- **Attack path**: A single authenticated `DELETE /transactions/:id` HTTP request after the transaction reaches `EXECUTED` status.
- **No special timing or race condition required**: The creator can call DELETE at any point after execution completes.
- **Realistic scenario**: A malicious insider (e.g., a rogue employee who created a transaction) can erase the organizational record of an executed fund transfer or account change.

## Recommendation

Add a status guard at the beginning of `removeTransaction` that rejects requests for terminal-state transactions, mirroring the pattern already used in `cancelTransactionWithOutcome`:

```typescript
async removeTransaction(id: number, user: User, softRemove: boolean = true): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);

    // Add this guard:
    const removableStatuses = [
      TransactionStatus.NEW,
      TransactionStatus.WAITING_FOR_SIGNATURES,
      TransactionStatus.WAITING_FOR_EXECUTION,
      TransactionStatus.CANCELED,   // allow cleanup of already-canceled
    ];
    if (!removableStatuses.includes(transaction.status)) {
      throw new BadRequestException(ErrorCodes.OTIP); // or a dedicated error code
    }
    ...
}
```

The same guard should be applied (or enforced at the call site) in `removeTransactionGroup` before iterating over group items.

## Proof of Concept

1. Authenticated user (creator) creates a transaction via `POST /transactions`.
2. Required signers sign the transaction; it transitions to `WAITING_FOR_EXECUTION` → `EXECUTED`.
3. Creator sends: `DELETE /transactions/<id>` with a valid JWT.
4. `deleteTransaction` controller calls `removeTransaction(id, user, true)`.
5. `getTransactionForCreator` passes (ownership check only).
6. `repo.update(transaction.id, { status: TransactionStatus.CANCELED })` overwrites the `EXECUTED` status.
7. `repo.softRemove(transaction)` sets `deletedAt = NOW()`.
8. All subsequent queries (which exclude soft-deleted rows by default) return "not found" for this transaction.
9. Signers, observers, and approvers permanently lose visibility into the executed transaction, and the audit trail is destroyed.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L92-96)
```typescript
  private readonly cancelableStatuses = [
    TransactionStatus.NEW,
    TransactionStatus.WAITING_FOR_SIGNATURES,
    TransactionStatus.WAITING_FOR_EXECUTION,
  ];
```

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L669-671)
```typescript
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

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L187-191)
```typescript
    for (const groupItem of groupItems) {
      const transactionId = groupItem.transactionId;
      await this.dataSource.manager.remove(TransactionGroupItem, groupItem);
      await this.transactionsService.removeTransaction(transactionId, user, false);
    }
```
