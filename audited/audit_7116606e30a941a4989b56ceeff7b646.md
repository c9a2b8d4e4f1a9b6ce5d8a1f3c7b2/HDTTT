### Title
`removeTransaction` Lacks Status Guard, Allowing Creators to Overwrite Terminal Transaction States and Corrupt Audit Trail

### Summary
`removeTransaction` and `cancelTransaction` are two functions with overlapping functionality — both can cancel a transaction — but they diverge critically in their state validation. `cancelTransaction` enforces a strict status allowlist before acting, while `removeTransaction` performs no status check at all, allowing a creator to overwrite any terminal state (`EXECUTED`, `FAILED`, `EXPIRED`, `REJECTED`) with `CANCELED` and soft-delete the record. For group transactions, `removeTransactionGroup` calls `removeTransaction` with hard-delete (`softRemove=false`), permanently erasing transactions regardless of their execution state.

### Finding Description

`cancelTransactionWithOutcome` enforces a strict status guard before acting:

```typescript
if (!this.cancelableStatuses.includes(transaction.status)) {
  throw new BadRequestException(ErrorCodes.OTIP);
}
``` [1](#0-0) 

`removeTransaction`, by contrast, calls only `getTransactionForCreator`, which checks ownership but **not status**, then unconditionally overwrites the status and removes the record:

```typescript
async removeTransaction(id: number, user: User, softRemove: boolean = true): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user); // ownership only, no status check

    if (softRemove) {
      await this.repo.update(transaction.id, { status: TransactionStatus.CANCELED }); // overwrites any state
      await this.repo.softRemove(transaction);
    } else {
      await this.repo.remove(transaction); // hard delete, no state check
    }
``` [2](#0-1) 

`getTransactionForCreator` confirms it only validates ownership:

```typescript
async getTransactionForCreator(id: number, user: User) {
    const transaction = await this.getTransactionById(id);
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);
    if (transaction.creatorKey?.userId !== user?.id)
      throw new UnauthorizedException('Only the creator has access to this transaction');
    return transaction;
}
``` [3](#0-2) 

The `DELETE /:id` controller endpoint routes directly to `removeTransaction`: [4](#0-3) 

For group transactions, `removeTransactionGroup` calls `removeTransaction` with `softRemove=false` (hard delete) for every item in the group, with no status pre-check:

```typescript
for (const groupItem of groupItems) {
    const transactionId = groupItem.transactionId;
    await this.dataSource.manager.remove(TransactionGroupItem, groupItem);
    await this.transactionsService.removeTransaction(transactionId, user, false); // hard delete, no status guard
}
``` [5](#0-4) 

**Exploit path:**
1. Creator submits a transaction; it reaches `EXECUTED` (or `FAILED`, `EXPIRED`, `REJECTED`).
2. Creator calls `DELETE /transactions/:id`.
3. `removeTransaction` sets status to `CANCELED` (overwriting `EXECUTED`) and soft-removes the record.
4. For a group: creator calls the group delete endpoint; `removeTransactionGroup` hard-deletes all group transactions regardless of state.

### Impact Explanation

- **Audit trail corruption**: An `EXECUTED` transaction — one that has already been submitted to the Hedera network and produced a receipt — can have its database status overwritten to `CANCELED` and be soft-deleted. Any downstream system, compliance check, or UI query relying on the database record will see a false state.
- **Permanent record destruction**: Via `removeTransactionGroup`, a creator can permanently hard-delete `EXECUTED` transactions from the database, making the on-chain execution unreconcilable with the application's own records.
- **State invariant violation**: The system's own `cancelableStatuses` allowlist (enforced in `cancelTransaction`) is completely bypassed by `removeTransaction`, breaking the intended state machine.

### Likelihood Explanation

Any authenticated user who created a transaction can trigger this with a standard `DELETE` HTTP request — no admin keys, no special privileges, no race condition required. The attacker precondition is simply: be the creator of a transaction that has reached a terminal state. This is a normal, reachable user flow.

### Recommendation

Add a status guard to `removeTransaction` mirroring the one in `cancelTransactionWithOutcome`. Only allow removal of transactions in non-terminal states (or explicitly define which states are removable):

```typescript
async removeTransaction(id: number, user: User, softRemove: boolean = true): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);

    // Guard: prevent removal of terminal-state transactions
    const removableStatuses = [
      TransactionStatus.NEW,
      TransactionStatus.WAITING_FOR_SIGNATURES,
      TransactionStatus.WAITING_FOR_EXECUTION,
      TransactionStatus.CANCELED,
    ];
    if (!removableStatuses.includes(transaction.status)) {
      throw new BadRequestException('Transaction cannot be removed in its current state.');
    }
    ...
}
```

Apply the same guard in `removeTransactionGroup` before iterating over group items.

### Proof of Concept

1. Authenticate as a normal user (creator).
2. Create a transaction and let it reach `EXECUTED` state (or `FAILED`, `EXPIRED`).
3. Send `DELETE /transactions/:id` with the creator's JWT.
4. Observe: HTTP 200 returned; database record now has `status = CANCELED` and `deletedAt` set — the `EXECUTED` state is gone.
5. For group variant: create a transaction group, let transactions execute, then call the group delete endpoint. All transactions are permanently hard-deleted from the database regardless of their execution state. [6](#0-5) [7](#0-6)

### Citations

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
