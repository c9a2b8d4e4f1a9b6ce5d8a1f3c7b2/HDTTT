All code references have been verified against the actual source. The vulnerability is confirmed.

---

Audit Report

## Title
`removeTransaction` Lacks Status Guard, Allowing Creators to Overwrite Terminal Transaction States and Corrupt Audit Trail

## Summary
`removeTransaction` performs no status validation before acting on a transaction. Any creator can call `DELETE /transactions/:id` to overwrite a terminal status (`EXECUTED`, `FAILED`, `EXPIRED`, `REJECTED`) with `CANCELED` and soft-delete the record. Via `removeTransactionGroup`, a creator can permanently hard-delete executed transactions from the database. The `cancelableStatuses` allowlist enforced in `cancelTransactionWithOutcome` is completely bypassed.

## Finding Description

`cancelTransactionWithOutcome` enforces a strict status guard:

```typescript
if (!this.cancelableStatuses.includes(transaction.status)) {
  throw new BadRequestException(ErrorCodes.OTIP);
}
``` [1](#0-0) 

The `cancelableStatuses` allowlist contains only `NEW`, `WAITING_FOR_SIGNATURES`, and `WAITING_FOR_EXECUTION`: [2](#0-1) 

`removeTransaction`, by contrast, calls only `getTransactionForCreator` (ownership check, no status check), then unconditionally overwrites the status and removes the record:

```typescript
async removeTransaction(id: number, user: User, softRemove: boolean = true): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user); // ownership only

    if (softRemove) {
      await this.repo.update(transaction.id, { status: TransactionStatus.CANCELED }); // overwrites any state
      await this.repo.softRemove(transaction);
    } else {
      await this.repo.remove(transaction); // hard delete, no state check
    }
``` [3](#0-2) 

`getTransactionForCreator` confirms it only validates ownership, not status: [4](#0-3) 

The `DELETE /:id` controller endpoint routes directly to `removeTransaction` with `softRemove=true`: [5](#0-4) 

For group transactions, `removeTransactionGroup` calls `removeTransaction` with `softRemove=false` (hard delete) for every item in the group, with no status pre-check:

```typescript
for (const groupItem of groupItems) {
    const transactionId = groupItem.transactionId;
    await this.dataSource.manager.remove(TransactionGroupItem, groupItem);
    await this.transactionsService.removeTransaction(transactionId, user, false); // hard delete, no status guard
}
``` [6](#0-5) 

The group delete endpoint is exposed at `DELETE /transaction-groups/:id`: [7](#0-6) 

## Impact Explanation

- **Audit trail corruption**: An `EXECUTED` transaction — one that has already been submitted to the Hedera network and produced a receipt — can have its database status overwritten to `CANCELED` and be soft-deleted. Any downstream system, compliance check, or UI query relying on the database record will see a false state.
- **Permanent record destruction**: Via `removeTransactionGroup`, a creator can permanently hard-delete `EXECUTED` transactions from the database, making the on-chain execution unreconcilable with the application's own records.
- **State invariant violation**: The system's own `cancelableStatuses` allowlist (enforced in `cancelTransactionWithOutcome`) is completely bypassed by `removeTransaction`, breaking the intended state machine.

## Likelihood Explanation

Any authenticated user who created a transaction can trigger this with a standard `DELETE` HTTP request — no admin keys, no special privileges, no race condition required. The attacker precondition is simply: be the creator of a transaction that has reached a terminal state. This is a normal, reachable user flow.

## Recommendation

Add a status guard to `removeTransaction` before performing any mutation. The guard should mirror the one in `cancelTransactionWithOutcome`:

```typescript
async removeTransaction(id: number, user: User, softRemove: boolean = true): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);

    // Add status guard: only allow removal of non-terminal transactions
    if (!this.cancelableStatuses.includes(transaction.status)) {
      throw new BadRequestException(ErrorCodes.OTIP);
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

For `removeTransactionGroup`, add a pre-check that rejects the entire group delete if any transaction is in a terminal state, or at minimum skip/reject individual terminal-state transactions rather than hard-deleting them. [8](#0-7) 

## Proof of Concept

**Single transaction (soft-delete, status overwrite):**
1. Creator submits a transaction; it reaches `EXECUTED` status.
2. Creator sends: `DELETE /transactions/{id}` with a valid JWT.
3. `removeTransaction` calls `getTransactionForCreator` — passes (creator owns it).
4. No status check occurs.
5. `repo.update(transaction.id, { status: TransactionStatus.CANCELED })` overwrites `EXECUTED` → `CANCELED`.
6. `repo.softRemove(transaction)` soft-deletes the record.
7. The database now shows the transaction as `CANCELED` (soft-deleted), hiding the on-chain execution.

**Group transaction (hard-delete, permanent destruction):**
1. Creator creates a group of transactions; they reach `EXECUTED` status.
2. Creator sends: `DELETE /transaction-groups/{groupId}` with a valid JWT.
3. `removeTransactionGroup` iterates all group items with no status check.
4. For each item: `removeTransaction(transactionId, user, false)` is called.
5. `repo.remove(transaction)` permanently hard-deletes each `EXECUTED` transaction.
6. All on-chain execution records are permanently erased from the application database. [9](#0-8) [6](#0-5)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L92-96)
```typescript
  private readonly cancelableStatuses = [
    TransactionStatus.NEW,
    TransactionStatus.WAITING_FOR_SIGNATURES,
    TransactionStatus.WAITING_FOR_EXECUTION,
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
