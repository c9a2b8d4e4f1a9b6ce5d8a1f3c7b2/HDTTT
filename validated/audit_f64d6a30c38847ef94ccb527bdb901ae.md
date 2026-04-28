### Title
TOCTOU Race Condition in `archiveTransaction` Allows Overwriting a Terminal Transaction Status

### Summary
`archiveTransaction` in `transactions.service.ts` reads the transaction status, validates it, then performs an **unconditional** `repo.update` to `ARCHIVED` with no WHERE guard on the current status. The chain service's concurrent execution can change the status to `EXECUTED` between the read and the write, causing a successfully-executed Hedera transaction to be permanently recorded as `ARCHIVED`, corrupting the audit trail for all participants.

### Finding Description

**Root cause — non-atomic check-then-act:**

`archiveTransaction` reads the transaction row, validates the status, then issues a plain update with no status condition:

```typescript
// back-end/apps/api/src/transactions/transactions.service.ts
async archiveTransaction(id: number, user: User): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);   // READ

    if (
      ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
        transaction.status,
      ) &&
      !transaction.isManual
    ) {
      throw new BadRequestException(ErrorCodes.OMTIP);
    }

    await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED }); // UNCONDITIONAL WRITE
``` [1](#0-0) 

The update at line 720 carries **no `WHERE status = ...` guard**. Any status present at read-time can be overwritten.

**Contrast with the safe pattern used elsewhere:**

`cancelTransactionWithOutcome` and `_executeTransaction` both use a conditional WHERE clause to make the check-and-update atomic:

```typescript
// cancelTransactionWithOutcome
.andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })

// _executeTransaction (chain service)
.where('id = :id AND status = :currentStatus', {
    id: transaction.id,
    currentStatus: TransactionStatus.WAITING_FOR_EXECUTION,
})
``` [2](#0-1) [3](#0-2) 

**Race window — two failure modes:**

| Race outcome | Result |
|---|---|
| Archive write wins first (status → ARCHIVED) | Chain service submits to Hedera but its conditional update (`status = WAITING_FOR_EXECUTION`) finds no matching row; transaction is executed on-chain but DB shows `ARCHIVED` |
| Chain service wins first (status → EXECUTED) | Archive's unconditional update overwrites `EXECUTED` with `ARCHIVED`; execution result is hidden |

**Entry point:**

`PATCH /transactions/archive/:id` is accessible to any authenticated, verified user who is the transaction creator — no privileged role required. [4](#0-3) 

### Impact Explanation

- A transaction executed on the Hedera network is permanently recorded as `ARCHIVED` in the database.
- `executedAt`, `statusCode`, and `receipt` fields may be set (if the chain service won the race) but the `status` field is wrong, breaking any downstream logic that checks `status`.
- All participants (signers, observers) see `ARCHIVED` instead of `EXECUTED`, losing visibility into the real on-chain outcome.
- If the archive wins first, the chain service cannot update the row, so `executedAt`/`statusCode`/`receipt` are never written — the execution is invisible in the system entirely.
- Users may attempt to re-submit the transaction, causing a duplicate-transaction error on Hedera.

### Likelihood Explanation

- The race window is the time between the chain service's scheduler picking up a `WAITING_FOR_EXECUTION` transaction and completing its conditional update — typically seconds.
- The transaction creator (a normal, unprivileged user) can call `PATCH /transactions/archive/:id` at any time.
- No special tooling is needed; a user who decides to archive a transaction that is simultaneously being executed by the scheduler will trigger this naturally.
- The chain service runs on a polling schedule (`updateTransactions` / `prepareTransactions`), making the window predictable. [5](#0-4) 

### Recommendation

Replace the unconditional `repo.update` in `archiveTransaction` with a conditional query-builder update that guards on the expected current status, mirroring the pattern already used in `cancelTransactionWithOutcome`:

```typescript
const updateResult = await this.repo
  .createQueryBuilder()
  .update(Transaction)
  .set({ status: TransactionStatus.ARCHIVED })
  .where('id = :id', { id })
  .andWhere('status IN (:...archivableStatuses)', {
    archivableStatuses: [
      TransactionStatus.WAITING_FOR_SIGNATURES,
      TransactionStatus.WAITING_FOR_EXECUTION,
    ],
  })
  .execute();

if (!updateResult.affected || updateResult.affected === 0) {
  // Re-read and surface the actual current status to the caller
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

This makes the check-and-update atomic at the database level, eliminating the TOCTOU window.

### Proof of Concept

1. Attacker (transaction creator) creates a transaction and collects enough signatures so it reaches `WAITING_FOR_EXECUTION`.
2. The chain service scheduler picks up the transaction and begins executing it on Hedera (calls `_executeTransaction`).
3. Before the chain service's conditional `UPDATE ... WHERE status = 'WAITING_FOR_EXECUTION'` completes, the attacker sends `PATCH /transactions/archive/:id`.
4. `archiveTransaction` reads status as `WAITING_FOR_EXECUTION` (passes the guard), then issues `UPDATE transaction SET status = 'ARCHIVED' WHERE id = :id` — no status condition.
5. **Scenario A**: Archive write lands first → status is `ARCHIVED`; chain service update finds 0 rows (`status ≠ WAITING_FOR_EXECUTION`), returns `null`, emits no notification. Transaction is executed on Hedera but the system records it as `ARCHIVED` with no `executedAt`, `statusCode`, or `receipt`.
6. **Scenario B**: Chain service write lands first → status is `EXECUTED`; archive write unconditionally overwrites to `ARCHIVED`. All participants see `ARCHIVED`; the execution result is hidden. [6](#0-5) [7](#0-6)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L673-679)
```typescript
    const updateResult = await this.repo
      .createQueryBuilder()
      .update(Transaction)
      .set({ status: TransactionStatus.CANCELED })
      .where('id = :id', { id })
      .andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
      .execute();
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L708-733)
```typescript
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

**File:** back-end/libs/common/src/execute/execute.service.ts (L187-198)
```typescript
    const updateResult = await this.transactionsRepo
      .createQueryBuilder()
      .update(Transaction)
      .set({ status: transactionStatus, executedAt, statusCode: transactionStatusCode })
      .where('id = :id AND status = :currentStatus', {
        id: transaction.id,
        currentStatus: TransactionStatus.WAITING_FOR_EXECUTION,
      })
      .returning('id')
      .execute();

    if (updateResult.raw.length === 0) return null;
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L264-270)
```typescript
  @Patch('/archive/:id')
  async archiveTransaction(
    @GetUser() user,
    @Param('id', ParseIntPipe) id: number,
  ): Promise<boolean> {
    return this.transactionsService.archiveTransaction(id, user);
  }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L130-161)
```typescript
  /* Checks if the signers are enough to sign the transactions and update their statuses */
  async updateTransactions(from: Date, to?: Date) {
    //Get the transaction, creatorKey, groupItem, and group. We need the group info upfront
    //in order to determine if the group needs to be processed together
    const transactions = await this.transactionRepo.find({
      where: {
        status: In([
          TransactionStatus.WAITING_FOR_SIGNATURES,
          TransactionStatus.WAITING_FOR_EXECUTION,
        ]),
        validStart: to ? Between(from, to) : MoreThan(from),
      },
      relations: {
        creatorKey: true,
        groupItem: {
          group: true,
        },
      },
      order: {
        validStart: 'ASC',
      },
    });

    const results = await processTransactionStatus(this.transactionRepo, this.transactionSignatureService, transactions);

    if (results.size > 0) {
      const events = Array.from(results.keys(), id => ({ entityId: id }));
      emitTransactionStatusUpdate(this.notificationsPublisher, events);
    }

    return transactions;
  }
```
