### Title
TOCTOU State Transition in `archiveTransaction` Allows Creator to Overwrite Terminal Transaction Status

### Summary

`archiveTransaction` in `transactions.service.ts` reads the transaction status, validates it, then issues an unconditional `UPDATE` without re-checking the status atomically. If the chain service transitions the transaction to `EXECUTED` between the read and the write, the creator can overwrite the `EXECUTED` status with `ARCHIVED`, corrupting the system's record of a transaction that was already submitted to the Hedera network. The analogous `cancelTransaction` function correctly guards against this with a conditional `WHERE status IN (...)` clause; `archiveTransaction` does not.

### Finding Description

**Root cause — non-atomic read-check-write in `archiveTransaction`:** [1](#0-0) 

```
Step 1 (READ):  transaction = await this.getTransactionForCreator(id, user);
Step 2 (CHECK): if status NOT IN [WAITING_FOR_SIGNATURES, WAITING_FOR_EXECUTION] → throw
Step 3 (WRITE): await this.repo.update({ id }, { status: ARCHIVED });   ← no WHERE on status
```

The `UPDATE` at step 3 uses only `WHERE id = :id`. There is no `AND status IN (...)` guard. Any status change that occurs between step 1 and step 3 is silently overwritten.

**Contrast with the correctly-guarded `cancelTransaction`:** [2](#0-1) 

`cancelTransaction` uses `.andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })` so a concurrent status change causes the UPDATE to affect 0 rows, which is then detected and handled. `archiveTransaction` has no equivalent guard.

**Race window — chain service vs. API service:**

The chain service's `updateTransactions` scheduler continuously polls for `WAITING_FOR_EXECUTION` transactions and executes them: [3](#0-2) 

`processTransactionStatus` uses a conditional `WHERE id IN (...) AND status = :oldStatus` update, so it correctly transitions the status to `EXECUTED`. If this happens between step 1 and step 3 of `archiveTransaction`, the `EXECUTED` status is overwritten with `ARCHIVED`. [4](#0-3) 

### Impact Explanation

A transaction creator can cause the system's database to record `ARCHIVED` for a transaction that was already submitted to and executed on the Hedera network. Concrete consequences:

- **Integrity failure**: The system's state diverges from the Hedera ledger. The transaction was executed on-chain but the organization's tool shows it as archived.
- **Deception of co-participants**: Signers, observers, and approvers who rely on the tool to track transaction outcomes see `ARCHIVED` instead of `EXECUTED`, hiding the fact that the transaction was executed.
- **Audit trail corruption**: Historical records no longer accurately reflect what happened on-chain.

### Likelihood Explanation

The attacker is the transaction creator — a normal authenticated user with no elevated privileges. The race window is the time between the API's `getTransactionForCreator` call and the `repo.update` call. The chain service scheduler runs continuously. A creator who monitors when their transaction reaches `WAITING_FOR_EXECUTION` and immediately calls `PATCH /transactions/archive/:id` has a realistic chance of winning the race, especially under load. No special tooling is required beyond a standard HTTP client.

### Recommendation

Apply the same conditional-update pattern used in `cancelTransaction` to `archiveTransaction`:

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
  // Re-read and throw appropriate error
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

This makes the status check and the write atomic at the database level, eliminating the TOCTOU window.

### Proof of Concept

1. Authenticated user (creator) creates a transaction requiring one signature and provides it, moving the transaction to `WAITING_FOR_EXECUTION`.
2. Creator monitors the transaction status (polling `GET /transactions/:id`).
3. The moment the status is `WAITING_FOR_EXECUTION`, the creator immediately sends `PATCH /transactions/archive/:id`.
4. Concurrently, the chain service scheduler picks up the transaction and calls `processTransactionStatus`, which executes it on Hedera and sets status to `EXECUTED` in the DB.
5. If the API's `repo.update` (step 3 of `archiveTransaction`) executes after the chain service's update, the DB status is overwritten to `ARCHIVED`.
6. Result: Hedera ledger shows the transaction as executed; the organization tool shows it as `ARCHIVED`. All co-participants (signers, observers, approvers) see the corrupted status. [5](#0-4)

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

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L130-158)
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
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L157-173)
```typescript
  if (updatesByStatus.size > 0) {
    await Promise.all(
      Array.from(updatesByStatus.values()).map(async ({ newStatus, oldStatus, ids }) => {
        const result = await transactionRepo
          .createQueryBuilder()
          .update(Transaction)
          .set({ status: newStatus })
          .where('id IN (:...ids) AND status = :oldStatus', { ids, oldStatus })
          .returning('id')
          .execute();

        for (const row of result.raw) {
          statusChanges.set(row.id, newStatus);
        }
      })
    );
  }
```
