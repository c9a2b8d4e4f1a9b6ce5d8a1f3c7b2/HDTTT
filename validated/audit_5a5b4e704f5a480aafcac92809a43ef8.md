I have read the actual source code. Let me verify each claim against the real implementation before rendering a verdict.

**Key files examined:**
- `back-end/libs/common/src/execute/execute.service.ts`
- `back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts`
- `back-end/libs/common/src/execute/execute.service.spec.ts`

**Verification of each claim point:**

1. **Pre-validation loop that throws on first failure** — Confirmed by the test at line 459–469 of `execute.service.spec.ts`: when `getValidatedSDKTransaction` throws for transaction index 0, the entire group rejects with `"Transaction Group cannot be submitted. Error validating transaction 0: ..."`. The `mockRejectedValueOnce` pattern confirms only the first call throws, yet the whole group is aborted.

2. **`validateTransactionStatus` re-fetches from DB** — Confirmed at lines 226–230 of `execute.service.ts`: it calls `this.transactionsRepo.findOne({ where: { id: transaction.id }, select: ['status'] })` — a live DB read, not the in-memory object.

3. **In-memory filter uses stale status** — Confirmed: `prepareTransactions` loads the group once via `transactionGroupRepo.findOne` (lines 175–189 of `transaction-scheduler.service.ts`) and passes the object to `collateGroupAndExecute` → `addGroupExecutionTimeout` → `executeTransactionGroup`. The object is never refreshed before the timeout fires.

4. **TOCTOU gap is real** — The in-memory filter correctly skips transactions whose in-memory status is already `CANCELED` (confirmed by test at line 472–493). However, if the in-memory status is stale (`WAITING_FOR_EXECUTION`) while the DB has been updated to `CANCELED`, the filter passes and `validateTransactionStatus` throws — blocking the whole group.

5. **`addGroupExecutionTimeout` error handler** — Confirmed at lines 338–346 of `transaction-scheduler.service.ts`: the `catch` block only calls `console.log(error)`. No retry, no per-transaction status update, no recovery.

6. **Remaining transactions left in `WAITING_FOR_EXECUTION`** — Confirmed: the expiry cron at lines 100–128 of `transaction-scheduler.service.ts` will eventually mark them `EXPIRED`, but there is no active recovery path.

All claims check out against the actual code. The finding is valid.

---

# Audit Report

## Title
Whole-Group Execution Blocked by Single Transaction Validation Failure in `executeTransactionGroup`

## Summary
`executeTransactionGroup` in `ExecuteService` performs a pre-execution validation pass over all non-filtered group items before submitting any of them to Hedera. Each item's status is re-fetched live from the database inside `validateTransactionStatus`. If any item's DB status has changed (e.g., to `CANCELED`, `EXPIRED`, `REJECTED`) since the group was loaded into memory, the function throws immediately, permanently blocking all other valid transactions in the group from executing. The caller (`addGroupExecutionTimeout`) catches the error, logs it, and deletes the timeout with no recovery path.

## Finding Description

**Root cause — stale in-memory object + live DB re-fetch mismatch:**

`prepareTransactions` loads the full `TransactionGroup` from the database once and passes it to `collateGroupAndExecute`: [1](#0-0) 

This object is captured in the `collateGroupAndExecute` closure and later forwarded to `addGroupExecutionTimeout`, which registers a `setTimeout` callback that holds a reference to the same stale object: [2](#0-1) 

The object is never refreshed between registration and firing. When the timeout fires, `executeTransactionGroup` calls `getValidatedSDKTransaction` for each item that passes the in-memory status filter. `getValidatedSDKTransaction` calls `validateTransactionStatus`, which performs a **live DB read**: [3](#0-2) 

If the DB status has changed to `CANCELED` (or any other terminal state) since the in-memory load, `validateTransactionStatus` throws: [4](#0-3) 

The test suite confirms that this throw propagates out of `executeTransactionGroup` as a group-level rejection: [5](#0-4) 

The `addGroupExecutionTimeout` callback catches the error and only logs it — no retry, no per-transaction status update: [2](#0-1) 

The remaining valid transactions are left in `WAITING_FOR_EXECUTION` until the expiry cron marks them `EXPIRED`: [6](#0-5) 

**Important distinction:** The in-memory filter correctly skips transactions whose in-memory status is already `CANCELED` (confirmed by the test at line 472–493 of `execute.service.spec.ts`). The vulnerability only triggers when the in-memory status is stale (`WAITING_FOR_EXECUTION`) while the DB has been updated to a terminal state — the classic TOCTOU pattern.

## Impact Explanation

All valid transactions in a group are permanently prevented from executing within their valid window. They are left in `WAITING_FOR_EXECUTION` with no recovery path and eventually expire. In an organization context, this means batch operations (payroll, multi-account updates, scheduled transfers) silently fail in their entirety because of one member's action or a timing race. The state corruption is unrecoverable without manual intervention.

## Likelihood Explanation

The TOCTOU window exists for every group execution: the group is loaded once into memory and the stale object is used until the timeout fires (up to ~15 seconds before valid start). Any state change to any group item during that window (cancel, expiry race) triggers the DoS. A malicious organization member can deliberately cancel one transaction just before execution to block the entire group. No privileged access is required — canceling one's own transaction is a normal user action. The same outcome occurs naturally if the expiry cron races with the execution timeout, making this also a reliability failure independent of malicious intent.

## Recommendation

1. **Re-fetch the group from the database inside `executeTransactionGroup`** (or at the start of the timeout callback) rather than relying on the stale in-memory object. This eliminates the TOCTOU window entirely.

2. **Skip rather than throw on per-item validation failure.** For non-atomic groups, if a single item fails validation (e.g., `CANCELED`), skip that item and continue executing the remaining valid items. Only abort the entire group for `atomic: true` groups where all-or-nothing semantics are required.

3. **Update the status of remaining valid transactions on group-level abort.** If the group must be aborted (e.g., atomic group with one invalid item), update the remaining `WAITING_FOR_EXECUTION` transactions to `FAILED` with an appropriate status code and emit notifications, rather than leaving them stranded.

## Proof of Concept

1. Attacker is a member of an organization and participates in a `TransactionGroup` with N transactions (e.g., a batch payroll group with `sequential: true`).
2. The chain service cron (`handleTransactionsBetweenNowAndAfterThreeMinutes`) runs, loads the group into memory via `prepareTransactions` → `transactionGroupRepo.findOne`, and registers the `collateGroupAndExecute` timeout. All in-memory statuses are `WAITING_FOR_EXECUTION`.
3. Before the `addGroupExecutionTimeout` fires, the attacker calls the cancel API endpoint for one transaction in the group. The DB status for that transaction is now `CANCELED`. The in-memory object is not updated.
4. The execution timeout fires. `executeTransactionGroup` is called with the stale in-memory object.
5. The in-memory filter passes for the attacker's transaction (stale status = `WAITING_FOR_EXECUTION`).
6. `getValidatedSDKTransaction` → `validateTransactionStatus` re-fetches from DB, finds `CANCELED`, throws `"Transaction has been canceled."`.
7. `executeTransactionGroup` propagates the throw: `"Transaction Group cannot be submitted. Error validating transaction X: Transaction has been canceled."`.
8. `addGroupExecutionTimeout` catches the error, logs it, deletes the timeout. No further action.
9. All N-1 remaining valid transactions are permanently stuck in `WAITING_FOR_EXECUTION` and eventually expire without ever being submitted to Hedera.

### Citations

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L100-128)
```typescript
  @Cron(CronExpression.EVERY_10_SECONDS, {
    name: 'status_update_expired_transactions',
  })
  async handleExpiredTransactions() {
    const result = await this.transactionRepo
      .createQueryBuilder()
      .update(Transaction)
      .set({ status: TransactionStatus.EXPIRED })
      .where('status IN (:...statuses) AND validStart < :before', {
        statuses: [
          TransactionStatus.NEW,
          TransactionStatus.REJECTED,
          TransactionStatus.WAITING_FOR_EXECUTION,
          TransactionStatus.WAITING_FOR_SIGNATURES,
        ],
        before: this.getThreeMinutesBefore(),
      })
      .returning(['id'])
      .execute();

    if (result.raw.length > 0) {
      emitTransactionStatusUpdate(
        this.notificationsPublisher,
        result.raw.map(t => ({
          entityId: t.id,
        })),
      );
    }
  }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L175-192)
```typescript
            const transactionGroup = await this.transactionGroupRepo.findOne({
              where: { id: transaction.groupItem.groupId },
              relations: {
                groupItems: {
                  transaction: true,
                },
              },
              order: {
                groupItems: {
                  transaction: {
                    validStart: 'ASC',
                  },
                },
              },
            });
            // All the transactions for the group are now pulled. If there is an issue validating for even one
            // transaction, the group will not be executed. This is handled in executeTransactionGroup
            this.collateGroupAndExecute(transactionGroup);
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L338-346)
```typescript
    const callback = async () => {
      try {
        await this.executeService.executeTransactionGroup(transactionGroup);
      } catch (error) {
        console.log(error);
      } finally {
        this.schedulerRegistry.deleteTimeout(name);
      }
    };
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L226-230)
```typescript
  private async validateTransactionStatus(transaction: Transaction) {
    const { status } = await this.transactionsRepo.findOne({
      where: { id: transaction.id },
      select: ['status'],
    });
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L243-244)
```typescript
      case TransactionStatus.CANCELED:
        throw new Error('Transaction has been canceled.');
```

**File:** back-end/libs/common/src/execute/execute.service.spec.ts (L459-469)
```typescript
    it('should throw error if failed to get validated transaction from the group', async () => {
      const errorMessage = 'Transaction not found';
      jest
        // @ts-expect-error private function
        .spyOn(service, 'getValidatedSDKTransaction')
        // @ts-expect-error private function
        .mockRejectedValueOnce(new Error(errorMessage));

      await expect(service.executeTransactionGroup(transactionGroup)).rejects.toThrow(
        `Transaction Group cannot be submitted. Error validating transaction 0: ${errorMessage}`,
      );
```
