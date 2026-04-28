Audit Report

## Title
Atomic Transaction Group Invariant Broken by Individual Transaction Cancellation

## Summary

The `TransactionGroup` entity exposes an `atomic` flag intended to guarantee all-or-nothing execution. However, individual transactions within an atomic group can be canceled via `PATCH /transactions/cancel/:id` without any check for group membership. The scheduler's `executeTransactionGroup` then silently filters out the canceled member and submits the remaining transactions to the Hedera network alone, permanently breaking the atomicity guarantee.

## Finding Description

**Root cause 1 — `cancelTransactionWithOutcome` has no atomic-group guard:**

`cancelTransactionWithOutcome` in `back-end/apps/api/src/transactions/transactions.service.ts` only verifies the caller is the transaction creator and that the status is cancelable. It never inspects `transaction.groupItem` or `transaction.groupItem.group.atomic`. [1](#0-0) 

The same omission exists in `archiveTransaction`, which can also remove a member from an atomic group without any group-membership check: [2](#0-1) 

Both are reachable by any authenticated creator via the controller: [3](#0-2) [4](#0-3) 

**Root cause 2 — `executeTransactionGroup` silently drops canceled members with no atomic guard:**

At the very start of `executeTransactionGroup`, the group's items are filtered to only those still in `WAITING_FOR_EXECUTION`. There is no subsequent check that aborts execution when the group is `atomic` and one or more members were removed by this filter: [5](#0-4) 

This behavior is even explicitly tested and expected — the test suite asserts that canceled members are silently skipped, with no distinction for atomic groups: [6](#0-5) 

The `TransactionGroup` entity does carry the `atomic` flag in the database, but `executeTransactionGroup` never reads it: [7](#0-6) 

**Scheduler routing:**

When the scheduler fires, `prepareTransactions` fetches the full group (including the now-CANCELED member) and routes it to `collateGroupAndExecute`, which proceeds to `executeTransactionGroup` without any pre-flight check on group completeness: [8](#0-7) 

## Impact Explanation

- **Broken atomicity**: Transactions declared atomic can execute partially. Any business logic depending on the all-or-nothing guarantee is violated.
- **Irreversible on-chain state**: Hedera transactions are final. A TX-B that executes without TX-A cannot be rolled back.
- **Concrete example**: If TX-A is a payment and TX-B is a service-delivery transaction, canceling TX-A while TX-B executes means the service is delivered without payment. If TX-A creates an account and TX-B transfers funds to it, TX-B will fail on-chain and the funds transfer is permanently lost.

## Likelihood Explanation

- **Attacker profile**: Any authenticated organization user who is the creator of the transactions. No privileged keys or admin access required.
- **Entry point**: Standard REST API endpoint `PATCH /transactions/cancel/:id`, reachable by any logged-in user.
- **Preconditions**: The attacker must have created the atomic group (a normal user action). The window is between both transactions reaching `WAITING_FOR_EXECUTION` and the scheduler firing.
- **Detectability**: The system emits no warning when an atomic group is partially executed; the UI shows individual transaction statuses without flagging the broken invariant.

## Recommendation

1. **In `cancelTransactionWithOutcome` and `archiveTransaction`**: After fetching the transaction, check whether it belongs to an atomic group. If `transaction.groupItem?.group?.atomic === true`, reject the individual cancellation/archive with an appropriate error (e.g., `BadRequestException`), and require the caller to use the group-level cancel endpoint instead.

2. **In `executeTransactionGroup`**: After filtering `groupItems` to `WAITING_FOR_EXECUTION`, check whether the group is `atomic` and whether the filtered count is less than the original count. If so, abort execution and mark all remaining `WAITING_FOR_EXECUTION` members as `FAILED` (or a new `ABORTED` status) with a descriptive status code.

3. **Add a group-level cancel endpoint guard**: The existing `cancelTransactionGroup` endpoint should be the only permitted path for canceling members of an atomic group.

## Proof of Concept

1. Authenticated user (creator) submits an atomic `TransactionGroup` containing TX-A and TX-B via `POST /transaction-groups` with `atomic: true`.
2. Both transactions accumulate required signatures and transition to `WAITING_FOR_EXECUTION`.
3. Creator calls `PATCH /transactions/cancel/{TX-A-id}`. `cancelTransactionWithOutcome` succeeds — TX-A is now `CANCELED`. No group-membership check is performed.
4. The chain-service scheduler (`prepareTransactions`) finds TX-B still in `WAITING_FOR_EXECUTION` with a `groupItem` pointing to the atomic group, fetches the full group (TX-A: CANCELED, TX-B: WAITING_FOR_EXECUTION), and routes it to `collateGroupAndExecute`.
5. `executeTransactionGroup` filters `groupItems` to only `WAITING_FOR_EXECUTION` — TX-A is silently dropped. TX-B is validated and submitted to the Hedera network alone.
6. The atomic group is partially executed. TX-B either fails on-chain (because its prerequisite TX-A never ran) or, worse, succeeds in an unintended state, producing an irreversible inconsistency.

### Citations

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L708-720)
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
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L248-254)
```typescript
  @Patch('/cancel/:id')
  async cancelTransaction(
    @GetUser() user,
    @Param('id', ParseIntPipe) id: number,
  ): Promise<boolean> {
    return this.transactionsService.cancelTransaction(id, user);
  }
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

**File:** back-end/libs/common/src/execute/execute.service.ts (L62-81)
```typescript
  @MurLock(15000, 'transactionGroup.id + "_group"')
  async executeTransactionGroup(transactionGroup: TransactionGroup) {
    this.logger.log('executing transactions');
    transactionGroup.groupItems = transactionGroup.groupItems.filter(
      tx => tx.transaction.status === TransactionStatus.WAITING_FOR_EXECUTION
    );
    const transactions: { sdkTransaction: SDKTransaction; transaction: Transaction }[] =
      [];
    // first we need to validate all the transactions, as they all need to be valid before we can execute any of them
    for (const groupItem of transactionGroup.groupItems) {
      const transaction = groupItem.transaction;
      try {
        const sdkTransaction = await this.getValidatedSDKTransaction(transaction);
        transactions.push({ sdkTransaction, transaction });
      } catch (error) {
        throw new Error(
          `Transaction Group cannot be submitted. Error validating transaction ${transaction.id}: ${error.message}`,
        );
      }
    }
```

**File:** back-end/libs/common/src/execute/execute.service.spec.ts (L472-493)
```typescript
    it('should execute all transactions except the canceled', async () => {
      const { receipt, response } = mockSDKTransactionExecution();

      transactionGroup.groupItems[0].transaction.status = TransactionStatus.CANCELED;

      transactionRepo.findOne.mockResolvedValue({
        status: TransactionStatus.WAITING_FOR_EXECUTION,
      } as Transaction);

      await service.executeTransactionGroup(transactionGroup);

      expect(response.getReceipt).toHaveBeenCalled();

      // Only non-canceled transactions should have triggered the query builder
      expect(mockQueryBuilder.set).toHaveBeenCalledWith({
        executedAt: expect.any(Date),
        status: TransactionStatus.EXECUTED,
        statusCode: receipt.status._code,
      });

      expect(client.close).toHaveBeenCalled();
    });
```

**File:** back-end/libs/common/src/database/entities/transaction-group.entity.ts (L12-13)
```typescript
  @Column({ default: false })
  atomic: boolean;
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L163-199)
```typescript
  async prepareTransactions(transactions: Transaction[]) {
    const processedGroupIds = new Set<number>();

    for (const transaction of transactions) {
      const waitingForExecution = transaction.status === TransactionStatus.WAITING_FOR_EXECUTION;

      if (waitingForExecution && this.isValidStartExecutable(transaction.validStart)) {
        if (transaction.groupItem && (transaction.groupItem.group.atomic || transaction.groupItem.group.sequential)) {
          if (!processedGroupIds.has(transaction.groupItem.groupId)) {
            processedGroupIds.add(transaction.groupItem.groupId);
            // Now that we are sure this transaction group needs to be processed together, get it
            // and being the processing
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
          }
        } else {
          this.collateAndExecute(transaction);
        }
      }
    }
  }
```
