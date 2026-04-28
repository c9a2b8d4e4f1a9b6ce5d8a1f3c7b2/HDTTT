### Title
Creator Can Execute Manual Transaction Before Required Signatures Are Collected, Bypassing Multi-Sig Enforcement

### Summary
The `PATCH /transactions/execute/:id` endpoint in `TransactionsService.executeTransaction()` allows the transaction creator to submit a manual transaction to the Hedera network at any time, regardless of whether all required co-signers have signed. The scheduler (`TransactionSchedulerService`) enforces a strict status gate — only transactions in `WAITING_FOR_EXECUTION` status (meaning all required signatures are present) are submitted. The direct API path skips this gate entirely, analogous to calling `Pools.removeLiquidity()` directly instead of through `Router.removeLiquidity()` which provides IL protection.

### Finding Description

**Root cause — missing status check in `executeTransaction`:**

`back-end/apps/api/src/transactions/transactions.service.ts`, lines 736–751:

```typescript
async executeTransaction(id: number, user: User): Promise<boolean> {
  const transaction = await this.getTransactionForCreator(id, user);

  if (!transaction.isManual) {
    throw new BadRequestException(ErrorCodes.IO);
  }

  if (transaction.validStart.getTime() > Date.now()) {
    await this.repo.update({ id }, { isManual: false });
    emitTransactionUpdate(...);
  } else {
    await this.executeService.executeTransaction(transaction); // ← no status check
  }

  return true;
}
```

The only guards are:
1. Caller must be the creator (`getTransactionForCreator`).
2. Transaction must be flagged `isManual`.

There is **no check** that `transaction.status === TransactionStatus.WAITING_FOR_EXECUTION`.

**Contrast with the scheduler path** (`back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts`, lines 163–198):

```typescript
async prepareTransactions(transactions: Transaction[]) {
  for (const transaction of transactions) {
    const waitingForExecution =
      transaction.status === TransactionStatus.WAITING_FOR_EXECUTION; // ← enforced

    if (waitingForExecution && this.isValidStartExecutable(transaction.validStart)) {
      ...
      this.collateAndExecute(transaction);
    }
  }
}
```

The scheduler only submits transactions whose status has been promoted to `WAITING_FOR_EXECUTION` — a status that is only set after `processTransactionStatus` confirms all required signatures are present. The direct API endpoint bypasses this entire gate.

**Exploit path:**

1. Attacker (any authenticated user) creates a multi-sig transaction with `isManual: true`. Transaction enters `WAITING_FOR_SIGNATURES`.
2. Required co-signers begin signing but have not all signed yet.
3. Creator calls `PATCH /transactions/execute/:id` while `validStart ≤ now`.
4. `executeService.executeTransaction(transaction)` is called with the partially-signed transaction bytes.
5. Two outcomes:
   - **Hedera rejects it** (INVALID_SIGNATURE): transaction is marked `FAILED`, the transaction ID is consumed, co-signers can no longer complete it — effective sabotage of the multi-sig workflow.
   - **Hedera accepts it** (if the actual on-chain key structure requires fewer signatures than the tool's approval list): the transaction succeeds with fewer signatures than the tool intended to enforce, bypassing the tool's multi-sig policy.

### Impact Explanation

- **Sabotage**: A creator can force any of their own manual multi-sig transactions to fail at will, even after co-signers have invested effort in signing. The transaction ID is consumed on Hedera and cannot be reused.
- **Policy bypass**: If the Hedera key structure for the target account accepts fewer signatures than the tool's signer list requires, the creator can execute the transaction before all required tool-level signers have signed, defeating the multi-sig governance model the tool is designed to enforce.
- **Severity**: Medium — requires the attacker to be the transaction creator (a normal, unprivileged role), and the worst-case outcome is sabotage of their own transaction or bypass of the tool's signature-count policy.

### Likelihood Explanation

Any authenticated user can create transactions and mark them `isManual`. No privileged access is required. The endpoint `PATCH /transactions/execute/:id` is a standard REST call documented in the controller. A malicious or impatient creator can trigger this at any time after `validStart` has passed, which is a realistic scenario.

### Recommendation

Add an explicit status check inside `executeTransaction` before calling `executeService.executeTransaction`:

```typescript
async executeTransaction(id: number, user: User): Promise<boolean> {
  const transaction = await this.getTransactionForCreator(id, user);

  if (!transaction.isManual) {
    throw new BadRequestException(ErrorCodes.IO);
  }

  // Enforce the same gate the scheduler uses
  if (
    transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
    transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
  ) {
    throw new BadRequestException(ErrorCodes.OTIP);
  }

  if (transaction.validStart.getTime() > Date.now()) {
    await this.repo.update({ id }, { isManual: false });
    emitTransactionUpdate(...);
  } else {
    // Optionally also verify all required signatures are present before submitting
    await this.executeService.executeTransaction(transaction);
  }

  return true;
}
```

Alternatively, mirror the scheduler's `processTransactionStatus` check to confirm all required signatures are collected before allowing manual execution.

### Proof of Concept

1. Register two users (Alice = creator, Bob = required co-signer).
2. Alice creates a transaction requiring Bob's signature, with `isManual: true`. Status → `WAITING_FOR_SIGNATURES`.
3. Bob does **not** sign.
4. Alice calls `PATCH /transactions/execute/:id` (authenticated as Alice) after `validStart` has elapsed.
5. Observe: `executeService.executeTransaction` is called with a transaction that lacks Bob's signature.
6. Expected (correct) behavior: request rejected with a status-mismatch error.
7. Actual behavior: transaction is submitted to Hedera without Bob's signature, resulting in either `FAILED` (Hedera rejects) or success (Hedera accepts with fewer signatures than the tool intended).

**Relevant code references:** [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L163-198)
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
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L280-286)
```typescript
  @Patch('/execute/:id')
  async executeTransaction(
    @GetUser() user,
    @Param('id', ParseIntPipe) id: number,
  ): Promise<boolean> {
    return this.transactionsService.executeTransaction(id, user);
  }
```
