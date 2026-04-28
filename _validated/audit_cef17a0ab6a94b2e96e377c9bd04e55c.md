Audit Report

## Title
`cutoffAt` Deadline Not Enforced in Signature Upload and Approval Paths, Allowing Post-Deadline State Transitions

## Summary
The `Transaction` entity stores a `cutoffAt` field representing the creator-defined deadline after which no new signatures or approvals should be accepted. None of the three enforcement paths — `SignersService.validateTransactionStatus`, `TransactionsService.importSignatures`, or `ApproversService.approveTransaction` — check `cutoffAt` before accepting input. A valid signer or approver can submit their signature after the deadline has passed, potentially pushing a transaction from `WAITING_FOR_SIGNATURES` to `WAITING_FOR_EXECUTION` and causing it to execute on-chain when the creator intended the signature window to be closed.

## Finding Description

**`cutoffAt` is stored but never read in any enforcement path.**

The `cutoffAt` column is defined on the `Transaction` entity: [1](#0-0) 

It is accepted at creation time and persisted: [2](#0-1) 

The database documentation confirms it is a real deadline (`cutoffAt: 2024-05-24 18:13:28`, `validStart: 2024-05-24 19:12:00` — the cutoff is ~1 hour before execution): [3](#0-2) [4](#0-3) 

**Path 1 — `SignersService.validateTransactionStatus`** (called from `uploadSignatureMaps`): [5](#0-4) 

The only guards are: status must be `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`, and the SDK transaction must not be expired. `cutoffAt` is never consulted.

**Path 2 — `TransactionsService.importSignatures`** (the file-import signature path): [6](#0-5) 

Same two guards only; `cutoffAt` is absent.

**Path 3 — `ApproversService.approveTransaction`**: [7](#0-6) 

Again, only status is checked; `cutoffAt` is not read.

After signatures are persisted, `processTransactionStatus` is called, which can transition the transaction to `WAITING_FOR_EXECUTION` if the signature threshold is met: [8](#0-7) 

The Chain Service scheduler then picks up `WAITING_FOR_EXECUTION` transactions and executes them on the Hedera network: [9](#0-8) 

## Impact Explanation
A transaction that the creator intended to expire without execution (by setting `cutoffAt` in the past) can be pushed to `WAITING_FOR_EXECUTION` by a late-signing authorized signer and subsequently executed on the Hedera network. Depending on the transaction type (HBAR transfer, account update, node operation, file operation), this results in unintended, irreversible on-chain state changes. The creator has no recourse once the transaction reaches `WAITING_FOR_EXECUTION` and is submitted.

## Likelihood Explanation
Any user who holds a key that is part of the transaction's required signature set can trigger this. No privileged access is required — only a valid organization account and a registered key. The attacker simply delays their signature submission past `cutoffAt`. The API endpoint `POST /transactions/:id/signers` is a standard authenticated endpoint reachable by any signer. [10](#0-9) 

## Recommendation
In all three enforcement paths, add a `cutoffAt` check immediately after the status check. If `transaction.cutoffAt` is set and `new Date() > transaction.cutoffAt`, reject the request with an appropriate error code (e.g., a new `ErrorCodes.TCD` — "Transaction Cutoff Deadline passed").

Specifically:

1. **`SignersService.validateTransactionStatus`** — add after the status check:
   ```ts
   if (transaction.cutoffAt && new Date() > transaction.cutoffAt) {
     return ErrorCodes.TCD;
   }
   ``` [5](#0-4) 

2. **`TransactionsService.importSignatures`** — add after the status check at line 539: [6](#0-5) 

3. **`ApproversService.approveTransaction`** — add after the status check at line 588: [7](#0-6) 

## Proof of Concept

1. Creator creates a transaction with `cutoffAt = T` (e.g., 1 hour before `validStart`), as accepted by `CreateTransactionDto.cutoffAt` and persisted via `createTransactions`. [11](#0-10) 

2. At time `T`, the transaction still lacks enough signatures and sits in `WAITING_FOR_SIGNATURES`.

3. After `T`, a valid signer submits their signature via `POST /transactions/:id/signers` (calls `uploadSignatureMaps`) or the import endpoint (`POST /transactions/signatures/import`).

4. `validateTransactionStatus` passes — status is still `WAITING_FOR_SIGNATURES`, SDK transaction is not yet expired (SDK expiry is based on `validStart + 180s`, not `cutoffAt`). `cutoffAt` is never checked. [5](#0-4) 

5. `processTransactionStatus` is called; if the new signature satisfies the threshold, the transaction transitions to `WAITING_FOR_EXECUTION`. [12](#0-11) 

6. The Chain Service scheduler (`handleTransactionsBetweenNowAndAfterThreeMinutes` or similar cron) picks it up and calls `collateAndExecute`, submitting it to the Hedera network — after the creator's intended deadline. [13](#0-12)

### Citations

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L129-130)
```typescript
  @Column({ nullable: true })
  cutoffAt?: Date;
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L451-453)
```typescript
            isManual: data.isManual,
            cutoffAt: data.cutoffAt,
            publicKeys: data.publicKeys,
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L534-543)
```typescript
        /* Checks if the transaction is canceled */
        if (
          transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
          transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
        )
          throw new BadRequestException(ErrorCodes.TNRS);

        /* Checks if the transaction is expired */
        const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
        if (isExpired(sdkTransaction)) throw new BadRequestException(ErrorCodes.TE);
```

**File:** docs/database/tables/transaction.md (L22-22)
```markdown
| **cutoff_At**       | Timestamp | The timestamp at which the transaciton can no longer be signed by the signers.                                                                       |
```

**File:** docs/database/tables/transaction.md (L61-65)
```markdown
validStart: 2024-05-24 19:12:00

network: testnet

cutoffAt: 2024-05-24 18:13:28.82329
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L98-124)
```typescript
  /* Upload signatures for the given transaction ids */
  async uploadSignatureMaps(
    dto: UploadSignatureMapDto[],
    user: User,
  ): Promise<{ signers: TransactionSigner[]; notificationReceiverIds: number[] }> {
    // Load all necessary data
    const { transactionMap, signersByTransaction } = await this.loadTransactionData(dto);

    // Validate and process signatures
    const validationResults = await this.validateAndProcessSignatures(
      dto,
      user,
      transactionMap,
      signersByTransaction
    );

    // Persist changes to database
    const { transactionsToProcess, signers, notificationsToDismiss } = await this.persistSignatureChanges(validationResults, user);

    // Update transaction statuses and emit notifications
    await this.updateStatusesAndNotify(transactionsToProcess);

    return {
      signers: Array.from(signers),
      notificationReceiverIds: notificationsToDismiss,
    };
  }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L201-215)
```typescript
  private validateTransactionStatus(transaction: Transaction): string | null {
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    ) {
      return ErrorCodes.TNRS;
    }

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    if (isExpired(sdkTransaction)) {
      return ErrorCodes.TE;
    }

    return null;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L583-588)
```typescript
    /* Checks if the transaction is requires approval */
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L139-154)
```typescript
    let newStatus = TransactionStatus.WAITING_FOR_SIGNATURES;

    if (isAbleToSign) {
      const collatedTx = await smartCollate(transaction, signatureKey);
      if (collatedTx !== null) {
        newStatus = TransactionStatus.WAITING_FOR_EXECUTION;
      }
    }

    if (transaction.status !== newStatus) {
      const key = `${transaction.status}->${newStatus}`;
      if (!updatesByStatus.has(key)) {
        updatesByStatus.set(key, { newStatus, oldStatus: transaction.status, ids: [] });
      }
      updatesByStatus.get(key)!.ids.push(transaction.id);
    }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L86-97)
```typescript
  /* For transactions with valid start between currently valid and 3 minutes */
  @Cron(CronExpression.EVERY_10_SECONDS, {
    name: 'status_update_between_now_and_three_minutes',
  })
  async handleTransactionsBetweenNowAndAfterThreeMinutes() {
    const transactions = await this.updateTransactions(
      this.getThreeMinutesBefore(),
      this.getThreeMinutesLater(),
    );

    await this.prepareTransactions(transactions);
  }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L163-197)
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
```

**File:** back-end/apps/api/src/transactions/dto/create-transaction.dto.ts (L30-33)
```typescript
  @Type(() => Date)
  @IsDate()
  @IsOptional()
  cutoffAt?: Date;
```
