### Title
`importSignatures` Fails to Update Transaction Status After Adding Signatures, Causing Transactions to Miss Execution Window

### Summary
The `importSignatures` function in `back-end/apps/api/src/transactions/transactions.service.ts` updates `transactionBytes` with newly added signatures but never calls `processTransactionStatus` to advance the transaction's `status` field from `WAITING_FOR_SIGNATURES` to `WAITING_FOR_EXECUTION`. The parallel code path `uploadSignatureMaps` in `signers.service.ts` correctly calls `processTransactionStatus` after persisting signature changes. Because the chain service's execution scheduler only acts on transactions in `WAITING_FOR_EXECUTION`, a transaction that receives its final required signatures through `importSignatures` may remain stuck in `WAITING_FOR_SIGNATURES` until the periodic scheduler runs — which may be after the transaction's `validStart` has passed, causing permanent expiry and non-execution.

### Finding Description

**Root cause — missing `processTransactionStatus` call in `importSignatures`**

`importSignatures` (lines 493–626 of `transactions.service.ts`) performs the following steps:

1. Validates each signature map against the stored `transactionBytes`.
2. Calls `sdkTransaction.addSignature(publicKey, map)` for each valid key.
3. Persists the updated `transactionBytes` to the database via a bulk `UPDATE`.
4. Emits `emitTransactionStatusUpdate` — a NATS/WebSocket notification to clients. [1](#0-0) 

What it **never** does is call `processTransactionStatus`, which is the function responsible for evaluating whether the accumulated signatures now satisfy the required key structure and, if so, writing `status = WAITING_FOR_EXECUTION` to the database. [2](#0-1) 

**Contrast with the correct path — `uploadSignatureMaps`**

`uploadSignatureMaps` in `signers.service.ts` follows the same signature-persistence steps but then explicitly calls `updateStatusesAndNotify`, which internally calls `processTransactionStatus` and writes the new status to the database before emitting any notification. [3](#0-2) [4](#0-3) 

**Why the emitted notification does not compensate**

`emitTransactionStatusUpdate` at line 616 of `transactions.service.ts` is a NATS publish that tells the notification service to push a WebSocket event to connected clients. It does not trigger the chain service to re-evaluate or update the transaction's `status` column. [5](#0-4) 

**Chain service execution dependency on `WAITING_FOR_EXECUTION`**

The chain service's `collateAndExecute` path is only triggered when a transaction transitions to `WAITING_FOR_EXECUTION`. The periodic scheduler (`updateTransactions`) queries only transactions already in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` and updates them — but only within the window before `validStart`. [6](#0-5) [7](#0-6) 

If the scheduler's next run occurs after the transaction's `validStart`, the transaction is expired and will never be executed — a permanent, unrecoverable loss of the transaction.

### Impact Explanation

A transaction that receives its final required signatures via `importSignatures` remains in `WAITING_FOR_SIGNATURES` in the database. The chain service does not schedule it for execution. If the periodic scheduler does not run before the transaction's `validStart` elapses, the transaction expires permanently. The user's intended on-chain operation (HBAR transfer, account update, file update, etc.) is silently lost with no error returned to the caller — `importSignatures` returns `{ id }` (success) for every updated transaction.

### Likelihood Explanation

Any authenticated user with access to a transaction can reach `importSignatures`. The timing window is realistic: Hedera transactions have a fixed validity window (default 120 seconds from `validStart`). If a user submits the final signatures close to the `validStart` boundary and the scheduler period is longer than the remaining window, the transaction expires. This is a normal usage pattern for time-sensitive multi-party signing workflows.

### Recommendation

After the batch `transactionBytes` update succeeds, call `processTransactionStatus` for all successfully updated transactions, exactly as `uploadSignatureMaps` does via `updateStatusesAndNotify`. This ensures the `status` column is advanced to `WAITING_FOR_EXECUTION` immediately when the signature threshold is met, regardless of scheduler timing.

```typescript
// After the batch update loop in importSignatures:
const successfulTransactions = updateArray
  .filter(u => /* batch succeeded */)
  .map(u => transactionMap.get(u.id));

await processTransactionStatus(this.repo, this.transactionSignatureService, successfulTransactions);
```

### Proof of Concept

1. Create a multi-signature organization transaction requiring two keys; transaction `validStart` is set 60 seconds in the future.
2. First signer uploads their signature via `POST /transactions/:id/signers` (`uploadSignatureMaps`) — status correctly advances to `WAITING_FOR_SIGNATURES`.
3. Second (final) signer submits their signature via `importSignatures` endpoint — `transactionBytes` is updated in the DB, success is returned.
4. Observe: `transaction.status` in the database remains `WAITING_FOR_SIGNATURES`.
5. Wait for `validStart` to pass without the scheduler running (or with a scheduler period > remaining window).
6. Observe: the transaction is now expired; the chain service never schedules it for execution; the on-chain operation never occurs despite both callers receiving success responses.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L551-563)
```typescript
        for (const publicKey of publicKeys) {
          sdkTransaction.addSignature(publicKey, map);
        }

        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());

        results.set(id, { id });
        updates.set(id, {
          id,
          transactionBytes: transaction.transactionBytes,
          transactionId: transaction.transactionId,
          network: transaction.mirrorNetwork,
        });
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L616-623)
```typescript
      emitTransactionStatusUpdate(
        this.notificationsPublisher,
        updateArray.map(r => ({
          entityId: r.id,
          additionalData: { transactionId: r.transactionId, network: r.network },
        })),
      );
    }
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L118-175)
```typescript
export async function processTransactionStatus(
  transactionRepo: Repository<Transaction>,
  transactionSignatureService: TransactionSignatureService,
  transactions: Transaction[],
): Promise<Map<number, TransactionStatus>> {
  const statusChanges = new Map<number, TransactionStatus>();

  // Group intended updates by [newStatus, oldStatus] so we can bulk update
  // only rows that still have the expected current status
  const updatesByStatus = new Map<string, { newStatus: TransactionStatus, oldStatus: TransactionStatus, ids: number[] }>();

  for (const transaction of transactions) {
    if (!transaction) continue;

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    const signatureKey = await transactionSignatureService.computeSignatureKey(transaction);
    const isAbleToSign = hasValidSignatureKey(
      [...sdkTransaction._signerPublicKeys],
      signatureKey
    );

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
  }

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

  return statusChanges;
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L114-124)
```typescript
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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L421-437)
```typescript
  private async updateStatusesAndNotify(
    transactionsToProcess: Array<{ id: number; transaction: Transaction }>
  ) {
    if (transactionsToProcess.length === 0) return;

    // Process statuses in bulk
    let statusMap: Map<number, TransactionStatus>;
    try {
      statusMap = await processTransactionStatus(
        this.txRepo,
        this.transactionSignatureService,
        transactionsToProcess.map(t => t.transaction)
      );
    } catch (err) {
      console.error('Bulk status processing failed:', err);
      statusMap = new Map();
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

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L271-327)
```typescript
  collateAndExecute(transaction: Transaction) {
    const name = `smart_collate_timeout_${transaction.id}`;

    if (this.schedulerRegistry.doesExist('timeout', name)) return;

    const timeToValidStart = transaction.validStart.getTime() - Date.now();

    const callback = async () => {
      try {
        const requiredKeys = await this.transactionSignatureService.computeSignatureKey(transaction);

        const sdkTransaction = await smartCollate(transaction, requiredKeys);

        // If the transaction is still too large,
        // set it to failed with the TRANSACTION_OVERSIZE status code
        // update the transaction, emit the event, and delete the timeout
        if (sdkTransaction === null) {
          const result = await this.transactionRepo
            .createQueryBuilder()
            .update(Transaction)
            .set({
              status: TransactionStatus.FAILED,
              executedAt: new Date(),
              statusCode: Status.TransactionOversize._code,
            })
            .where('id = :id AND status = :currentStatus', {
              id: transaction.id,
              currentStatus: TransactionStatus.WAITING_FOR_EXECUTION,
            })
            .returning('id')
            .execute();

          if (result.raw.length > 0) {
            emitTransactionStatusUpdate(
              this.notificationsPublisher,
              result.raw.map(row => ({ entityId: row.id })),
            );
          }
          return;
        }

        // TODO then make sure that front end doesn't allow chunks larger than 2k'
        //NOTE: the transactionBytes are set here but are not to be saved. Otherwise,
        // any signatures that were removed in order to make the transaction fit
        // would be lost.
        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());

        this.addExecutionTimeout(transaction);
      } catch (error) {
        console.log(error);
      } finally {
        this.schedulerRegistry.deleteTimeout(name);
      }
    };

    const timeout = setTimeout(callback, timeToValidStart - 10 * 1_000);
    this.schedulerRegistry.addTimeout(name, timeout);
```
