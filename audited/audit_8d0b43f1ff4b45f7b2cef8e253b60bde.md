### Title
Approver Rejection (`approved: false`) Is Stored But Never Enforced in the Transaction Execution Path

### Summary
The `transaction_approver` table stores an `approved` boolean that designates whether each approver has accepted or rejected a transaction. When an approver explicitly rejects a transaction by submitting `approved: false`, this value is persisted to the database and a status-update notification is emitted — but the execution pipeline (`processTransactionStatus`) never reads the `approved` field. As a result, a transaction with enough cryptographic signers will advance to `WAITING_FOR_EXECUTION` and be submitted to the Hedera network even when one or more designated approvers have explicitly rejected it.

### Finding Description

**Root cause — `approveTransaction` stores the rejection but nothing enforces it**

In `approvers.service.ts`, `approveTransaction` accepts `dto.approved` (which can be `true` or `false`) and writes it directly to the database: [1](#0-0) 

After the write, the function emits a `transactionStatusUpdate` event when `!dto.approved` (i.e., on rejection): [2](#0-1) 

This notification implies the status should change on rejection — but the function that actually changes statuses never consults the `approved` column.

**Execution path — `processTransactionStatus` ignores the `approved` field entirely**

`processTransactionStatus` is the sole function responsible for transitioning a transaction from `WAITING_FOR_SIGNATURES` to `WAITING_FOR_EXECUTION`. It only checks whether the SDK transaction's cryptographic signers satisfy the required key structure: [3](#0-2) 

There is no query against `transaction_approver.approved`. A transaction whose signers satisfy `hasValidSignatureKey` will be promoted to `WAITING_FOR_EXECUTION` regardless of how many approvers have set `approved = false`.

**Chain service — executes based solely on status**

`prepareTransactions` in the chain service picks up every transaction in `WAITING_FOR_EXECUTION` and schedules it for submission: [4](#0-3) 

No approver-rejection check exists here either.

**The `REJECTED` status is never set by approver decisions**

`TransactionStatus.REJECTED` exists in the enum: [5](#0-4) 

But `processTransactionStatus` never transitions a transaction to `REJECTED` based on `approved = false` rows in `transaction_approver`. The status is therefore a dead code path with respect to approver rejections.

**Database documentation confirms the design intent**

The schema documentation states that `approved` should gate whether a transaction proceeds: [6](#0-5) 

The implementation does not honour this intent.

### Impact Explanation

Any transaction that accumulates sufficient cryptographic signatures from its required signers will be executed on the Hedera network, even if every designated approver has explicitly rejected it. The approver oversight layer — which is the primary governance control in Organization Mode — provides no actual enforcement. Hedera transactions are irreversible once submitted; funds transferred, accounts deleted, or keys rotated cannot be undone.

### Likelihood Explanation

The exploit requires no special privilege beyond being a transaction creator or signer. The normal workflow is:

1. Creator creates a transaction and assigns approvers.
2. Signers (who may be the creator themselves) provide the required cryptographic signatures.
3. Approvers call `POST /transactions/:id/approve` with `approved: false`.
4. `processTransactionStatus` runs (every 10 seconds via cron), sees sufficient signatures, and promotes the transaction to `WAITING_FOR_EXECUTION`.
5. The chain service submits the transaction to Hedera.

Step 3 has no effect on steps 4–5. This is a deterministic, always-reachable path requiring only a valid authenticated session.

### Recommendation

In `processTransactionStatus`, before promoting a transaction to `WAITING_FOR_EXECUTION`, query `transaction_approver` for the given transaction and verify that no root-level approver has `approved = false`. If any approver has explicitly rejected the transaction, set the status to `REJECTED` instead and skip execution scheduling.

Alternatively, add a dedicated check inside `prepareTransactions` (chain service) that re-reads the approver table and aborts scheduling if any rejection is present, providing a defence-in-depth layer even if the API-side check is missed.

### Proof of Concept

1. Register two users (Alice = creator/signer, Bob = approver) in an Organization instance.
2. Alice creates a `CryptoTransfer` transaction and adds Bob as an approver.
3. Alice signs the transaction with her key (satisfying the required key threshold).
4. Bob calls `POST /transactions/:id/approve` with `{ approved: false, signature: <valid_sig>, userKeyId: <id> }`.
5. Wait up to 10 seconds for the `status_update_between_now_and_three_minutes` cron to fire.
6. Observe that the transaction status transitions to `WAITING_FOR_EXECUTION` (not `REJECTED`).
7. The chain service submits the transaction to Hedera; the transfer executes despite Bob's explicit rejection.

The root cause is confirmed at:
- [7](#0-6) 
- [8](#0-7) 
- [4](#0-3)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L598-618)
```typescript
    /* Update the approver with the signature */
    await this.dataSource.transaction(async transactionalEntityManager => {
      await transactionalEntityManager
        .createQueryBuilder()
        .update(TransactionApprover)
        .set({
          userKeyId: dto.userKeyId,
          signature: dto.signature,
          approved: dto.approved,
        })
        .whereInIds(userApprovers.map(a => a.id))
        .execute();
    });

    const notificationEvent = [{ entityId: transaction.id }];

    if (!dto.approved || userApprovers.every(a => a.approved)) {
      emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
    } else {
      emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
    }
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L118-155)
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

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L46-56)
```typescript
export enum TransactionStatus {
  NEW = 'NEW', // unused
  CANCELED = 'CANCELED',
  REJECTED = 'REJECTED',
  WAITING_FOR_SIGNATURES = 'WAITING FOR SIGNATURES',
  WAITING_FOR_EXECUTION = 'WAITING FOR EXECUTION',
  EXECUTED = 'EXECUTED',
  FAILED = 'FAILED',
  EXPIRED = 'EXPIRED',
  ARCHIVED = 'ARCHIVED',
}
```

**File:** docs/database/tables/transaction_approver.md (L16-16)
```markdown
| **approved**      | boolean   | A boolean representation indicates whether the approver has approved the transaction. If it is a single key, we should set this field to true when that key signs the transaction. If it is a multisig approver, we should check if we have the required signatures after each signature. If we do, we should set this field to true. |
```
