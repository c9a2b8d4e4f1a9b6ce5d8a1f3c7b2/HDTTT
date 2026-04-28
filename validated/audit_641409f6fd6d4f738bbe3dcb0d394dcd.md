### Title
Approver Threshold Not Enforced Before Transaction Execution

### Summary
The Hedera Transaction Tool supports an organizational approver-threshold system where a configurable number of designated approvers must approve a transaction before it proceeds. However, `processTransactionStatus()` — the function that transitions a transaction from `WAITING_FOR_SIGNATURES` to `WAITING_FOR_EXECUTION` — checks only cryptographic signatures, never the approver-threshold satisfaction. A transaction can therefore reach execution with zero approvals, bypassing the entire organizational governance control.

### Finding Description

**Root cause — `processTransactionStatus` ignores approver state**

`back-end/libs/common/src/utils/transaction/index.ts` lines 118–176 is the sole function responsible for promoting a transaction to `WAITING_FOR_EXECUTION`:

```typescript
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
``` [1](#0-0) 

The decision is made entirely on `hasValidSignatureKey` (cryptographic signatures on the Hedera SDK transaction bytes) and `smartCollate`. There is no call to any approver-status check here.

**The approver threshold is stored but never consulted at this gate**

The `TransactionApprover` entity stores a `threshold` column and an `approved` boolean per approver: [2](#0-1) 

The `isApproved()` utility correctly evaluates the threshold tree: [3](#0-2) 

But this function is only used for UI display (`ApproverStructureStatus.vue`). It is never called inside `processTransactionStatus()` or anywhere in the chain-service execution path.

**Execution path never checks approver threshold**

After `processTransactionStatus` sets the status to `WAITING_FOR_EXECUTION`, the chain service's `collateAndExecute` picks it up and calls `addExecutionTimeout` → `_executeTransaction`. Neither function checks approver state: [4](#0-3) 

The manual-execution path (`executeTransaction` in `transactions.service.ts`) also only checks the transaction status and signature validity, not approver threshold.

**Exploit path**

1. Organization admin creates a transaction and configures an approver tree with threshold N (e.g., 2-of-3 managers must approve).
2. A user who holds the required Hedera signing keys (a signer) signs the transaction cryptographically — without any approver having approved.
3. `processTransactionStatus()` is triggered (via `emitTransactionStatusUpdate` after signing). It sees sufficient cryptographic signatures → sets status to `WAITING_FOR_EXECUTION`.
4. The chain service executes the transaction on Hedera. The approver threshold was never evaluated.

### Impact Explanation

The approver-threshold system is the primary organizational governance control: it is the mechanism by which organizations enforce multi-party authorization for sensitive transactions (HBAR transfers, account updates, file updates). Bypassing it means:

- A single signer with the required cryptographic keys can unilaterally execute any transaction, regardless of the configured approval policy.
- Organizational funds or account configurations can be moved/changed without the required managerial sign-off.
- The `FEATURE_APPROVERS_ENABLED` flag and the entire approver UI workflow provide no actual security guarantee.

### Likelihood Explanation

Any authenticated organization user who holds the cryptographic keys required to satisfy the Hedera signature threshold can trigger this. This is a realistic attacker profile: in many deployments, signers and approvers overlap, and a signer who disagrees with a pending rejection can simply sign and force execution. No privileged access, no leaked credentials, and no external network access are required — only a valid organization account with signing keys.

### Recommendation

Inside `processTransactionStatus()`, before setting `newStatus = TransactionStatus.WAITING_FOR_EXECUTION`, fetch the root-level `TransactionApprover` records for the transaction and evaluate `isApproved()` against the threshold tree. Only promote the status if both conditions are true:

1. `hasValidSignatureKey` is satisfied (cryptographic signatures sufficient).
2. The approver threshold tree evaluates to `true` (or no approvers are configured, treating absence of approvers as auto-approved).

Alternatively, add a dedicated pre-execution guard in `executeTransaction` / `collateAndExecute` that rejects execution if the approver threshold is not met, mirroring the pattern used in `approveTransaction` where status is checked before proceeding.

### Proof of Concept

**Setup:**
- Organization with transaction T requiring 2-of-3 approver threshold.
- Attacker is User A, a signer holding the required Hedera private key. Zero approvers have approved.

**Steps:**
1. User A calls `POST /transactions/{id}/signers` (or the equivalent signing endpoint) with a valid cryptographic signature for transaction T.
2. The backend calls `processTransactionStatus([T])`.
3. `hasValidSignatureKey` returns `true` (signature threshold met). `smartCollate` returns non-null. `newStatus` is set to `WAITING_FOR_EXECUTION`.
4. The chain service's scheduler picks up T (status = `WAITING_FOR_EXECUTION`) and calls `collateAndExecute(T)` → `_executeTransaction(T, sdkTx)`.
5. Transaction T is submitted to Hedera and executed — with 0 of 2 required approvals obtained.

**Expected (correct) behavior:** Status should remain `WAITING_FOR_SIGNATURES` until the approver threshold is satisfied.

**Actual behavior:** Status transitions to `WAITING_FOR_EXECUTION` and the transaction is executed, as confirmed by `processTransactionStatus` at: [5](#0-4)

### Citations

**File:** back-end/libs/common/src/utils/transaction/index.ts (L118-176)
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
}
```

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L43-64)
```typescript
  @Column({ nullable: true })
  threshold?: number;

  @ManyToOne(() => UserKey, userKey => userKey.approvedTransactions, { nullable: true })
  @JoinColumn({ name: 'userKeyId' })
  userKey?: UserKey;

  @Column({ nullable: true })
  userKeyId?: number;

  @Column({ type: 'bytea', nullable: true })
  signature?: Buffer;

  @ManyToOne(() => User, user => user.approvableTransactions, { nullable: true })
  @JoinColumn({ name: 'userId' })
  user?: User;

  @Column({ nullable: true })
  userId?: number;

  @Column({ nullable: true })
  approved?: boolean;
```

**File:** front-end/src/renderer/utils/sdk/index.ts (L342-358)
```typescript
export const isApproved = (approver: ITransactionApprover): boolean | null => {
  if (approver.approved === false) {
    return false;
  }

  if (approver.approved === true) {
    return true;
  }

  if (approver.approvers) {
    const approvals = approver.approvers.filter(approver => isApproved(approver) === true);
    const rejections = approver.approvers.filter(approver => isApproved(approver) === false);
    if (approvals.length >= (approver.threshold || approvals.length)) {
      return true;
    }
    return rejections.length >= (approver.threshold || rejections.length) ? false : null;
  }
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L128-196)
```typescript
  private async _executeTransaction(
    transaction: Transaction,
    sdkTransaction: SDKTransaction,
  ): Promise<TransactionExecutedDto | null> {
    const client = await getClientFromNetwork(transaction.mirrorNetwork);

    const executedAt = new Date();
    let transactionStatus = TransactionStatus.EXECUTED;
    let transactionStatusCode = null;
    let isDuplicate = false;

    const result: TransactionExecutedDto = {
      status: transactionStatus,
    };

    try {
      const response = await sdkTransaction.execute(client);
      const receipt = await response.getReceipt(client);

      result.response = JSON.stringify(response.toJSON());
      result.receipt = JSON.stringify(receipt.toJSON());
      result.receiptBytes = Buffer.from(receipt.toBytes());
      transactionStatusCode = receipt.status._code || Status.Ok._code;
    } catch (error) {
      let message = 'Unknown error';
      let statusCode = null;

      if (error instanceof Error) {
        message = error.message;

        const status = (error as any).status;
        if (status?._code) {
          statusCode = status._code;
        } else {
          statusCode = getStatusCodeFromMessage(message);
        }
      }

      // Another pod already submitted this — don't touch the row, let the
      // successful pod win the update and emit the change
      if (statusCode === Status.DuplicateTransaction._code) {
        isDuplicate = true;
        this.logger.debug(
          `Duplicate transaction ${transaction.id} (txId=${sdkTransaction.transactionId}, statusCode=${statusCode}) detected; assuming it was successfully executed by another pod and skipping updates.`,
        );
      } else {
        transactionStatus = TransactionStatus.FAILED;
        transactionStatusCode = statusCode;
        result.error = message;
        this.logger.error(
          `Error executing transaction ${transaction.id} (txId=${sdkTransaction.transactionId}, statusCode=${statusCode}): ${message}`,
        );
      }
    } finally {
      client.close();
    }

    if (isDuplicate) return null;

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
```
