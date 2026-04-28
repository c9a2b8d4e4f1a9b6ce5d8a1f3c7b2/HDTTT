### Title
Transaction Creator Can Execute Manually Without Satisfying Required Approvals

### Summary
The `executeTransaction` endpoint in the API service allows the transaction creator to manually trigger execution of a transaction that has `isManual: true`, without verifying that the configured approval threshold has been met. This means a creator can bypass the multi-party approval mechanism entirely by invoking manual execution immediately after creating the transaction, rendering the approver system ineffective as a security control.

### Finding Description
The vulnerability is in `back-end/apps/api/src/transactions/transactions.service.ts` at `executeTransaction` (lines 736–751):

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
    await this.executeService.executeTransaction(transaction);
  }

  return true;
}
```

The only guards are:
1. The caller must be the transaction creator (`getTransactionForCreator`).
2. `isManual` must be `true`.

There is **no check** that the `transaction_approver` records have reached their required approval threshold before execution proceeds. The approval system — which records per-user `approved` flags and enforces a `threshold` count — is completely decoupled from this execution path.

The approval mechanism is defined in `back-end/apps/api/src/transactions/approvers/approvers.service.ts`. Approvals are recorded via `approveTransaction` (lines 547–620), which updates `TransactionApprover.approved` and emits a status event, but never blocks or gates the manual execution path. The `executeTransaction` call in the service goes directly to `executeService.executeTransaction`, which collates signatures and submits to the Hedera network without consulting the approver table.

**Exploit path:**
1. Attacker (normal authenticated user) creates a transaction with `isManual: true` and adds required approvers (e.g., a 2-of-3 threshold).
2. Without waiting for any approver to respond, the attacker immediately calls `POST /transactions/:id/execute`.
3. `executeTransaction` passes both guards (creator check, `isManual` check) and submits the transaction to the Hedera network.
4. The approval threshold is never evaluated; the transaction executes with zero approvals collected.

### Impact Explanation
The approval mechanism is the primary organizational authorization control for multi-party transaction governance. Bypassing it allows a single user (the creator) to unilaterally execute any transaction they created, regardless of the approval policy configured. This directly violates the integrity of the multi-signature/multi-approval workflow and enables unauthorized state changes on the Hedera network (e.g., unauthorized token transfers, account updates, or file operations) that were supposed to require organizational consensus.

### Likelihood Explanation
The attacker is a normal authenticated user with no special privileges beyond being the transaction creator. The attack requires only two API calls: create a transaction with `isManual: true`, then immediately call the execute endpoint. No race condition, cryptographic break, or privileged credential is needed. Any organization member who can create transactions can exploit this.

### Recommendation
Before proceeding with execution in `executeTransaction`, verify that the approval threshold is satisfied. Specifically:

1. Query the `transaction_approver` table for the transaction and evaluate whether the approval tree's threshold conditions are met (reusing the existing `getApproversByTransactionId` + tree-evaluation logic already present in `approvers.service.ts`).
2. If approvers exist and the threshold is not met, throw a `BadRequestException` (e.g., `ErrorCodes.TNRA` or a new `APPROVALS_NOT_MET` code).
3. Alternatively, enforce that `executeTransaction` can only be called when the transaction is in `WAITING_FOR_EXECUTION` status, since the scheduler's `processTransactionStatus` already gates that transition on signature/approval sufficiency.

### Proof of Concept

**Preconditions:** Attacker is a registered organization user with at least one registered key.

**Steps:**
1. `POST /transactions` with body `{ ..., isManual: true }` — creates transaction T with `isManual = true`.
2. `POST /transactions/:T_id/approvers` — adds approvers with threshold 2 (e.g., two other users must approve).
3. Immediately `POST /transactions/:T_id/execute` — no approvals have been collected.
4. `executeTransaction` passes the `isManual` check and calls `executeService.executeTransaction(transaction)`.
5. The transaction is submitted to the Hedera network and reaches `EXECUTED` status with 0 approvals recorded.

**Expected (correct) behavior:** Step 3 should fail with an error indicating approvals are not yet satisfied.
**Actual behavior:** The transaction executes successfully, bypassing the approval requirement entirely. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L547-620)
```typescript
  async approveTransaction(
    dto: ApproverChoiceDto,
    transactionId: number,
    user: User,
  ): Promise<boolean> {
    /* Get all the approvers */
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);

    /* If user is approver, filter the records that belongs to the user */
    const userApprovers = approvers.filter(a => a.userId === user.id);

    /* Check if the user is an approver */
    if (userApprovers.length === 0)
      throw new UnauthorizedException('You are not an approver of this transaction');

    /* Check if the user has already approved the transaction */
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);

    /* Ensures the user keys are passed */
    await attachKeys(user, this.dataSource.manager);
    if (user.keys.length === 0) return false;

    const signatureKey = user.keys.find(key => key.id === dto.userKeyId);

    /* Gets the public key that the signature belongs to */
    const publicKey = PublicKey.fromString(signatureKey?.publicKey);

    /* Get the transaction body */
    const transaction = await this.dataSource.manager.findOne(Transaction, {
      where: { id: transactionId },
      relations: { creatorKey: true, observers: true },
    });

    /* Check if the transaction exists */
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    /* Checks if the transaction is requires approval */
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    /* Verify the signature matches the transaction */
    if (
      !verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTransaction, dto.signature, publicKey)
    )
      throw new BadRequestException(ErrorCodes.SNMP);

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

    return true;
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L128-202)
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

    if (updateResult.raw.length === 0) return null;

    result.status = transactionStatus;
    return result;
  }
```
