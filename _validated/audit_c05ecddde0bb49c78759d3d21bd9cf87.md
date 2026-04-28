The code is confirmed. Let me trace the full execution path carefully before rendering a verdict.

**Key finding in `execute.service.ts` `validateTransactionStatus` (lines 226–248):**

The switch statement only throws for terminal states: `NEW`, `FAILED`, `EXECUTED`, `REJECTED`, `EXPIRED`, `CANCELED`, `ARCHIVED`. It does **not** throw for `WAITING_FOR_SIGNATURES`. A transaction in that status passes through to `hasValidSignatureKey`, which checks against the **Hedera key structure** (via `computeSignatureKey`), not the tool's approval list.

**Critical path in `_executeTransaction` (lines 187–198):**

The DB update uses `WHERE status = WAITING_FOR_EXECUTION`. If the transaction is in `WAITING_FOR_SIGNATURES`, the update returns 0 rows and the function returns `null` — but the Hedera submission at line 144 (`sdkTransaction.execute(client)`) has **already happened**, consuming the transaction ID on-chain.

---

Audit Report

## Title
Creator Can Execute Manual Transaction Before Required Signatures Are Collected, Bypassing Multi-Sig Enforcement

## Summary
`PATCH /transactions/execute/:id` → `TransactionsService.executeTransaction()` allows the transaction creator to submit a manual transaction to the Hedera network while it is still in `WAITING_FOR_SIGNATURES` status. The downstream `ExecuteService.validateTransactionStatus()` does not block this status, and the on-chain submission occurs before the DB status guard is evaluated, consuming the transaction ID regardless of the DB update outcome.

## Finding Description

**Root cause — `validateTransactionStatus` does not block `WAITING_FOR_SIGNATURES`:**

`back-end/libs/common/src/execute/execute.service.ts`, lines 226–248:

```typescript
private async validateTransactionStatus(transaction: Transaction) {
  const { status } = await this.transactionsRepo.findOne({ ... });

  switch (status) {
    case TransactionStatus.NEW:      throw new Error(...);
    case TransactionStatus.FAILED:   throw new Error(...);
    case TransactionStatus.EXECUTED: throw new Error(...);
    case TransactionStatus.REJECTED: throw new Error(...);
    case TransactionStatus.EXPIRED:  throw new Error(...);
    case TransactionStatus.CANCELED: throw new Error(...);
    case TransactionStatus.ARCHIVED: throw new Error(...);
    // WAITING_FOR_SIGNATURES: no case → falls through silently
  }
}
``` [1](#0-0) 

`WAITING_FOR_SIGNATURES` is not handled. The function returns without throwing, allowing execution to proceed.

**The Hedera submission precedes the DB status guard:**

In `_executeTransaction`, the on-chain call happens at line 144, and the DB update (which uses `WHERE status = WAITING_FOR_EXECUTION`) happens at lines 187–196. If the transaction is in `WAITING_FOR_SIGNATURES`, the DB update returns 0 rows and the function returns `null` — but the transaction has **already been submitted to Hedera**. [2](#0-1) 

**The API entry point has no status gate:**

`back-end/apps/api/src/transactions/transactions.service.ts`, lines 736–751 — the only guards are creator ownership and `isManual` flag. No check for `transaction.status === WAITING_FOR_EXECUTION`. [3](#0-2) 

**Contrast with the scheduler path:**

`transaction-scheduler.service.ts` line 167 explicitly gates on `status === WAITING_FOR_EXECUTION` before calling `collateAndExecute`. The direct API path skips this gate entirely. [4](#0-3) 

**The `hasValidSignatureKey` check is against the Hedera key structure, not the tool's approval list:**

`getValidatedSDKTransaction` (lines 204–223) calls `computeSignatureKey` to get the on-chain required key, then checks `hasValidSignatureKey`. If the Hedera account key structure requires fewer signatures than the tool's approval list, a `WAITING_FOR_SIGNATURES` transaction can pass this check and be submitted. [5](#0-4) 

## Impact Explanation

- **Policy bypass**: When the Hedera key structure for the target account accepts fewer signatures than the tool's signer list requires, the creator can call `PATCH /transactions/execute/:id` while the transaction is still in `WAITING_FOR_SIGNATURES`, successfully submitting it to Hedera before all tool-required co-signers have signed. The tool's multi-sig governance model is defeated.
- **Sabotage / transaction ID consumption**: Even when Hedera rejects the submission (e.g., `INVALID_SIGNATURE`), the transaction ID is consumed on Hedera. The DB record remains in `WAITING_FOR_SIGNATURES` (the DB update at line 191 requires `status = WAITING_FOR_EXECUTION` and returns 0 rows), leaving the system in an inconsistent state. Subsequent scheduler attempts will receive `DUPLICATE_TRANSACTION` from Hedera. [6](#0-5) 

## Likelihood Explanation

Any authenticated user can create a transaction with `isManual: true`. No privileged access is required. The endpoint `PATCH /transactions/execute/:id` is a standard REST call. A malicious or impatient creator can trigger this at any time after `validStart` has passed. The precondition (Hedera key structure satisfiable with fewer signatures than the tool's approval list) is a realistic configuration, especially for accounts with threshold keys.

## Recommendation

Add an explicit status check in `TransactionsService.executeTransaction()` before delegating to `executeService.executeTransaction()`:

```typescript
if (transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION) {
  throw new BadRequestException(ErrorCodes.TNR); // or an appropriate error code
}
```

Alternatively, add `WAITING_FOR_SIGNATURES` as a blocking case in `ExecuteService.validateTransactionStatus()`:

```typescript
case TransactionStatus.WAITING_FOR_SIGNATURES:
  throw new Error('Transaction has not collected all required signatures yet.');
```

The fix should be applied at the API layer (`transactions.service.ts`) so the gate is enforced before any downstream call is made.

## Proof of Concept

1. Authenticated user Alice creates a multi-sig transaction with `isManual: true`. Transaction enters `WAITING_FOR_SIGNATURES`. The Hedera account key is a 1-of-2 threshold key; the tool's approval list requires both signers.
2. Alice (signer 1) signs. The transaction now satisfies the Hedera threshold key (`hasValidSignatureKey` returns `true`) but the tool still shows `WAITING_FOR_SIGNATURES` because signer 2 has not signed.
3. Alice (as creator) calls `PATCH /transactions/execute/:id` with `validStart ≤ now`.
4. `validateTransactionStatus` does not throw for `WAITING_FOR_SIGNATURES`. `hasValidSignatureKey` passes (1-of-2 threshold satisfied). `sdkTransaction.execute(client)` is called — transaction submitted to Hedera successfully.
5. The DB update at line 191 (`WHERE status = WAITING_FOR_EXECUTION`) matches 0 rows; the DB record stays in `WAITING_FOR_SIGNATURES`. The tool believes the transaction is still pending, but it has already executed on-chain, bypassing the tool's 2-of-2 approval requirement.

### Citations

**File:** back-end/libs/common/src/execute/execute.service.ts (L144-198)
```typescript
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
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L204-223)
```typescript
  private async getValidatedSDKTransaction(
    transaction: Transaction,
  ): Promise<SDKTransaction> {
    /* Throws an error if the transaction is not found or in incorrect state */
    if (!transaction) throw new Error('Transaction not found');

    await this.validateTransactionStatus(transaction);

    /* Gets the SDK transaction from the transaction body */
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    /* Gets the signature key */
    const signatureKey = await this.transactionSignatureService.computeSignatureKey(transaction);

    /* Checks if the transaction has valid signatureKey */
    if (!hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey))
      throw new Error('Transaction has invalid signature.');

    return sdkTransaction;
  }
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L226-248)
```typescript
  private async validateTransactionStatus(transaction: Transaction) {
    const { status } = await this.transactionsRepo.findOne({
      where: { id: transaction.id },
      select: ['status'],
    });

    switch (status) {
      case TransactionStatus.NEW:
        throw new Error('Transaction is new and has not been signed yet.');
      case TransactionStatus.FAILED:
        throw new Error('Transaction has already been executed, but failed.');
      case TransactionStatus.EXECUTED:
        throw new Error('Transaction has already been executed.');
      case TransactionStatus.REJECTED:
        throw new Error('Transaction has already been rejected.');
      case TransactionStatus.EXPIRED:
        throw new Error('Transaction has been expired.');
      case TransactionStatus.CANCELED:
        throw new Error('Transaction has been canceled.');
      case TransactionStatus.ARCHIVED:
        throw new Error('Transaction is archived.');
    }
  }
```

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

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L163-169)
```typescript
  async prepareTransactions(transactions: Transaction[]) {
    const processedGroupIds = new Set<number>();

    for (const transaction of transactions) {
      const waitingForExecution = transaction.status === TransactionStatus.WAITING_FOR_EXECUTION;

      if (waitingForExecution && this.isValidStartExecutable(transaction.validStart)) {
```
