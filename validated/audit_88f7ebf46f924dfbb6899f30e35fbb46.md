### Title
Null Dereference on `getFeePayerAccountId()` in `extractSignatureRequirements` Causes Unhandled Crash in Signature Computation Pipeline

### Summary
`TransactionSignatureService.extractSignatureRequirements()` unconditionally calls `.toString()` on the return value of `getFeePayerAccountId()`, which is explicitly typed and documented to return `AccountId | null`. When a transaction with no `transactionId` is processed, this produces a `TypeError: Cannot read properties of null (reading 'toString')`, crashing the signature computation pipeline. This is the direct analog of the external report's `getSyntRepresentation` returning a zero/null address without a guard.

### Finding Description

`getFeePayerAccountId()` in `TransactionBaseModel` is typed `AccountId | null` and uses optional chaining, explicitly returning `null` when `transactionId` or `transactionId.accountId` is absent: [1](#0-0) 

The caller `extractSignatureRequirements()` calls `.toString()` on this return value with no null guard: [2](#0-1) 

This is invoked from `computeSignatureKey()`: [3](#0-2) 

`computeSignatureKey` is called from three critical backend paths:

1. **Transaction execution validation** — `getValidatedSDKTransaction` in `execute.service.ts`: [4](#0-3) 

2. **Scheduled collation/execution** — `collateAndExecute` in `transaction-scheduler.service.ts`: [5](#0-4) 

3. **Batch status processing** — `processTransactionStatus` in `utils/transaction/index.ts`: [6](#0-5) 

The `transactionBytes` field is user-supplied at transaction creation time. The Hedera protobuf format permits a `TransactionBody` without a `transactionId` field; `SDKTransaction.fromBytes()` can succeed on such bytes, producing an SDK transaction where `transactionId` is `undefined`, causing `getFeePayerAccountId()` to return `null`. The subsequent `.toString()` call at line 71 throws `TypeError`.

### Impact Explanation

- In `collateAndExecute`, the `TypeError` is swallowed by a generic `catch` block (line 319), silently preventing the transaction from ever being executed — a permanent, unrecoverable DoS for that transaction.
- In `getValidatedSDKTransaction`, the error propagates, blocking execution of any transaction whose bytes trigger this path.
- In `processTransactionStatus`, the error propagates mid-loop, potentially halting status updates for all transactions in the current batch, corrupting the signing/execution pipeline for the entire organization.

### Likelihood Explanation

Any authenticated user (no admin privileges required) who can submit a transaction to the API controls the `transactionBytes` field. Crafting protobuf bytes that omit the `transactionId` field is straightforward using any protobuf library. The optional chaining in `getFeePayerAccountId()` confirms the developers anticipated this null case, but the guard was never added at the call site.

### Recommendation

Add a null guard in `extractSignatureRequirements` before calling `.toString()`:

```typescript
private extractSignatureRequirements(
  transactionModel: TransactionBaseModel<any>
): SignatureRequirements {
  const feePayerId = transactionModel.getFeePayerAccountId();
  if (!feePayerId) {
    throw new Error('Transaction is missing a fee payer account ID (transactionId not set)');
  }
  return {
    feePayerAccount: feePayerId.toString(),
    signingAccounts: transactionModel.getSigningAccounts(),
    receiverAccounts: transactionModel.getReceiverAccounts(),
    newKeys: transactionModel.getNewKeys() ?? [],
    nodeId: transactionModel.getNodeId(),
  };
}
```

This converts the silent crash into an explicit, catchable error that callers can handle gracefully.

### Proof of Concept

1. Craft a Hedera `TransactionBody` protobuf with no `transactionId` field set (e.g., a `CryptoTransferTransactionBody` with transfers but no `TransactionID`).
2. Serialize it as a valid `SignedTransaction` wrapping the body bytes.
3. Submit these bytes to the API's transaction creation endpoint as an authenticated user.
4. When the chain service processes the transaction (either via `collateAndExecute` or `processTransactionStatus`), `SDKTransaction.fromBytes()` succeeds, `getFeePayerAccountId()` returns `null`, and `extractSignatureRequirements` throws `TypeError: Cannot read properties of null (reading 'toString')`.
5. In the `collateAndExecute` path, the transaction is permanently stuck — it will never be executed and no error is surfaced to the user or operator. [7](#0-6) [1](#0-0)

### Citations

**File:** back-end/libs/common/src/transaction-signature/model/transaction-base.model.ts (L6-12)
```typescript
  getFeePayerAccountId(): AccountId | null {
    const payerId = this.transaction.transactionId?.accountId;
    if (payerId) {
      return payerId;
    }
    return null;
  }
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L38-62)
```typescript
  async computeSignatureKey(
    transaction: Transaction,
    showAll: boolean = false,
  ): Promise<KeyList> {
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    const transactionModel = TransactionFactory.fromTransaction(sdkTransaction);

    // Extract signature requirements from the transaction model
    const requirements = this.extractSignatureRequirements(transactionModel);

    // Build the key list
    const signatureKey = new KeyList();

    await this.addFeePayerKey(signatureKey, transaction, requirements.feePayerAccount);
    await this.addSigningAccountKeys(signatureKey, transaction, requirements.signingAccounts);
    await this.addReceiverAccountKeys(signatureKey, transaction, requirements.receiverAccounts, showAll);

    if (requirements.nodeId) {
      await this.addNodeKeys(signatureKey, transaction, requirements.nodeId);
    }

    signatureKey.push(...requirements.newKeys);

    return signatureKey;
  }
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L67-77)
```typescript
  private extractSignatureRequirements(
    transactionModel: TransactionBaseModel<any>
  ): SignatureRequirements {
    return {
      feePayerAccount: transactionModel.getFeePayerAccountId().toString(),
      signingAccounts: transactionModel.getSigningAccounts(),
      receiverAccounts: transactionModel.getReceiverAccounts(),
      newKeys: transactionModel.getNewKeys() ?? [],
      nodeId: transactionModel.getNodeId(),
    };
  }
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L213-220)
```typescript
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    /* Gets the signature key */
    const signatureKey = await this.transactionSignatureService.computeSignatureKey(transaction);

    /* Checks if the transaction has valid signatureKey */
    if (!hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey))
      throw new Error('Transaction has invalid signature.');
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L278-284)
```typescript
    const callback = async () => {
      try {
        const requiredKeys = await this.transactionSignatureService.computeSignatureKey(transaction);

        const sdkTransaction = await smartCollate(transaction, requiredKeys);

        // If the transaction is still too large,
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L129-137)
```typescript
  for (const transaction of transactions) {
    if (!transaction) continue;

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    const signatureKey = await transactionSignatureService.computeSignatureKey(transaction);
    const isAbleToSign = hasValidSignatureKey(
      [...sdkTransaction._signerPublicKeys],
      signatureKey
    );
```
