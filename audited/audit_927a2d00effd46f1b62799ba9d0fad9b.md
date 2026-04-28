### Title
`uploadSignatureMaps` Accepts Cryptographically Unverified Signatures, Enabling Malicious State Advancement and Forced Transaction Failure

### Summary

The `uploadSignatureMaps` function in `signers.service.ts` adds user-supplied signature bytes to transaction data without cryptographically verifying them, unlike the parallel `importSignatures` path in `transactions.service.ts` which explicitly calls `validateSignature` before accepting any signature. A malicious organization member can submit a garbage/invalid signature for their registered key, have it stored in the transaction bytes, and — if their key is required — cause the transaction to advance to `WAITING_FOR_EXECUTION` with an invalid signature, guaranteeing failure at the Hedera network level and permanently marking the transaction `FAILED`.

### Finding Description

**Root cause — missing `validateSignature` call in `uploadSignatureMaps`**

`importSignatures` (the personal/offline path) explicitly validates every signature before accepting it: [1](#0-0) 

`validateSignature` iterates the map and calls `publicKey.verify(bodyBytes, signature)` for every entry, throwing on any invalid signature: [2](#0-1) 

The organization-mode path `uploadSignatureMaps` → `processTransactionSignatures` performs **no equivalent check**. It only verifies that the public key belongs to the authenticated user, then unconditionally calls `addSignature`: [3](#0-2) 

Because the Hedera SDK's `addSignature` does not internally verify the signature bytes (the existence of the separate `validateSignature` utility confirms this), an attacker can supply a well-formed `SignatureMap` containing their registered public key paired with arbitrary/invalid bytes. The SDK will embed those bytes in the transaction, `isSameBytes` will be `false`, and the corrupted bytes will be persisted: [4](#0-3) 

A `TransactionSigner` row is then inserted for the user, and `processTransactionStatus` is called. That function reads `sdkTransaction._signerPublicKeys` — which now includes the attacker's key — and evaluates whether the threshold is met: [5](#0-4) 

If the attacker's key was the last required key, `hasValidSignatureKey` returns `true`, the status advances to `WAITING_FOR_EXECUTION`, and the chain service submits the transaction to Hedera. The network rejects it (invalid signature), and the transaction is permanently marked `FAILED`. [6](#0-5) 

### Impact Explanation

A required signer in an organization can:
1. Submit a `signatureMap` containing their registered public key paired with invalid/garbage signature bytes.
2. Force the transaction to advance from `WAITING_FOR_SIGNATURES` to `WAITING_FOR_EXECUTION` while carrying a cryptographically invalid signature.
3. Cause the chain service to submit the transaction to Hedera, which rejects it.
4. Permanently mark the transaction `FAILED` — an irreversible terminal state.

Other co-signers and the transaction creator have no way to detect or prevent this before execution. The transaction cannot be recovered once it reaches `FAILED`.

### Likelihood Explanation

The attacker must be an authenticated organization member whose registered key is part of the required signing set for the target transaction. This is a "malicious normal user abusing valid product flows" scenario — no privileged access is required. Any organization member who is designated as a required signer can trigger this unilaterally via a single crafted API call to the signature upload endpoint.

### Recommendation

Add a `validateSignature` call inside `processTransactionSignatures` before calling `addSignature`, mirroring the check already present in `importSignatures`:

```typescript
// In processTransactionSignatures, before sdkTransaction.addSignature(publicKey, map):
const { data: validKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(null, sdkTransaction, map),
);
if (error || !validKeys?.length) throw new Error(ErrorCodes.ISNMPN);
```

This ensures both signature-upload paths enforce the same cryptographic integrity guarantee.

### Proof of Concept

1. Attacker is an authenticated organization member; their key (`attackerPubKey`) is a required signer for transaction ID `42`.
2. Attacker constructs a `SignatureMap` where `attackerPubKey` maps to 64 bytes of `0xFF` (invalid signature).
3. Attacker POSTs to `POST /transactions/42/signers` with `{ signatureMap: <crafted map> }`.
4. `uploadSignatureMaps` → `processTransactionSignatures` finds `attackerPubKey` in `userKeyMap`, calls `sdkTransaction.addSignature(attackerPubKey, map)` — no verification occurs.
5. `isSameBytes` is `false`; corrupted bytes are written to the DB via `bulkUpdateTransactions`.
6. A `TransactionSigner` row is inserted for the attacker.
7. `processTransactionStatus` sees `attackerPubKey` in `_signerPublicKeys`, threshold is met, status advances to `WAITING_FOR_EXECUTION`.
8. Chain service submits to Hedera → `INVALID_SIGNATURE` error → transaction permanently `FAILED`.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L545-553)
```typescript
        /* Validates the signatures */
        const { data: publicKeys, error } = safe<PublicKey[]>(
          validateSignature.bind(this, sdkTransaction, map),
        );
        if (error) throw new BadRequestException(ErrorCodes.ISNMPN);

        for (const publicKey of publicKeys) {
          sdkTransaction.addSignature(publicKey, map);
        }
```

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L213-248)
```typescript
export const validateSignature = (transaction: SDKTransaction, signatureMap: SignatureMap) => {
  const signerPublicKeys: PublicKey[] = [];

  const { rowLength, nodeAccountIdRow, transactionIdCol } =
    getSignedTransactionsDimensions(transaction);

  for (const [nodeAccountId, transactionIds] of signatureMap._map) {
    for (const [transactionId, publicKeys] of transactionIds._map) {
      for (const [publicKeyDer, signature] of publicKeys._map) {
        const publicKey = PublicKey.fromString(publicKeyDer);
        const publicKeyHex = publicKey.toStringRaw();

        const alreadySigned =
          transaction._signerPublicKeys.has(publicKeyHex) ||
          transaction._signerPublicKeys.has(publicKeyDer);

        if (!alreadySigned) {
          const row = nodeAccountIdRow[nodeAccountId];
          const col = transactionIdCol[transactionId];

          const bodyBytes = transaction._signedTransactions.get(col * rowLength + row).bodyBytes;

          const signatureValid = publicKey.verify(bodyBytes, signature);

          if (signatureValid) {
            signerPublicKeys.push(publicKey);
          } else {
            throw new Error('Invalid signature');
          }
        }
      }
    }
  }

  return signerPublicKeys;
};
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L234-257)
```typescript
    for (const nodeMap of map.values()) {
      for (const txMap of nodeMap.values()) {
        for (const publicKey of txMap.keys()) {
          const raw = publicKey.toStringRaw();

          // Skip duplicates across node/tx maps, and already-processed keys
          if (processedRawKeys.has(raw)) continue;
          processedRawKeys.add(raw);

          // Look up key (raw first, then DER)
          let userKey = userKeyMap.get(raw);
          if (!userKey) {
            userKey = userKeyMap.get(publicKey.toStringDer());
          }
          if (!userKey) throw new Error(ErrorCodes.PNY);

          // Only add the signature once per unique key
          sdkTransaction = sdkTransaction.addSignature(publicKey, map);

          // Only return "new" signers (not already persisted)
          if (!existingSignerIds.has(userKey.id)) {
            userKeys.push(userKey);
          }
        }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L261-298)
```typescript
    // Finally, compare the resulting transaction bytes to see if any signatures were actually added
    const isSameBytes = Buffer.from(sdkTransaction.toBytes()).equals(
      transaction.transactionBytes
    );

    return { sdkTransaction, userKeys, isSameBytes };
  }

  private async persistSignatureChanges(
    validationResults: any[],
    user: User,
  ) {
    const signers = new Set<TransactionSigner>();
    let notificationsToDismiss: number[] = [];

    // Prepare batched operations
    const transactionsToUpdate: { id: number; transactionBytes: Buffer }[] = [];
    const notificationsToUpdate: { userId: number; transactionId: number }[] = [];
    const signersToInsert: { userId: number; transactionId: number; userKeyId: number }[] = [];
    const transactionsToProcess: { id: number; transaction: Transaction }[] = [];

    for (const result of validationResults) {
      if (result.error) {
        console.error(`[TX ${result.id}] Validation failed: ${result.error}`);
        continue;
      }

      const { id, transaction, sdkTransaction, userKeys, isSameBytes } = result;

      // Skip if nothing to do - no signatures were added to the transaction
      // AND no new signers were inserted (the signature can be present on the transaction
      // if collated by an outside or 'offline' method)
      if (isSameBytes && userKeys.length === 0) continue;

      // Collect updates
      if (!isSameBytes) {
        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
        transactionsToUpdate.push({ id, transactionBytes: transaction.transactionBytes });
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L129-154)
```typescript
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
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L143-180)
```typescript
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
```
