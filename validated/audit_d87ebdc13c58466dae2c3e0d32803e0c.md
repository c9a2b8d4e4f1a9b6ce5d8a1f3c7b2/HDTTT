### Title
Unverified Signature Bytes in Primary Signature Upload Path Allow False Signing State

### Summary

The primary signature upload endpoint (`POST /transactions/:id/signers`) in `signers.service.ts` accepts and persists signature maps without performing any cryptographic verification of the signature bytes. An authenticated user with a registered key can submit arbitrary/invalid bytes as their signature, causing the system to record them as a valid signer and update the stored transaction bytes — potentially advancing the transaction toward execution with signatures that the Hedera network will reject.

### Finding Description

There are two distinct code paths for uploading signatures:

**Path 1 — `importSignatures` in `transactions.service.ts` (safe):**
This path calls `validateSignature`, which calls `publicKey.verify(bodyBytes, signature)` for each new signature, rejecting invalid bytes. [1](#0-0) 

**Path 2 — `processTransactionSignatures` in `signers.service.ts` (vulnerable):**
This is the path invoked by the primary `POST /transactions/:id/signers` endpoint. It iterates the signature map, checks only that the public key belongs to the authenticated user, then calls `sdkTransaction.addSignature(publicKey, map)` directly — **with no cryptographic verification of the signature bytes**. [2](#0-1) 

The `IsSignatureMap` decorator rejects zero-length signatures but performs no cryptographic check: [3](#0-2) 

After `addSignature` is called with invalid bytes, the SDK still adds the public key to `_signerPublicKeys` and the transaction bytes are updated and persisted. The user is then recorded as a signer in the database. [4](#0-3) 

The chain service's execution guard checks only whether the required public keys are present in `_signerPublicKeys`, not whether the underlying signature bytes are valid: [5](#0-4) 

### Impact Explanation

An authenticated user whose public key is registered for a transaction can submit a signature map containing non-empty but cryptographically invalid bytes (e.g., random bytes, all-zeros padded to the expected length). The system will:

1. Accept the upload and record the user as a signer.
2. Overwrite the stored `transactionBytes` with the corrupted signature embedded.
3. Potentially satisfy the threshold required to advance the transaction to `WAITING_FOR_EXECUTION`.
4. When the chain service submits the transaction to the Hedera network, the network will reject it with `INVALID_SIGNATURE`, causing the transaction to fail permanently.

This enables a legitimate-but-malicious participant to silently sabotage any multi-signature transaction they are a required signer for, with no indication of wrongdoing at the application layer.

### Likelihood Explanation

The attacker must be an authenticated user with a key registered in the system for the target transaction. This is a realistic scenario in any organization workflow where multiple users are required signers. The attack requires no special privileges beyond normal participation in the signing workflow.

### Recommendation

In `processTransactionSignatures`, add cryptographic verification of each signature before calling `addSignature`, mirroring the logic already present in `validateSignature`:

```typescript
// Before: sdkTransaction = sdkTransaction.addSignature(publicKey, map);
// Add:
const bodyBytes = sdkTransaction._signedTransactions.get(0).bodyBytes;
const sig = txMap.get(publicKey);
if (!publicKey.verify(bodyBytes, sig)) {
  throw new Error(ErrorCodes.ISNMPN);
}
sdkTransaction = sdkTransaction.addSignature(publicKey, map);
```

Alternatively, refactor `processTransactionSignatures` to reuse the existing `validateSignature` utility before calling `addSignature`, ensuring a single verified code path for all signature uploads. [6](#0-5) 

### Proof of Concept

1. Register as a user with a valid ECDSA key pair in the organization.
2. Obtain a transaction that requires your key as a signer.
3. Construct a `signatureMap` payload where the signature bytes for your public key are replaced with random non-empty bytes (e.g., 64 bytes of `0xAA`).
4. POST to `POST /transactions/:id/signers` with this payload.
5. Observe: HTTP 201 returned, your user is recorded as a signer in `transaction_signer`, and `transactionBytes` is updated with the invalid signature embedded.
6. If your key was the last required signer, the transaction advances to `WAITING_FOR_EXECUTION`.
7. The chain service submits the transaction; Hedera network returns `INVALID_SIGNATURE`; the transaction is marked `FAILED`. [7](#0-6) [8](#0-7)

### Citations

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L217-267)
```typescript
  private async processTransactionSignatures(
    transaction: Transaction,
    map: SignatureMap,
    userKeyMap: Map<string, UserKey>,
    existingSignerIds: Set<number>
  ) {
    let sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    const userKeys: UserKey[] = [];
    const processedRawKeys = new Set<string>();

    // To explain what is going on here, we need to understand how sdkTransaction.addSignature works.
    // The addSignature method will go through each inner transaction, then go through the map
    // and pull the signatures for the supplied public key belonging to that inner transaction
    // (denoted by the node and transaction id), add the signatures to the inner transactions.
    // So we need to go through the map and get each unique publicKey and call addSignature one time
    // per key.
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
      }
    }

    // Finally, compare the resulting transaction bytes to see if any signatures were actually added
    const isSameBytes = Buffer.from(sdkTransaction.toBytes()).equals(
      transaction.transactionBytes
    );

    return { sdkTransaction, userKeys, isSameBytes };
  }
```

**File:** back-end/libs/common/src/decorators/is-signature-map.decorator.ts (L47-59)
```typescript
          for (const publicKey in publicKeys) {
            const signature = publicKeys[publicKey];
            const decodedSignature = new Uint8Array(decode(signature));

            if (decodedSignature.length === 0) {
              throw new BadRequestException(ErrorCodes.ISNMP);
            }

            signatureMap.addSignature(
              AccountId.fromString(nodeAccountId),
              TransactionId.fromString(transactionId),
              PublicKey.fromString(publicKey),
              decodedSignature,
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L218-222)
```typescript
    /* Checks if the transaction has valid signatureKey */
    if (!hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey))
      throw new Error('Transaction has invalid signature.');

    return sdkTransaction;
```

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L100-119)
```typescript
  @Post()
  @HttpCode(201)
  async uploadSignatureMap(
    @Body() body: UploadSignatureMapDto | UploadSignatureMapDto[],
    @GetUser() user: User,
    @Query('includeNotifications') includeNotifications?: boolean,
  ): Promise<TransactionSigner[] | UploadSignatureMapResponseDto> {
    const transformedSignatureMaps = await transformAndValidateDto(UploadSignatureMapDto, body);

    const { signers, notificationReceiverIds } = await this.signaturesService.uploadSignatureMaps(
      transformedSignatureMaps,
      user,
    );

    if (includeNotifications) {
      return { signers, notificationReceiverIds };
    }

    return signers;
  }
```
