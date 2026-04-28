### Title
Missing Cryptographic Signature Verification in `uploadSignatureMaps` Allows Forged/Invalid Signatures to Be Accepted and Persisted

### Summary
The `POST /transactions/:transactionId/signers` endpoint processes uploaded signature maps in `SignersService.processTransactionSignatures()` without performing any cryptographic verification of the signature bytes. The code only checks that the submitted public key belongs to the authenticated user, then unconditionally calls `sdkTransaction.addSignature()` with the unverified bytes. A required signer can submit a structurally valid signature map containing their own public key paired with garbage/invalid signature bytes. The server records them as a signer, persists the corrupted transaction bytes, and the transaction subsequently fails on the Hedera network when submitted.

### Finding Description

**Root Cause**

In `processTransactionSignatures()`, the only check performed on the signature map is an ownership check — does the public key belong to the authenticated user? There is no call to `validateSignature()` or any equivalent cryptographic verification before `addSignature()` is called. [1](#0-0) 

The critical sequence is:
1. Iterate over the submitted `SignatureMap`
2. For each public key, look it up in `userKeyMap` (the authenticated user's registered keys)
3. If found, call `sdkTransaction.addSignature(publicKey, map)` — **no cryptographic check**
4. Record the user as a signer [2](#0-1) 

The `addSignature` call in the Hiero SDK adds the raw bytes from the map to the transaction's inner signed transactions without verifying them against the transaction body. This is confirmed by the asymmetry with the `importSignatures()` path in `TransactionsService`, which **does** call `validateSignature()` before `addSignature()`: [3](#0-2) 

The `validateSignature()` function performs the actual cryptographic check (`publicKey.verify(bodyBytes, signature)`): [4](#0-3) 

The `uploadSignatureMaps` path is missing this call entirely.

**Exploit Flow**

1. Attacker is an authenticated user whose key is a required signer for a target transaction.
2. Attacker constructs a `SignatureMap` containing their registered public key paired with arbitrary invalid bytes (e.g., 64 zero bytes) as the signature.
3. Attacker POSTs to `POST /transactions/{id}/signers` with this map.
4. `IsSignatureMap` decorator validates structure (node account ID, transaction ID, non-empty bytes) — passes. [5](#0-4) 

5. `processTransactionSignatures()` finds the public key in `userKeyMap` — ownership check passes.
6. `sdkTransaction.addSignature(publicKey, map)` is called with the invalid bytes — no cryptographic rejection.
7. `isSameBytes` is `false` (bytes changed), so the corrupted `transactionBytes` are written to the database.
8. A `TransactionSigner` record is created, recording the attacker as having signed.
9. The chain service later calls `getValidatedSDKTransaction()`, which checks `hasValidSignatureKey()` against `_signerPublicKeys` — the attacker's key is present (added by `addSignature`), so the check passes. [6](#0-5) 

10. The transaction is submitted to the Hedera network with the invalid signature bytes.
11. Hedera rejects the transaction — it is marked `FAILED` permanently.

### Impact Explanation

A required signer can permanently sabotage any transaction they are assigned to by submitting invalid signature bytes. The transaction:
- Appears fully signed to the system (all required signers recorded)
- Is submitted to Hedera and rejected due to the invalid signature
- Is permanently marked `FAILED` — unrecoverable
- Wastes all other signers' legitimate signatures and coordination effort

This is a concrete integrity failure: the system accepts and persists a forged/invalid signature, leading to permanent corruption of transaction state. In an organizational multi-sig workflow, a single malicious required signer can unilaterally destroy any transaction they are assigned to, with no ability for other participants to recover it.

### Likelihood Explanation

The attacker must be:
1. An authenticated, verified user (registered account)
2. A required signer for the target transaction

Both conditions are realistic in the intended use case — organization members are regularly assigned as required signers. No privileged access, leaked credentials, or external network access is required. The attack requires only a crafted HTTP POST to a standard API endpoint with a valid JWT.

### Recommendation

Add cryptographic signature verification in `processTransactionSignatures()` before calling `addSignature()`, mirroring the pattern already used in `importSignatures()`:

```typescript
// Before calling addSignature, verify the signature bytes are valid
const { data: verifiedKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(this, sdkTransaction, map),
);
if (error) throw new Error(ErrorCodes.ISNMPN);
```

The `validateSignature` function at `back-end/libs/common/src/utils/sdk/transaction.ts` lines 213–247 already implements the correct cryptographic check and should be reused here. [7](#0-6) 

### Proof of Concept

1. Register as a user and obtain a JWT token.
2. Create a transaction where your registered key is a required signer.
3. Construct a signature map with your public key (DER-encoded) and 64 zero bytes as the signature value.
4. POST to `/transactions/{id}/signers`:
```json
{
  "id": <transaction_id>,
  "signatureMap": {
    "0.0.3": {
      "0.0.<your_account>@<timestamp>": {
        "<your_public_key_der>": "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
      }
    }
  }
}
```
5. Observe HTTP 201 response — server accepts the invalid signature.
6. Observe `TransactionSigner` record created for your user key.
7. Observe `transactionBytes` in the database updated with the invalid signature.
8. When the chain service executes the transaction, observe it fail on Hedera with an invalid signature error and the transaction status set to `FAILED`.

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L234-256)
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
```

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

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L213-247)
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
```

**File:** back-end/libs/common/src/decorators/is-signature-map.decorator.ts (L47-60)
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
            );
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L218-222)
```typescript
    /* Checks if the transaction has valid signatureKey */
    if (!hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey))
      throw new Error('Transaction has invalid signature.');

    return sdkTransaction;
```
