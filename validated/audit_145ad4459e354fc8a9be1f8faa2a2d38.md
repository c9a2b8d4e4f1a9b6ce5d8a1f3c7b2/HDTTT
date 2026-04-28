Audit Report

## Title
Missing Cryptographic Signature Verification in `uploadSignatureMaps` Allows Forged/Invalid Signatures to Be Accepted and Persisted

## Summary
The `POST /transactions/:transactionId/signers` endpoint processes uploaded signature maps via `SignersService.processTransactionSignatures()` without performing any cryptographic verification of the submitted signature bytes. The code only checks that the submitted public key belongs to the authenticated user, then unconditionally calls `sdkTransaction.addSignature()` with unverified bytes. A required signer can submit a structurally valid signature map containing their own public key paired with garbage/invalid signature bytes. The server records them as a signer, persists the corrupted transaction bytes, and the transaction subsequently fails permanently on the Hedera network when submitted.

## Finding Description

**Root Cause**

In `processTransactionSignatures()`, the only check performed on the signature map is an ownership check — does the public key belong to the authenticated user via `userKeyMap`? There is no call to `validateSignature()` or any equivalent cryptographic verification before `addSignature()` is called.

The critical sequence in `signers.service.ts`:

```
for (const publicKey of txMap.keys()) {
  // ownership check only
  let userKey = userKeyMap.get(raw);
  if (!userKey) throw new Error(ErrorCodes.PNY);

  // NO cryptographic check — raw bytes accepted unconditionally
  sdkTransaction = sdkTransaction.addSignature(publicKey, map);
  userKeys.push(userKey);
}
``` [1](#0-0) 

This is in direct contrast to the `importSignatures()` path in `TransactionsService`, which **does** call `validateSignature()` before `addSignature()`:

```typescript
const { data: publicKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(this, sdkTransaction, map),
);
if (error) throw new BadRequestException(ErrorCodes.ISNMPN);

for (const publicKey of publicKeys) {
  sdkTransaction.addSignature(publicKey, map);
}
``` [2](#0-1) 

The `validateSignature()` function performs the actual cryptographic check via `publicKey.verify(bodyBytes, signature)`, throwing `'Invalid signature'` on failure: [3](#0-2) 

The `IsSignatureMap` decorator only validates structural correctness (valid node account ID, valid transaction ID, non-empty byte array) — it does not verify that the bytes are a valid cryptographic signature over the transaction body: [4](#0-3) 

The `isSameBytes` check at the end of `processTransactionSignatures()` only detects whether the transaction bytes changed after `addSignature()` — it does not verify cryptographic validity: [5](#0-4) 

## Impact Explanation

A required signer can permanently sabotage any transaction they are assigned to by submitting a `SignatureMap` containing their registered public key paired with arbitrary invalid bytes (e.g., 64 zero bytes). The consequences are:

1. The server accepts the submission — ownership check passes, structural validation passes.
2. `addSignature()` embeds the invalid bytes into the transaction's inner signed transactions.
3. `isSameBytes` is `false` (bytes changed), so the corrupted `transactionBytes` are written to the database.
4. A `TransactionSigner` record is created, recording the attacker as having signed.
5. When all required signers are recorded, the chain service submits the transaction to Hedera.
6. Hedera rejects the transaction due to the invalid signature bytes — the transaction is permanently marked `FAILED`.

The transaction is unrecoverable. All other signers' legitimate signatures and coordination effort are wasted. In an organizational multi-sig workflow, a single malicious required signer can unilaterally destroy any transaction they are assigned to.

## Likelihood Explanation

The attacker must be:
1. An authenticated, verified user (registered account in the organization).
2. A required signer for the target transaction.

Both conditions are the normal intended use case — organization members are regularly assigned as required signers. No privileged access, leaked credentials, or external network access is required. The attack requires only a crafted HTTP POST to `POST /transactions/{id}/signers` with a valid JWT and a `SignatureMap` containing the attacker's own registered public key paired with invalid signature bytes.

## Recommendation

Add a call to `validateSignature()` inside `processTransactionSignatures()` before calling `addSignature()`, mirroring the pattern already used in `importSignatures()`:

```typescript
// Validate signatures cryptographically before adding
const { data: validPublicKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(this, sdkTransaction, map),
);
if (error) throw new Error(ErrorCodes.ISNMPN);
```

This ensures that only cryptographically valid signatures (i.e., bytes that actually verify against the transaction body for the given public key) are accepted and persisted.

## Proof of Concept

1. Attacker is an authenticated user whose key (e.g., ECDSA public key `0xABCD...`) is a required signer for transaction ID `42`.
2. Attacker constructs a `SignatureMap` JSON payload:
   ```json
   {
     "0.0.3": {
       "0.0.2@1234567890.000000000": {
         "0xABCD...": "<base64 of 64 zero bytes>"
       }
     }
   }
   ```
3. Attacker POSTs to `POST /transactions/42/signers` with a valid JWT.
4. `IsSignatureMap` decorator validates structure — passes (non-empty bytes, valid account ID, valid transaction ID).
5. `processTransactionSignatures()` finds `0xABCD...` in `userKeyMap` — ownership check passes.
6. `sdkTransaction.addSignature(publicKey, map)` is called with the 64 zero bytes — no cryptographic rejection.
7. `isSameBytes` is `false` (bytes changed), so the corrupted `transactionBytes` are written to the database.
8. A `TransactionSigner` record is created for the attacker.
9. When all required signers are recorded, the transaction is submitted to Hedera.
10. Hedera rejects the transaction — it is permanently marked `FAILED`.

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L243-256)
```typescript
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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L261-264)
```typescript
    // Finally, compare the resulting transaction bytes to see if any signatures were actually added
    const isSameBytes = Buffer.from(sdkTransaction.toBytes()).equals(
      transaction.transactionBytes
    );
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

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L229-241)
```typescript
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
