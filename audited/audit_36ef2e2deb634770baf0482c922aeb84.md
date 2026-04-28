### Title
Missing Cryptographic Signature Validity Check in `uploadSignatureMaps` Allows Malicious Signer to Corrupt Transaction State

### Summary
The `POST /transactions/:id/signers` endpoint accepts signature maps and adds them to stored Hedera transactions without verifying that the submitted signature bytes are cryptographically valid. The only guard is a non-zero length check. A legitimate signer can submit an invalid signature (e.g., wrong byte length or random bytes), which gets persisted into the transaction's bytes and recorded as a valid signing event. When the transaction is later submitted to the Hedera network it fails with `INVALID_SIGNATURE`, permanently corrupting the transaction if it expires before the issue is caught.

### Finding Description

**Two signature-upload paths exist in the codebase, with inconsistent validation:**

**Path 1 — `POST /transactions/signatures/import` (`TransactionsService.importSignatures`):**
This path calls `validateSignature` before adding any signature to the transaction. [1](#0-0) 

`validateSignature` calls `publicKey.verify(bodyBytes, signature)` for every entry in the map and throws on failure — a proper cryptographic check. [2](#0-1) 

**Path 2 — `POST /transactions/:id/signers` (`SignersService.uploadSignatureMaps`):**
This path goes through `processTransactionSignatures`, which iterates the map and calls `sdkTransaction.addSignature(publicKey, map)` with **no cryptographic verification** of the signature bytes. [3](#0-2) 

The only upstream guard is the `IsSignatureMap` decorator, which only rejects a signature if its decoded byte length is exactly zero: [4](#0-3) 

Any non-empty byte sequence — including 1 byte of `0x00`, 63 bytes instead of the required 64, or random garbage — passes this check and is accepted into the `SignatureMap`, then written into the stored transaction bytes and committed to the database. [5](#0-4) 

The `TransactionSigner` record is also inserted, marking the user's key as having signed. [6](#0-5) 

### Impact Explanation
A malicious signer submits an invalid signature via `POST /transactions/:id/signers`. The transaction's stored bytes are overwritten with the corrupted signature. If the signing threshold is subsequently met (by other legitimate signers), the transaction advances to `WAITING_FOR_EXECUTION`. The chain service submits it to Hedera, which rejects it with `INVALID_SIGNATURE`. If the transaction's `validStart` window expires before anyone detects and corrects the state, the transaction is permanently unexecutable. For high-value or time-sensitive transactions (e.g., `NodeCreateTransaction`, `FileUpdateTransaction` for network governance files), this constitutes permanent, unrecoverable loss of the transaction's intended effect.

### Likelihood Explanation
The attacker only needs to be an authenticated user with a registered key that is listed as a signer on the target transaction — a normal, non-privileged role. No admin access, no leaked credentials, and no special tooling are required. The attack is a single crafted HTTP POST request. The `IsSignatureMap` decorator's `length === 0` guard is trivially bypassed by supplying any non-empty byte string (e.g., `"0x00"`).

### Recommendation
In `processTransactionSignatures` (`signers.service.ts`), add the same cryptographic verification that `validateSignature` performs before calling `sdkTransaction.addSignature`. Specifically, for each `(publicKey, signature)` pair extracted from the map, call `publicKey.verify(bodyBytes, signature)` against the relevant inner transaction body bytes and reject the entire request if any signature fails verification. The existing `validateSignature` utility in `back-end/libs/common/src/utils/sdk/transaction.ts` already implements this logic and can be reused directly in `processTransactionSignatures`. [1](#0-0) 

### Proof of Concept

**Preconditions:**
- Attacker is an authenticated user with a registered key (`userKey`) that is a required signer on transaction ID `42`.

**Steps:**

1. Attacker calls `POST /transactions/42/signers` with the following body (signature is `0x00` — 1 byte, passes the `length === 0` guard):

```json
{
  "id": 42,
  "signatureMap": {
    "0.0.3": {
      "0.0.1234@1700000000.000000000": {
        "<attacker_DER_public_key>": "0x00"
      }
    }
  }
}
```

2. `IsSignatureMap` decodes `"0x00"` → `Uint8Array([0])`, length is 1, check passes. [7](#0-6) 

3. `processTransactionSignatures` finds the attacker's `UserKey` in `userKeyMap`, calls `sdkTransaction.addSignature(publicKey, map)` — no `verify()` call. [8](#0-7) 

4. The corrupted transaction bytes are persisted; a `TransactionSigner` row is inserted for the attacker's key.

5. Once the signing threshold is met, the chain service submits the transaction to Hedera.

6. Hedera returns `INVALID_SIGNATURE`. The transaction expires and cannot be re-executed.

**Expected outcome:** The request should be rejected with an error indicating the signature is cryptographically invalid, mirroring the behavior of the `importSignatures` path.

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L302-309)
```typescript
      if (userKeys.length > 0) {
        const newSigners = userKeys.map(userKey => ({
          userId: user.id,
          transactionId: id,
          userKeyId: userKey.id,
        }));
        signersToInsert.push(...newSigners);
      }
```

**File:** back-end/libs/common/src/decorators/is-signature-map.decorator.ts (L47-53)
```typescript
          for (const publicKey in publicKeys) {
            const signature = publicKeys[publicKey];
            const decodedSignature = new Uint8Array(decode(signature));

            if (decodedSignature.length === 0) {
              throw new BadRequestException(ErrorCodes.ISNMP);
            }
```
