### Title
Missing Cryptographic Signature Verification in `processTransactionSignatures` Allows Invalid Signatures to Be Accepted as Valid Signers

### Summary
The `uploadSignatureMaps` code path in `signers.service.ts` accepts and persists any signature bytes submitted by an authenticated user without performing cryptographic verification. A user with a registered public key can submit a signature map containing garbage/invalid signature bytes, be recorded as a valid signer, and cause the transaction's stored bytes to be corrupted with an invalid signature — permanently preventing the transaction from executing on-chain.

### Finding Description

There are two code paths for submitting signatures in this system:

**Path 1 — `transactions.service.ts::importSignatures`** (lines 545–549): calls `validateSignature`, which performs explicit cryptographic verification via `publicKey.verify(bodyBytes, signature)` before accepting any signature. [1](#0-0) 

**Path 2 — `signers.service.ts::uploadSignatureMaps` → `processTransactionSignatures`** (lines 217–267): iterates over the submitted `SignatureMap`, checks only that the public key belongs to the authenticated user (`userKeyMap.get(raw)`), then calls `sdkTransaction.addSignature(publicKey, map)` **without any call to `publicKey.verify()`**. [2](#0-1) 

The Hedera SDK's `addSignature` method does not validate signatures cryptographically — it blindly appends whatever bytes are in the map to the transaction. Verification only occurs at the Hedera network level when the transaction is submitted.

After `addSignature` is called with invalid bytes:
- `isSameBytes` becomes `false` (bytes changed), so the corrupted transaction bytes are written to the database.
- The user key is pushed to `userKeys` and persisted as a `TransactionSigner` record.
- `processTransactionStatus` is called, which may advance the transaction to `WAITING_FOR_EXECUTION`. [3](#0-2) 

The root cause is the absence of `publicKey.verify()` in `processTransactionSignatures`, which is present in `validateSignature` but absent in this parallel code path.

### Impact Explanation

An authenticated user with at least one registered public key can:

1. Construct a `SignatureMap` containing their registered public key mapped to 64 bytes of zeros (valid format, invalid cryptographic signature).
2. Submit it to `POST /transactions/{id}/signers`.
3. Be recorded as a valid signer in the `transaction_signer` table.
4. Cause the transaction's stored `transactionBytes` to be overwritten with the invalid signature.
5. If this was the last required signature, the transaction advances to `WAITING_FOR_EXECUTION` and the chain service submits it to Hedera.
6. Hedera rejects the transaction with `INVALID_SIGNATURE`.
7. The transaction is permanently broken — it cannot be re-signed or re-executed because its stored bytes now contain an invalid signature.

**Impact category:** Permanent lock/freeze of user/project state; unauthorized state change (signer registration without valid cryptographic proof).

### Likelihood Explanation

- **Attacker preconditions:** Only requires a valid authenticated account with at least one registered public key — the baseline unprivileged user role.
- **No privileged access required.**
- **Trivially reachable:** The `POST /transactions/{id}/signers` endpoint is the normal signing workflow. Any user who is an observer or approver of a transaction can reach it.
- **Deterministic:** The attack always succeeds because there is no cryptographic check in this code path.

### Recommendation

Add explicit cryptographic signature verification inside `processTransactionSignatures`, mirroring the check already present in `validateSignature`:

```typescript
// After resolving userKey, before calling addSignature:
for (const [nodeAccountId, txMap] of map._map) {
  for (const [transactionId, pkMap] of txMap._map) {
    const sigBytes = pkMap._map.get(publicKey.toStringDer());
    if (sigBytes) {
      const row = nodeAccountIdRow[nodeAccountId];
      const col = transactionIdCol[transactionId];
      const bodyBytes = sdkTransaction._signedTransactions.get(col * rowLength + row).bodyBytes;
      if (!publicKey.verify(bodyBytes, sigBytes)) {
        throw new Error(ErrorCodes.ISNMP);
      }
    }
  }
}
```

Alternatively, refactor `processTransactionSignatures` to call the existing `validateSignature` utility before calling `addSignature`, eliminating the duplicated (and incomplete) code path. [4](#0-3) 

### Proof of Concept

**Setup:** Attacker is an authenticated user with registered public key `PK_A` (ECDSA or ED25519). A transaction `TX_ID` exists in `WAITING_FOR_SIGNATURES` status and requires `PK_A` as one of its signers.

**Steps:**

1. Construct a `SignatureMap` object where `PK_A` maps to 64 zero bytes (`Buffer.alloc(64)`) for each node/transaction ID entry.
2. Send `POST /api/transactions/{TX_ID}/signers` with `{ signatureMap: <constructed map> }` using the attacker's auth token.
3. Observe HTTP 201 response — the attacker is recorded as a signer.
4. Query the database: `SELECT * FROM transaction_signer WHERE "transactionId" = TX_ID` — attacker's `userKeyId` appears.
5. Query `transaction.transactionBytes` — the bytes now contain the invalid zero-byte signature.
6. If `TX_ID` required only `PK_A`, the transaction status advances to `WAITING_FOR_EXECUTION`.
7. The chain service submits the transaction to Hedera; Hedera returns `INVALID_SIGNATURE`.
8. The transaction is permanently failed/frozen.

**Expected (correct) behavior:** The server should reject the request with `400 ISNMP` because the signature bytes do not cryptographically verify against `PK_A` over the transaction body bytes. [5](#0-4)

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L290-312)
```typescript
      // Skip if nothing to do - no signatures were added to the transaction
      // AND no new signers were inserted (the signature can be present on the transaction
      // if collated by an outside or 'offline' method)
      if (isSameBytes && userKeys.length === 0) continue;

      // Collect updates
      if (!isSameBytes) {
        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
        transactionsToUpdate.push({ id, transactionBytes: transaction.transactionBytes });
      }

      // Collect inserts
      if (userKeys.length > 0) {
        const newSigners = userKeys.map(userKey => ({
          userId: user.id,
          transactionId: id,
          userKeyId: userKey.id,
        }));
        signersToInsert.push(...newSigners);
      }

      transactionsToProcess.push({ id, transaction });
      notificationsToUpdate.push({ userId: user.id, transactionId: transaction.id });
```
