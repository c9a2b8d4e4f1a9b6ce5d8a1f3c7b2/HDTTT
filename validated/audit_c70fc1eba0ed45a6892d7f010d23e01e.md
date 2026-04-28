All four claims were verified against the actual source code. Here is the result:

---

Audit Report

## Title
Missing Cryptographic Signature Validation in `uploadSignatureMaps` Allows Forged Signatures to Corrupt Transaction State

## Summary
`SignersService.uploadSignatureMaps` (`POST /transactions/:transactionId/signers`) accepts and persists signature bytes without cryptographically verifying them against the transaction body. A registered user can submit arbitrary bytes as a "signature" for their own registered public key, causing the system to falsely record them as a valid signer, overwrite the stored transaction bytes with corrupted data, and potentially advance the transaction toward execution — where it will be rejected by the Hedera network. The parallel endpoint `POST /transactions/signatures/import` correctly calls `validateSignature()` before accepting signatures, confirming the fix is known but was not applied to the signer upload path.

## Finding Description

**Root cause — missing `validateSignature` call in `processTransactionSignatures`:**

`SignersService.processTransactionSignatures` iterates over the submitted `SignatureMap`, checks that each public key belongs to the authenticated user via `userKeyMap`, and then unconditionally calls `sdkTransaction.addSignature(publicKey, map)`: [1](#0-0) 

The only check performed is ownership of the public key — not whether the submitted signature bytes are a valid cryptographic signature over the transaction body. There is no call to `validateSignature()` anywhere in this path.

**Contrast — `importSignatures` correctly validates:**

`TransactionsService.importSignatures` calls `validateSignature` before adding any signature: [2](#0-1) 

**What `validateSignature` actually does:**

It iterates the signature map and calls `publicKey.verify(bodyBytes, signature)` for each entry, throwing `'Invalid signature'` on failure: [3](#0-2) 

The `uploadSignatureMaps` path never calls this function. The Hedera SDK's `addSignature` method does not perform cryptographic verification — it simply appends the bytes to the internal signature map.

**Persistence of corrupted state:**

After `processTransactionSignatures` returns, `persistSignatureChanges` writes the corrupted transaction bytes to the database and inserts a `TransactionSigner` record marking the user as having signed: [4](#0-3) 

## Impact Explanation

1. **Integrity failure / threshold bypass**: A user who is a required signer can submit forged (cryptographically invalid) signature bytes for their own registered public key. The system records them as a valid signer. If this satisfies the multi-signature threshold, the transaction is advanced to `WAITING_FOR_EXECUTION` without any legitimate signature from that key.

2. **Guaranteed on-chain execution failure**: The chain service submits the transaction to Hedera with invalid signature bytes. Hedera rejects it. The transaction fails permanently, causing a denial-of-service against any transaction where this attack is used.

3. **Permanent state corruption**: The stored `transactionBytes` in the database are overwritten with bytes containing an invalid signature, corrupting the transaction record for all participants. The `isSameBytes` check at line 262 only detects whether bytes changed — not whether the change is valid — so corrupted bytes pass through. [5](#0-4) 

## Likelihood Explanation

**Attacker preconditions (no privilege required):**
- A registered organization user account (normal user, no admin role needed).
- At least one registered public key in the system.
- Access to a transaction where that key is a required signer (the normal workflow — users are notified when their signature is needed).

The attack requires only crafting a `SignatureMap` with arbitrary bytes for the attacker's own public key and posting it to the standard signer upload endpoint. This is a normal API call that any authenticated user makes as part of the signing workflow. No cryptographic break, no leaked secrets, no privileged access required.

## Recommendation

Add a `validateSignature()` call inside `processTransactionSignatures`, mirroring the pattern already used in `importSignatures`. Specifically, before calling `sdkTransaction.addSignature(publicKey, map)`, call `validateSignature(sdkTransaction, map)` (or an equivalent per-key check using `publicKey.verify(bodyBytes, signature)`) and throw an error if validation fails. This ensures that only cryptographically valid signatures over the actual transaction body are accepted and persisted. [6](#0-5) 

## Proof of Concept

1. Register a user account and register a public key (e.g., ECDSA key pair `K`).
2. Obtain or be assigned to a transaction `T` that requires a signature from `K`.
3. Construct a `SignatureMap` containing the public key of `K` mapped to arbitrary random bytes (e.g., 64 zero bytes) as the "signature".
4. POST the crafted payload to `POST /transactions/T/signers` with valid JWT authentication.
5. Observe that the server responds with success and a new `TransactionSigner` record is created for the user.
6. Query the transaction and observe that `transactionBytes` now contains the invalid signature bytes.
7. If the forged signature satisfies the threshold, the transaction status advances to `WAITING_FOR_EXECUTION`.
8. When the chain service submits the transaction to Hedera, it is rejected with `INVALID_SIGNATURE`, permanently failing the transaction.

### Citations

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L296-309)
```typescript
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
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L546-549)
```typescript
        const { data: publicKeys, error } = safe<PublicKey[]>(
          validateSignature.bind(this, sdkTransaction, map),
        );
        if (error) throw new BadRequestException(ErrorCodes.ISNMPN);
```

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L235-241)
```typescript
          const signatureValid = publicKey.verify(bodyBytes, signature);

          if (signatureValid) {
            signerPublicKeys.push(publicKey);
          } else {
            throw new Error('Invalid signature');
          }
```
