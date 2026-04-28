After verifying the actual code in the repository, the vulnerability claim is substantiated. Here is the validated report:

---

Audit Report

## Title
Missing Cryptographic Signature Verification in `processTransactionSignatures` Allows Authenticated User to Falsely Register as a Transaction Signer

## Summary

`SignersService.processTransactionSignatures` verifies that a submitted public key belongs to the authenticated user but never verifies that the accompanying signature bytes are cryptographically valid for that key. An authenticated user can submit a `SignatureMap` containing their own registered public key paired with arbitrary bytes, and the system will accept it, persist them as a signer, and overwrite the stored transaction bytes with the invalid signature.

## Finding Description

**Root cause — missing cryptographic verification in `processTransactionSignatures`:**

In `back-end/apps/api/src/transactions/signers/signers.service.ts`, the loop at lines 234–258 iterates over every `publicKey` in the submitted `SignatureMap`, checks ownership via `userKeyMap`, and then unconditionally calls `sdkTransaction.addSignature(publicKey, map)`:

```typescript
if (!userKey) throw new Error(ErrorCodes.PNY);   // ← only ownership check

sdkTransaction = sdkTransaction.addSignature(publicKey, map); // ← no validity check
``` [1](#0-0) 

The Hedera SDK's `addSignature` blindly appends whatever bytes are in the map. There is no call to `PublicKey.verify()` or any equivalent before or after `addSignature`.

**Contrast with `validateSignature`**, which exists in the codebase and does perform cryptographic verification:

```typescript
const signatureValid = publicKey.verify(bodyBytes, signature);
if (signatureValid) {
  signerPublicKeys.push(publicKey);
} else {
  throw new Error('Invalid signature');
}
``` [2](#0-1) 

This `validateSignature` utility is used elsewhere (in `transactions.service.ts`) but is entirely absent from the `uploadSignatureMaps` → `processTransactionSignatures` path. [3](#0-2) 

**Byte corruption path confirmed:** After `addSignature`, the code compares resulting bytes. If they differ (`!isSameBytes`), the corrupted transaction bytes are persisted to the database:

```typescript
if (!isSameBytes) {
  transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
  transactionsToUpdate.push({ id, transactionBytes: transaction.transactionBytes });
}
``` [4](#0-3) 

**Signer registration path confirmed:** The attacker's key is added to `userKeys` and subsequently bulk-inserted into `TransactionSigner`: [5](#0-4) [6](#0-5) 

**Exploit flow:**
1. Attacker authenticates as a normal user and registers a public key `K`.
2. Attacker constructs a `SignatureMap` containing key `K` paired with 64 bytes of garbage (e.g., all zeros).
3. Attacker POSTs to `POST /transactions/<id>/signers`.
4. `processTransactionSignatures` finds `K` in `userKeyMap` → ownership check passes.
5. `addSignature(K, garbage_map)` appends invalid bytes → `isSameBytes` is `false`.
6. Corrupted `transactionBytes` are written to the database.
7. Attacker's key is inserted as a `TransactionSigner` record.

## Impact Explanation

- **False signer accounting**: The system records the attacker as having signed the transaction. If the transaction requires a threshold of signers, this false entry can make the system believe the threshold is met when it is not.
- **Transaction byte corruption**: The stored `transactionBytes` are overwritten with a version containing an invalid signature. Any subsequent legitimate signer who downloads and re-signs the transaction will be working from corrupted bytes.
- **On-chain failure / DoS**: When the chain service submits the transaction to the Hedera network, the network will reject it due to the invalid signature, permanently failing the transaction. The stored bytes cannot be recovered.
- **Integrity break**: The `TransactionSigner` table no longer accurately reflects who has actually signed, breaking the trust model of the multi-signature workflow.

## Likelihood Explanation

- **Preconditions**: The attacker only needs a valid JWT and one registered public key — both are normal user-level capabilities requiring no privilege escalation.
- **Attack complexity**: Constructing a `SignatureMap` with a known public key and garbage signature bytes is trivial using the Hedera SDK or by crafting the protobuf directly.
- **No detection**: The system logs no error and returns a success response; the attack is silent.
- **Reachable endpoint**: `POST /transactions/:id/signers` is a standard API endpoint protected only by JWT authentication.

## Recommendation

Add a call to the existing `validateSignature` utility inside `processTransactionSignatures`, before or immediately after `addSignature`, to cryptographically verify each signature byte array against the transaction body bytes and the claimed public key. This mirrors the verification already performed in the `importSignatures` path via `transactions.service.ts`. Reject the entire submission with a `BadRequestException` if any signature fails verification, consistent with the existing `ErrorCodes.ISNMPN` error handling pattern. [3](#0-2) [7](#0-6) 

## Proof of Concept

```typescript
import { SignatureMap, PublicKey, Transaction } from '@hiero-ledger/sdk';

// 1. Obtain a valid JWT for a normal user account
// 2. Retrieve the user's registered public key hex string (e.g. from GET /user/keys)
const myPublicKey = PublicKey.fromString('<registered_public_key_hex>');

// 3. Build a SignatureMap with the real public key but garbage signature bytes
const fakeSignature = new Uint8Array(64).fill(0x00); // 64 zero bytes
const signatureMap = new SignatureMap();
// Populate signatureMap with myPublicKey -> fakeSignature for the target transaction's
// node account IDs and transaction ID (obtainable from GET /transactions/:id)

// 4. POST to the signers endpoint
// POST /transactions/<target_id>/signers
// Authorization: Bearer <jwt>
// Body: [{ id: <target_id>, signatureMap: <serialized_signatureMap> }]

// Expected (vulnerable) result:
// - HTTP 200/201 success response
// - TransactionSigner row inserted for attacker's key
// - transaction.transactionBytes overwritten with garbage-signature bytes
// - Subsequent on-chain submission fails with INVALID_SIGNATURE
```

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L296-299)
```typescript
      if (!isSameBytes) {
        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
        transactionsToUpdate.push({ id, transactionBytes: transaction.transactionBytes });
      }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L336-340)
```typescript
        // Bulk insert signers
        if (signersToInsert.length > 0) {
          const results = await this.bulkInsertSigners(manager, signersToInsert);
          results.forEach(signer => signers.add(signer));
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
