I have read all the relevant source files. Let me now verify the exact code paths before rendering a verdict.

**Path 1 — `importSignatures`** calls `validateSignature` at: [1](#0-0) 

`validateSignature` performs real cryptographic verification: [2](#0-1) 

**Path 2 — `processTransactionSignatures`** only checks key ownership, then calls `addSignature` with no cryptographic check: [3](#0-2) 

Corrupted bytes are then persisted: [4](#0-3) 

`IsSignatureMap` only validates structural format, not cryptographic validity: [5](#0-4) 

The asymmetry is real and confirmed. The report follows.

---

# Audit Report

## Title
Missing Cryptographic Signature Verification in `uploadSignatureMaps` / `processTransactionSignatures` Allows Injection of Invalid Signatures, Corrupting Stored Transaction Bytes

## Summary
`uploadSignatureMaps` in `signers.service.ts` accepts and persists signature bytes into a transaction's stored `transactionBytes` without cryptographically verifying that the submitted signatures are valid over the transaction body. The sibling path `importSignatures` in `transactions.service.ts` does perform this check via `validateSignature`. An authenticated organization member with a registered `UserKey` can inject arbitrary/garbage signature bytes for their own public key, corrupting the stored transaction and causing it to be rejected by the Hedera network when the chain service attempts to execute it.

## Finding Description

Two separate API paths accept signature submissions:

**Path 1 — `POST /transactions/signatures/import` → `importSignatures`**

Before calling `addSignature`, this path invokes `validateSignature`, which iterates over every `(publicKey, signature)` pair in the map and calls `publicKey.verify(bodyBytes, signature)`, throwing on any invalid signature:

```typescript
// transactions.service.ts:546-549
const { data: publicKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(this, sdkTransaction, map),
);
if (error) throw new BadRequestException(ErrorCodes.ISNMPN);
``` [1](#0-0) 

The cryptographic check inside `validateSignature`:
```typescript
// transaction.ts:235-240
const signatureValid = publicKey.verify(bodyBytes, signature);
if (signatureValid) {
  signerPublicKeys.push(publicKey);
} else {
  throw new Error('Invalid signature');
}
``` [2](#0-1) 

**Path 2 — `POST /transactions/:transactionId/signers` → `uploadSignatureMaps` → `processTransactionSignatures`**

This path only verifies that the public key belongs to the authenticated user, then immediately calls `addSignature` with no cryptographic verification:

```typescript
// signers.service.ts:244-251
let userKey = userKeyMap.get(raw);
if (!userKey) {
  userKey = userKeyMap.get(publicKey.toStringDer());
}
if (!userKey) throw new Error(ErrorCodes.PNY);

sdkTransaction = sdkTransaction.addSignature(publicKey, map);
``` [3](#0-2) 

The Hedera SDK's `addSignature` inserts the provided bytes into the signature map without any cryptographic check. After the call, if the resulting bytes differ from the stored bytes, the corrupted bytes are persisted:

```typescript
// signers.service.ts:262-264, 296-299
const isSameBytes = Buffer.from(sdkTransaction.toBytes()).equals(
  transaction.transactionBytes
);
// ...
if (!isSameBytes) {
  transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
  transactionsToUpdate.push({ id, transactionBytes: transaction.transactionBytes });
}
``` [6](#0-5) [4](#0-3) 

The `IsSignatureMap` decorator only validates structural format (valid account IDs, transaction IDs, non-empty byte arrays) and does not perform any cryptographic verification: [5](#0-4) 

**Root cause:** `processTransactionSignatures` never calls `validateSignature` (or any equivalent), so the `publicKey.verify(bodyBytes, signature)` check that guards `importSignatures` is entirely absent from this code path.

## Impact Explanation

An authenticated organization member with at least one registered `UserKey` can:

1. Call `POST /transactions/:transactionId/signers` with their valid public key but with garbage/invalid signature bytes.
2. The server accepts the request. `processTransactionSignatures` confirms the public key belongs to the user, calls `addSignature` with the garbage bytes, detects `isSameBytes = false`, and persists the corrupted `transactionBytes` to the database.
3. A `TransactionSigner` record is inserted, marking the attacker as having signed.
4. When the chain service later attempts to execute the transaction, the Hedera network rejects it because the stored signature is cryptographically invalid.
5. The attacker can repeatedly re-submit garbage bytes (the `existingSignerIds` check at line 254 only gates `TransactionSigner` record insertion, not the `addSignature` call itself) to keep the transaction in a corrupted state, preventing any valid execution.

The transaction creator can cancel and recreate the transaction, but the attacker can repeat the attack on the new transaction as long as they remain an organization member.

## Likelihood Explanation

**Medium.** The attacker must be an authenticated organization member with a registered `UserKey`. This is not an unauthenticated attack. However, insider threats, compromised accounts, or malicious members of an organization are realistic adversaries in a multi-user transaction coordination system. No special administrative privileges are required — any signer-eligible user can exploit this.

## Recommendation

Add a call to `validateSignature` inside `processTransactionSignatures`, immediately before `sdkTransaction.addSignature(publicKey, map)`, mirroring the check already present in `importSignatures`:

```typescript
// In processTransactionSignatures, before addSignature:
const { data: _, error } = safe<PublicKey[]>(
  validateSignature.bind(null, sdkTransaction, map),
);
if (error) throw new Error(ErrorCodes.ISNMPN);

sdkTransaction = sdkTransaction.addSignature(publicKey, map);
```

This ensures that both signature submission paths enforce the same cryptographic invariant before mutating and persisting transaction state. [7](#0-6) 

## Proof of Concept

1. Register as an organization member and obtain a valid `UserKey` (public key registered in the system).
2. Obtain the internal `transactionId` of a transaction in `WAITING_FOR_SIGNATURES` status for which your key is a required signer.
3. Construct a `POST /transactions/:transactionId/signers` request body with your valid public key but with a garbage 64-byte signature value (e.g., all zeros) in the `signatureMap`.
4. The server responds with success. Inspect the database: `transactionBytes` now contains your garbage signature bytes, and a `TransactionSigner` record exists for your key.
5. When the chain service attempts to execute the transaction, the Hedera network returns `INVALID_SIGNATURE` and the transaction fails.
6. Re-submit the garbage bytes at any time to re-corrupt the stored bytes, preventing recovery without cancellation and recreation of the transaction.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L546-549)
```typescript
        const { data: publicKeys, error } = safe<PublicKey[]>(
          validateSignature.bind(this, sdkTransaction, map),
        );
        if (error) throw new BadRequestException(ErrorCodes.ISNMPN);
```

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L233-240)
```typescript
          const bodyBytes = transaction._signedTransactions.get(col * rowLength + row).bodyBytes;

          const signatureValid = publicKey.verify(bodyBytes, signature);

          if (signatureValid) {
            signerPublicKeys.push(publicKey);
          } else {
            throw new Error('Invalid signature');
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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L296-299)
```typescript
      if (!isSameBytes) {
        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
        transactionsToUpdate.push({ id, transactionBytes: transaction.transactionBytes });
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
