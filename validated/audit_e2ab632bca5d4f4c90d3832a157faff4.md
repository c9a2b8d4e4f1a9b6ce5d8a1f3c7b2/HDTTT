The code confirms the claim. Let me verify the `persistSignatureChanges` guard condition precisely before writing the report.

Audit Report

## Title
Missing Cryptographic Signature Verification in `processTransactionSignatures` Allows False Signer Registration

## Summary
The `SignersService.processTransactionSignatures` method records a user as a transaction signer and updates transaction bytes without ever verifying that the submitted signature bytes are cryptographically valid. Any authenticated user who owns a registered key can submit a `SignatureMap` containing their public key paired with arbitrary/garbage bytes, be permanently recorded as a legitimate signer, and potentially advance the transaction to `WAITING_FOR_EXECUTION` — causing irreversible on-chain failure.

## Finding Description

**Root cause:** `processTransactionSignatures` performs only an ownership check (does this public key belong to the authenticated user?) and then unconditionally calls `sdkTransaction.addSignature(publicKey, map)` and pushes the user into `userKeys`. No call to `publicKey.verify(bodyBytes, signature)` is made. [1](#0-0) 

The only downstream guard in `persistSignatureChanges` is:

```typescript
if (isSameBytes && userKeys.length === 0) continue;
``` [2](#0-1) 

This guard only skips processing when **both** conditions are true. When an attacker submits garbage bytes for the first time, `addSignature` modifies the transaction bytes (making `isSameBytes = false`) and `userKeys.length > 0` (new signer), so both conditions fail — the signer record is inserted and the corrupted transaction bytes are persisted.

A correct cryptographic verification helper, `validateSignature`, already exists in the codebase and calls `publicKey.verify(bodyBytes, signature)`, throwing on failure: [3](#0-2) 

This helper is correctly used in the parallel `importSignatures` path: [4](#0-3) 

But it is entirely absent from the `uploadSignatureMaps` → `validateAndProcessSignatures` → `processTransactionSignatures` call chain in `signers.service.ts`. [5](#0-4) 

## Impact Explanation

- **False signer record**: The attacker is permanently recorded in `TransactionSigner` as having signed a transaction they did not sign.
- **Corrupted transaction bytes**: The garbage signature bytes are written to `transaction.transactionBytes` in the database, replacing the valid accumulated signatures.
- **Premature status advancement**: If the attacker's false record satisfies the last required signature threshold, `processTransactionStatus` advances the transaction to `WAITING_FOR_EXECUTION`.
- **Irreversible on-chain failure**: The chain service submits the transaction to Hedera with a missing or invalid signature; Hedera rejects it, and the transaction is permanently marked `FAILED` — a terminal state with no recovery path in the system.
- **Denial of Service against legitimate users**: Legitimate signers can no longer complete the transaction; any funds or operations it represents are permanently blocked.

## Likelihood Explanation

- **Minimal attacker precondition**: a valid account with any one registered key — the lowest possible privilege level in the system.
- **No additional authorization**: the endpoint `POST /transactions/:id/signers` is reachable by any authenticated user; `loadTransactionData` fetches transactions by ID with no access-control check.
- **Trivial to craft**: constructing a `SignatureMap` with a valid public key and arbitrary signature bytes requires only the public Hedera SDK API.
- **Asymmetric discrepancy**: the `importSignatures` path verifies signatures; the `uploadSignatureMaps` path does not — making this a straightforward oversight to identify and exploit.

## Recommendation

Call `validateSignature` inside `processTransactionSignatures` before calling `addSignature`, mirroring the pattern already used in `importSignatures`:

```typescript
// In processTransactionSignatures, before sdkTransaction.addSignature(publicKey, map):
const { data: validKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(null, sdkTransaction, map),
);
if (error) throw new Error(ErrorCodes.ISNMPN);
```

Only keys returned by `validateSignature` (those whose signatures pass `publicKey.verify(bodyBytes, signature)`) should be passed to `addSignature` and recorded as signers.

## Proof of Concept

1. Attacker registers an account and adds a key pair with public key `K_attacker`.
2. Attacker observes any transaction in `WAITING_FOR_SIGNATURES` status (transaction ID is sufficient; no access-control check in `loadTransactionData`).
3. Attacker constructs a `SignatureMap` using the Hedera SDK, mapping `K_attacker` to 64 bytes of random garbage.
4. Attacker calls `POST /transactions/:id/signers` with this map.
5. `processTransactionSignatures` finds `K_attacker` in `userKeyMap` (ownership check passes), calls `sdkTransaction.addSignature(K_attacker, map)` with the garbage bytes, and pushes the attacker into `userKeys`.
6. `isSameBytes` is `false` (bytes changed) and `userKeys.length > 0`, so `persistSignatureChanges` inserts the signer record and overwrites `transactionBytes` with the garbage-signed transaction.
7. `processTransactionStatus` is called; if this was the last required signature, the transaction advances to `WAITING_FOR_EXECUTION`.
8. The chain service submits the transaction to Hedera; Hedera rejects it due to the invalid signature; the transaction is permanently set to `FAILED`.

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L293-309)
```typescript
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L546-549)
```typescript
        const { data: publicKeys, error } = safe<PublicKey[]>(
          validateSignature.bind(this, sdkTransaction, map),
        );
        if (error) throw new BadRequestException(ErrorCodes.ISNMPN);
```
