### Title
Unverified Signature Bytes in `uploadSignatureMaps` Allow a Malicious Signer to Corrupt and Permanently Destroy Multi-Signature Transactions

### Summary
In `SignersService.processTransactionSignatures`, the server verifies that the public key in a submitted `signatureMap` belongs to the authenticated user, but never cryptographically verifies that the accompanying signature bytes are a valid signature over the transaction body. A malicious user who is a required signer can submit their legitimate public key paired with forged/invalid signature bytes. The system records them as a signer, overwrites the stored transaction bytes with the corrupted data, and may advance the transaction to `WAITING_FOR_EXECUTION`, causing it to be permanently rejected by the Hedera network.

### Finding Description

**Root Cause**

There are two signature-upload code paths in the back-end:

1. `POST /transactions/:transactionId/signers` → `SignersController.uploadSignatureMap` → `SignersService.uploadSignatureMaps` → `processTransactionSignatures`
2. `TransactionsService.importSignatures`

Path 2 calls `validateSignature` which cryptographically verifies every signature byte against the transaction body: [1](#0-0) 

Path 1 — the primary signing endpoint — does **not** call `validateSignature`. In `processTransactionSignatures`, the only check performed is whether the public key in the map belongs to the authenticated user: [2](#0-1) 

After confirming key ownership, the code unconditionally calls `sdkTransaction.addSignature(publicKey, map)`, which in the Hedera SDK adds the raw bytes from the map to the transaction without cryptographic verification. The resulting (potentially corrupted) bytes are then persisted: [3](#0-2) 

**Exploit Flow**

1. Attacker registers a valid public key (`pubKeyA`) with the system — a normal user action.
2. Attacker is added as a required signer to a multi-sig transaction T.
3. Attacker constructs a `signatureMap` containing `pubKeyA` mapped to 64 zero bytes (or any invalid bytes).
4. Attacker calls `POST /transactions/T/signers` with this map.
5. `processTransactionSignatures` finds `pubKeyA` in `userKeyMap` → ownership check passes.
6. `sdkTransaction.addSignature(pubKeyA, map)` embeds the invalid bytes into the transaction.
7. `isSameBytes` is `false`; the corrupted `transactionBytes` are written to the database and the attacker is recorded as a `TransactionSigner`.
8. If the attacker was the last required signer, `processTransactionStatus` advances the transaction to `WAITING_FOR_EXECUTION`.
9. The chain service submits the transaction to the Hedera network.
10. Hedera rejects the transaction due to the invalid signature → status becomes `FAILED` (terminal state).

The controller endpoint is guarded only by JWT authentication — no privileged role is required: [4](#0-3) 

### Impact Explanation

A malicious authenticated user who is a required signer can **permanently destroy any multi-signature transaction** they are part of. The transaction enters the terminal `FAILED` state and cannot be re-executed. All other signers' work (collecting signatures, approvals) is lost. For high-value or time-sensitive Hedera operations (e.g., system file updates, node operations, large transfers), this constitutes an irreversible denial of service against the transaction's intended outcome.

### Likelihood Explanation

The attacker only needs to be a normal authenticated user who has been added as a required signer — a routine organizational workflow. No privileged access, leaked credentials, or cryptographic breaks are required. The attack requires a single crafted API call. Any disgruntled or malicious organization member who is a signer can trigger this.

### Recommendation

Add cryptographic signature verification in `processTransactionSignatures` before calling `addSignature`, mirroring what `importSignatures` already does:

```typescript
// In processTransactionSignatures, before sdkTransaction.addSignature(publicKey, map):
const { data: validKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(null, sdkTransaction, map),
);
if (error) throw new Error(ErrorCodes.ISNMPN);
```

The `validateSignature` utility already exists and performs the correct per-byte cryptographic check: [1](#0-0) 

Alternatively, unify both upload paths to share the same validation logic so the gap cannot re-emerge.

### Proof of Concept

**Preconditions**: Two users exist; User A creates a 2-of-2 multi-sig transaction requiring signatures from both User A and User B (the attacker). User B has registered public key `pubKeyB`.

**Steps**:
1. User B generates a valid `SignatureMap` structure with `pubKeyB` as the key but replaces the 64-byte signature value with `0x` + `"00".repeat(64)`.
2. User B sends:
   ```
   POST /transactions/{txId}/signers
   Authorization: Bearer <user_b_jwt>
   Body: { "id": txId, "signatureMap": { "0.0.3": { "<txId>@<validStart>": { "<pubKeyB_DER>": "0x000...000" } } } }
   ```
3. The server accepts the request (200/201), records User B as a signer, and overwrites `transactionBytes` with the corrupted data.
4. If User A had already signed, the transaction advances to `WAITING_FOR_EXECUTION`.
5. The chain service submits the transaction; Hedera returns `INVALID_SIGNATURE`.
6. Transaction status is set to `FAILED` — permanently unrecoverable. [5](#0-4)

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

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L39-39)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
```
