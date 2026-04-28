### Title
Missing Cryptographic Signature Validation in `uploadSignatureMaps` Allows Forged Signer Registration and Forced Transaction Failure

### Summary
The `uploadSignatureMaps` endpoint (`POST /transactions/:id/signers`) in `signers.service.ts` accepts signature maps and records signers without performing any cryptographic verification of the signature bytes. A required signer can submit their own public key paired with arbitrary/invalid signature bytes, be recorded as a legitimate signer, and cause the transaction to advance to `WAITING_FOR_EXECUTION` with a corrupted signature — which the Hedera network will then reject, permanently failing the transaction.

### Finding Description

**Root cause:** `processTransactionSignatures` in `signers.service.ts` only checks that the submitted public key belongs to the calling user (via `userKeyMap` lookup), then unconditionally calls `sdkTransaction.addSignature(publicKey, map)` without verifying that the signature bytes are cryptographically valid for that key. [1](#0-0) 

The `addSignature` call adds the public key to `sdkTransaction._signerPublicKeys` regardless of whether the signature bytes are valid. No call to `validateSignature` is made anywhere in this path.

**Contrast with `importSignatures`** in `transactions.service.ts`, which explicitly validates signature bytes before adding them: [2](#0-1) 

**Downstream state corruption:** After `persistSignatureChanges` writes the corrupted transaction bytes and signer record to the database, `updateStatusesAndNotify` calls `processTransactionStatus`: [3](#0-2) 

`processTransactionStatus` evaluates `hasValidSignatureKey` against `sdkTransaction._signerPublicKeys`: [4](#0-3) 

Because the attacker's public key was added to `_signerPublicKeys` by `addSignature` (even with invalid bytes), `hasValidSignatureKey` returns `true`, and the transaction is promoted to `WAITING_FOR_EXECUTION`.

`hasValidSignatureKey` itself only checks key presence, not cryptographic validity: [5](#0-4) 

The chain service then calls `getValidatedSDKTransaction`, which re-runs `hasValidSignatureKey` (still passes), and submits the transaction to Hedera. Hedera rejects it with `INVALID_SIGNATURE`, and the transaction is permanently marked `FAILED`. [6](#0-5) 

**Full call graph:**
```
POST /transactions/:id/signers
  → SignersService.uploadSignatureMaps
    → validateAndProcessSignatures
      → processTransactionSignatures   ← NO validateSignature call
        → sdkTransaction.addSignature  ← adds key to _signerPublicKeys unconditionally
    → persistSignatureChanges          ← writes corrupted bytes + signer record to DB
    → updateStatusesAndNotify
      → processTransactionStatus
        → hasValidSignatureKey         ← passes because key is in _signerPublicKeys
        → status → WAITING_FOR_EXECUTION
  → chain service executes → Hedera rejects → FAILED
```

### Impact Explanation

A required signer can permanently destroy any transaction they are required to sign by submitting their own public key with garbage signature bytes. The transaction is irrecoverably marked `FAILED` on-chain. In a multi-party signing workflow, a single malicious required signer can unilaterally veto and destroy any transaction, even one they were only added to as a signer by the creator. This breaks the integrity guarantee of the multi-signature orchestration system.

### Likelihood Explanation

The attacker only needs to be a registered user whose public key appears in the transaction's required signing set — a normal, non-privileged role in the system. The `POST /transactions/:id/signers` endpoint is a standard user-facing API. The attacker constructs a `SignatureMap` containing their own public key with arbitrary bytes (e.g., 64 zero bytes) and submits it. No special access, leaked credentials, or cryptographic breaks are required.

### Recommendation

Add a `validateSignature` call inside `processTransactionSignatures` before calling `addSignature`, mirroring the pattern already used in `importSignatures`:

```typescript
// In processTransactionSignatures, before sdkTransaction.addSignature(publicKey, map):
const { error } = safe<PublicKey[]>(
  validateSignature.bind(this, sdkTransaction, map),
);
if (error) throw new Error(ErrorCodes.ISNMPN);
``` [7](#0-6) 

### Proof of Concept

1. User A creates a transaction requiring signatures from User A and User B (e.g., a `KeyList` with both keys).
2. User A signs legitimately.
3. User B (attacker) constructs a `SignatureMap` containing their own public key but with 64 bytes of `0x00` as the signature value.
4. User B calls `POST /transactions/:id/signers` with this forged map.
5. `processTransactionSignatures` finds User B's key in `userKeyMap` (ownership check passes), calls `addSignature` with the invalid bytes — no `validateSignature` is called.
6. User B is inserted into `transaction_signer` table; transaction bytes are updated with the invalid signature.
7. `processTransactionStatus` sees both keys in `_signerPublicKeys`, promotes the transaction to `WAITING_FOR_EXECUTION`.
8. Chain service submits to Hedera → `INVALID_SIGNATURE` response → transaction status set to `FAILED`.
9. The transaction is permanently destroyed; User A's funds/operation are lost.

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L421-437)
```typescript
  private async updateStatusesAndNotify(
    transactionsToProcess: Array<{ id: number; transaction: Transaction }>
  ) {
    if (transactionsToProcess.length === 0) return;

    // Process statuses in bulk
    let statusMap: Map<number, TransactionStatus>;
    try {
      statusMap = await processTransactionStatus(
        this.txRepo,
        this.transactionSignatureService,
        transactionsToProcess.map(t => t.transaction)
      );
    } catch (err) {
      console.error('Bulk status processing failed:', err);
      statusMap = new Map();
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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L132-146)
```typescript
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    const signatureKey = await transactionSignatureService.computeSignatureKey(transaction);
    const isAbleToSign = hasValidSignatureKey(
      [...sdkTransaction._signerPublicKeys],
      signatureKey
    );

    let newStatus = TransactionStatus.WAITING_FOR_SIGNATURES;

    if (isAbleToSign) {
      const collatedTx = await smartCollate(transaction, signatureKey);
      if (collatedTx !== null) {
        newStatus = TransactionStatus.WAITING_FOR_EXECUTION;
      }
    }
```

**File:** back-end/libs/common/src/utils/sdk/key.ts (L31-46)
```typescript
export const hasValidSignatureKey = (publicKeys: string[], key: Key) => {
  if (key instanceof KeyList) {
    const keys = key.toArray();
    let currentThreshold = 0;

    keys.forEach(key => {
      if (hasValidSignatureKey(publicKeys, key)) {
        currentThreshold++;
      }
    });

    return currentThreshold >= (key.threshold || keys.length);
  } else if (key instanceof PublicKey) {
    return publicKeys.includes(key.toStringRaw());
  } else throw new Error(`Invalid key type`);
};
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L204-222)
```typescript
  private async getValidatedSDKTransaction(
    transaction: Transaction,
  ): Promise<SDKTransaction> {
    /* Throws an error if the transaction is not found or in incorrect state */
    if (!transaction) throw new Error('Transaction not found');

    await this.validateTransactionStatus(transaction);

    /* Gets the SDK transaction from the transaction body */
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    /* Gets the signature key */
    const signatureKey = await this.transactionSignatureService.computeSignatureKey(transaction);

    /* Checks if the transaction has valid signatureKey */
    if (!hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey))
      throw new Error('Transaction has invalid signature.');

    return sdkTransaction;
```
