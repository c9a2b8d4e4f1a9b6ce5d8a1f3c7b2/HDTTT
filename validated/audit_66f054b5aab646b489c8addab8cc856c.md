All three code locations were verified against the actual source. The finding is accurate.

---

Audit Report

## Title
`processTransactionSignatures` Accepts Cryptographically Unverified Signatures, Enabling Signer Record Forgery and Transaction Corruption

## Summary
`processTransactionSignatures` in `signers.service.ts` calls `sdkTransaction.addSignature()` without first invoking `validateSignature`. The parallel code path `importSignatures` in `transactions.service.ts` explicitly calls `validateSignature` before `addSignature`, confirming that `addSignature` itself performs no cryptographic verification. An authenticated user with a registered `UserKey` can submit arbitrary garbage bytes as a signature, be permanently recorded as a legitimate signer, and — depending on threshold state — cause the transaction to advance to execution and fail irreversibly on-chain.

## Finding Description

**Root cause:** `processTransactionSignatures` (lines 217–267 of `signers.service.ts`) iterates over the submitted `SignatureMap`, verifies only that each public key belongs to the authenticated user (lines 244–248), then unconditionally calls `sdkTransaction.addSignature(publicKey, map)` at line 251 with no cryptographic check on the signature bytes. [1](#0-0) 

By contrast, `importSignatures` in `transactions.service.ts` (lines 546–553) wraps `validateSignature` in a `safe()` call and throws `ErrorCodes.ISNMPN` on failure before ever reaching `addSignature`: [2](#0-1) 

`validateSignature` (lines 213–248 of `transaction.ts`) is the only location in the codebase that calls `publicKey.verify(bodyBytes, signature)` — the actual cryptographic check. Its absence in `processTransactionSignatures` means signature bytes are never verified against the transaction body or the claimed public key. [3](#0-2) 

**Secondary bypass — `isSameBytes` does not protect signer recording:**
Even if `addSignature` silently drops garbage bytes (leaving `isSameBytes = true`), the attacker's key is still pushed into `userKeys` at line 255 whenever the key is not already in `existingSignerIds`. In `persistSignatureChanges`, the skip guard is:

```
if (isSameBytes && userKeys.length === 0) continue;
``` [4](#0-3) 

If `userKeys.length > 0` (attacker's key is new), execution continues and a `TransactionSigner` row is inserted regardless of whether any bytes changed. [5](#0-4) 

## Impact Explanation

1. **Signer record forgery / audit trail corruption:** The attacker is permanently recorded in the `TransactionSigner` table as having signed the transaction, which is false. This corrupts the approval workflow and audit trail.
2. **Multi-sig threshold bypass:** In a multi-sig scenario, the fraudulent signer record can satisfy a signing threshold, causing `processTransactionStatus` to advance the transaction to `WAITING_FOR_EXECUTION`.
3. **Permanent transaction failure on-chain:** If the transaction is submitted to the Hedera network with an invalid signature embedded in `transactionBytes`, the network returns `INVALID_SIGNATURE` and the transaction is permanently marked `FAILED`. Legitimate signers cannot recover it.

## Likelihood Explanation

Any authenticated user who has at least one registered `UserKey` and access to a transaction (as approver, observer, or creator) can trigger this. No privileged access is required. The attacker only needs their own registered public key and the target transaction ID. The `POST /transactions/:transactionId/signers` endpoint is a standard, documented API endpoint protected only by JWT authentication. [6](#0-5) 

## Recommendation

Add a `validateSignature` call inside `processTransactionSignatures` before `addSignature`, mirroring the pattern already used in `importSignatures`:

```typescript
// In processTransactionSignatures, before addSignature:
const { data: validKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(null, sdkTransaction, map),
);
if (error) throw new Error(ErrorCodes.ISNMPN);
```

This ensures `publicKey.verify(bodyBytes, signature)` is called for every submitted signature before it is accepted or persisted. [7](#0-6) 

## Proof of Concept

1. Authenticate as a normal user with a registered `UserKey` (public key `PK`).
2. Obtain a valid transaction ID `T` for a transaction in `WAITING_FOR_SIGNATURES` status.
3. Construct a `SignatureMap` where the signature bytes for `PK` are 64 zero bytes (or any arbitrary garbage).
4. POST the payload to `POST /transactions/T/signers`.
5. `processTransactionSignatures` finds `PK` in `userKeyMap` (line 244), passes the ownership check, calls `sdkTransaction.addSignature(publicKey, map)` with the garbage bytes (line 251), and returns `userKeys` containing the attacker's key.
6. `persistSignatureChanges` inserts a `TransactionSigner` row for the attacker (lines 302–309) and, if bytes changed, updates `transactionBytes` with the corrupted signature (lines 296–298).
7. `updateStatusesAndNotify` calls `processTransactionStatus`; if the attacker's key was the last required signer, the transaction advances to `WAITING_FOR_EXECUTION`.
8. The chain service submits the transaction to Hedera; the network rejects it with `INVALID_SIGNATURE`; the transaction is permanently marked `FAILED`. [8](#0-7)

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L99-124)
```typescript
  async uploadSignatureMaps(
    dto: UploadSignatureMapDto[],
    user: User,
  ): Promise<{ signers: TransactionSigner[]; notificationReceiverIds: number[] }> {
    // Load all necessary data
    const { transactionMap, signersByTransaction } = await this.loadTransactionData(dto);

    // Validate and process signatures
    const validationResults = await this.validateAndProcessSignatures(
      dto,
      user,
      transactionMap,
      signersByTransaction
    );

    // Persist changes to database
    const { transactionsToProcess, signers, notificationsToDismiss } = await this.persistSignatureChanges(validationResults, user);

    // Update transaction statuses and emit notifications
    await this.updateStatusesAndNotify(transactionsToProcess);

    return {
      signers: Array.from(signers),
      notificationReceiverIds: notificationsToDismiss,
    };
  }
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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L293-293)
```typescript
      if (isSameBytes && userKeys.length === 0) continue;
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
