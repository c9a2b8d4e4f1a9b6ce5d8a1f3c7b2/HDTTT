### Title
Missing Cryptographic Signature Verification in `uploadSignatureMaps` Allows Injection of Invalid Signatures, Causing Transaction Denial of Service

---

### Summary

The `uploadSignatureMaps` function in `signers.service.ts` accepts and persists signature bytes into a transaction's stored `transactionBytes` without cryptographically verifying that the submitted signatures are valid over the transaction body. This is a direct analog to the nucypher `set_policy` / `verify_from` vulnerability: one code path verifies signatures before committing state (`importSignatures`), while the other (`uploadSignatureMaps`) does not. An authenticated organization member with a registered public key can inject arbitrary/garbage signature bytes for their key, corrupting the stored transaction and causing it to fail when the chain service attempts to execute it on the Hedera network.

---

### Finding Description

There are two endpoints for submitting signatures to the backend:

**Path 1 — `POST /transactions/signatures/import` → `importSignatures`**

This path calls `validateSignature` before adding anything to the transaction:

```
const { data: publicKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(this, sdkTransaction, map),
);
if (error) throw new BadRequestException(ErrorCodes.ISNMPN);
``` [1](#0-0) 

**Path 2 — `POST /transactions/:transactionId/signers` → `uploadSignatureMaps` → `processTransactionSignatures`**

This path only checks that the public key belongs to the authenticated user, then immediately calls `addSignature` with no cryptographic verification of the signature bytes:

```typescript
let userKey = userKeyMap.get(raw);
if (!userKey) {
  userKey = userKeyMap.get(publicKey.toStringDer());
}
if (!userKey) throw new Error(ErrorCodes.PNY);

// Only add the signature once per unique key
sdkTransaction = sdkTransaction.addSignature(publicKey, map);
``` [2](#0-1) 

The Hedera SDK's `addSignature` method does not verify the signature cryptographically — it simply inserts the provided bytes into the signature map. Verification only occurs at the Hedera network node level when the transaction is submitted.

After `addSignature`, the corrupted bytes are compared against the original and, if different, are persisted to the database:

```typescript
const isSameBytes = Buffer.from(sdkTransaction.toBytes()).equals(
  transaction.transactionBytes
);
// ...
if (!isSameBytes) {
  transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
  transactionsToUpdate.push({ id, transactionBytes: transaction.transactionBytes });
}
``` [3](#0-2) 

The `IsSignatureMap` decorator only validates the structural format (valid account IDs, transaction IDs, non-empty byte arrays) — it does not verify that the signature bytes are a valid cryptographic signature over the transaction body: [4](#0-3) 

---

### Impact Explanation

An attacker who is an authenticated organization member with at least one registered public key can:

1. Call `POST /transactions/:transactionId/signers` with their valid public key but with garbage/invalid signature bytes.
2. The server accepts the request, calls `addSignature` with the invalid bytes, detects the bytes changed (`isSameBytes = false`), and persists the corrupted `transactionBytes` to the database.
3. A `TransactionSigner` record is also inserted, marking the attacker as having signed.
4. When the chain service later attempts to execute the transaction, the Hedera network rejects it because the stored signature is cryptographically invalid.
5. The transaction is permanently DoS'd — it cannot be re-signed with the correct signature because the signer record already exists and the corrupted bytes are stored.

This maps directly to the nucypher analog: state is committed to the database based on an unverified cryptographic claim, making the stored object permanently unusable.

---

### Likelihood Explanation

**Medium.** The attacker must be an authenticated organization member with a registered `UserKey`. This is not an unauthenticated attack. However, insider threats, compromised accounts, or malicious members of an organization are realistic adversaries in a multi-user transaction coordination system. No special administrative privileges are required — any signer-eligible user can exploit this.

---

### Recommendation

1. **Apply `validateSignature` in `processTransactionSignatures`** before calling `sdkTransaction.addSignature`, mirroring the pattern already used in `importSignatures`.
2. **Unify the two signature submission paths** to share a single verified signature-addition function, eliminating the inconsistency.
3. **Do not treat structural validity of a `SignatureMap` as cryptographic validity.** The `IsSignatureMap` decorator confirms format, not authenticity.

---

### Proof of Concept

```
POST /transactions/42/signers
Authorization: Bearer <valid_jwt_for_org_member_with_registered_key>
Content-Type: application/json

[{
  "id": 42,
  "signatureMap": {
    "0.0.3": {
      "0.0.1234@1700000000.000000000": {
        "<attacker_registered_public_key_DER>": "0xdeadbeefdeadbeef..."
      }
    }
  }
}]
```

**Expected (correct) behavior:** Server rejects with signature verification error.

**Actual behavior:** Server calls `sdkTransaction.addSignature(publicKey, map)` with the garbage bytes, detects `isSameBytes = false`, persists the corrupted `transactionBytes` to the `transaction` table, inserts a `TransactionSigner` record, and returns HTTP 201. The transaction will subsequently fail on-chain execution due to the invalid signature. [5](#0-4) [6](#0-5)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L546-549)
```typescript
        const { data: publicKeys, error } = safe<PublicKey[]>(
          validateSignature.bind(this, sdkTransaction, map),
        );
        if (error) throw new BadRequestException(ErrorCodes.ISNMPN);
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L217-298)
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

  private async persistSignatureChanges(
    validationResults: any[],
    user: User,
  ) {
    const signers = new Set<TransactionSigner>();
    let notificationsToDismiss: number[] = [];

    // Prepare batched operations
    const transactionsToUpdate: { id: number; transactionBytes: Buffer }[] = [];
    const notificationsToUpdate: { userId: number; transactionId: number }[] = [];
    const signersToInsert: { userId: number; transactionId: number; userKeyId: number }[] = [];
    const transactionsToProcess: { id: number; transaction: Transaction }[] = [];

    for (const result of validationResults) {
      if (result.error) {
        console.error(`[TX ${result.id}] Validation failed: ${result.error}`);
        continue;
      }

      const { id, transaction, sdkTransaction, userKeys, isSameBytes } = result;

      // Skip if nothing to do - no signatures were added to the transaction
      // AND no new signers were inserted (the signature can be present on the transaction
      // if collated by an outside or 'offline' method)
      if (isSameBytes && userKeys.length === 0) continue;

      // Collect updates
      if (!isSameBytes) {
        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
        transactionsToUpdate.push({ id, transactionBytes: transaction.transactionBytes });
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

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L100-119)
```typescript
  @Post()
  @HttpCode(201)
  async uploadSignatureMap(
    @Body() body: UploadSignatureMapDto | UploadSignatureMapDto[],
    @GetUser() user: User,
    @Query('includeNotifications') includeNotifications?: boolean,
  ): Promise<TransactionSigner[] | UploadSignatureMapResponseDto> {
    const transformedSignatureMaps = await transformAndValidateDto(UploadSignatureMapDto, body);

    const { signers, notificationReceiverIds } = await this.signaturesService.uploadSignatureMaps(
      transformedSignatureMaps,
      user,
    );

    if (includeNotifications) {
      return { signers, notificationReceiverIds };
    }

    return signers;
  }
```
