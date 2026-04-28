All code references have been verified against the actual codebase. The vulnerability is real and all claims check out.

---

Audit Report

## Title
Missing Cryptographic Signature Verification in `uploadSignatureMaps` Allows Submission of Invalid Signatures to Advance Transaction State

## Summary
The `uploadSignatureMaps` endpoint in `signers.service.ts` verifies that submitted public keys belong to the authenticated user but never cryptographically verifies that the signature bytes are valid for the transaction body. The parallel `importSignatures` endpoint in `transactions.service.ts` explicitly calls `validateSignature` — which performs a real `publicKey.verify()` check — before accepting signatures. An authenticated required-signer can submit their own public key paired with arbitrary/invalid signature bytes, get recorded as having signed, corrupt the persisted transaction bytes, and potentially advance the transaction to `WAITING_FOR_EXECUTION`, causing it to fail permanently at the Hedera network.

## Finding Description

**Root cause — missing `validateSignature` call in `processTransactionSignatures`:**

In `signers.service.ts`, `processTransactionSignatures` (lines 217–267) iterates over the submitted `SignatureMap`, checks that each public key belongs to the authenticated user via `userKeyMap` lookup, and then unconditionally calls `sdkTransaction.addSignature(publicKey, map)`:

```typescript
let userKey = userKeyMap.get(raw);
if (!userKey) {
  userKey = userKeyMap.get(publicKey.toStringDer());
}
if (!userKey) throw new Error(ErrorCodes.PNY);

// Only add the signature once per unique key
sdkTransaction = sdkTransaction.addSignature(publicKey, map);
```

There is no call to `validateSignature` or any equivalent cryptographic check on the signature bytes before they are added to the transaction. [1](#0-0) 

**`validateSignature` performs real cryptographic verification:**

The `validateSignature` utility at `back-end/libs/common/src/utils/sdk/transaction.ts` (lines 213–248) explicitly calls `publicKey.verify(bodyBytes, signature)` and throws `'Invalid signature'` if it returns false. This is a genuine cryptographic check, not a structural one. [2](#0-1) 

**Contrast with `importSignatures`:**

The `importSignatures` method in `transactions.service.ts` (lines 545–553) explicitly validates the signature bytes before calling `addSignature`:

```typescript
const { data: publicKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(this, sdkTransaction, map),
);
if (error) throw new BadRequestException(ErrorCodes.ISNMPN);

for (const publicKey of publicKeys) {
  sdkTransaction.addSignature(publicKey, map);
}
``` [3](#0-2) 

The existence of this explicit `validateSignature` call confirms that `addSignature` in the Hedera SDK does **not** perform cryptographic verification internally. The `uploadSignatureMaps` path is therefore missing this guard entirely.

**`processTransactionStatus` uses `_signerPublicKeys` populated by `addSignature`:**

`processTransactionStatus` in `back-end/libs/common/src/utils/transaction/index.ts` (lines 132–137) deserializes the stored transaction bytes and reads `sdkTransaction._signerPublicKeys` to determine if the threshold is met. Since `addSignature` populates `_signerPublicKeys` even with invalid bytes, the threshold check passes. [4](#0-3) 

**Corrupted bytes are persisted:**

In `persistSignatureChanges` (lines 296–298), if `isSameBytes` is `false` (which it will be when invalid bytes are added), the corrupted `transactionBytes` are written to the database. [5](#0-4) 

**`loadTransactionData` fetches any transaction by ID without user relationship check:**

`loadTransactionData` (lines 131–133) fetches transactions by ID with no ownership or relationship check. The only guard is the subsequent `userKeyMap` check, which requires the submitted public key to belong to the authenticated user. [6](#0-5) 

**Endpoint access control:**

The `SignersController` is protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. No ownership or role check is applied at the controller level. [7](#0-6) 

## Impact Explanation

- **Corrupted transaction bytes persisted**: Invalid signature bytes are written to the database, permanently corrupting the transaction's serialized form.
- **Direct loss of funds**: If the transaction advances to `WAITING_FOR_EXECUTION` and is submitted to the Hedera network, the network rejects it due to the invalid signature. The fee payer's HBAR is consumed and non-refundable.
- **Permanent transaction destruction**: Once submitted and failed, the transaction is marked `FAILED` and cannot be re-executed. High-value operations (`NodeUpdateTransaction`, `AccountUpdateTransaction`, treasury transfers) are permanently lost.
- **Integrity failure in multi-sig workflow**: The attacker is recorded as a `TransactionSigner`, suppressing further signing reminders and deceiving other participants into believing the transaction is legitimately signed. [8](#0-7) 

## Likelihood Explanation

- **Attacker preconditions**: A registered, authenticated user account whose public key is a required signer for the target transaction. This is a realistic scenario for a malicious insider or a compromised account.
- **No special privileges required**: Standard JWT authentication is sufficient. The endpoint is protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`.
- **Ease of exploitation**: Constructing a `SignatureMap` with a valid public key and invalid/garbage signature bytes is trivial using the Hedera SDK. [9](#0-8) 

## Recommendation

Add a `validateSignature` call in `processTransactionSignatures` before calling `sdkTransaction.addSignature`, mirroring the pattern already used in `importSignatures`:

```typescript
// In processTransactionSignatures, before addSignature:
const { data: validPublicKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(null, sdkTransaction, map),
);
if (error) throw new Error(ErrorCodes.ISNMPN);

// Then only call addSignature for validated keys
sdkTransaction = sdkTransaction.addSignature(publicKey, map);
```

This ensures that only cryptographically valid signatures are accepted, consistent with the behavior of `importSignatures`. [10](#0-9) [2](#0-1) 

## Proof of Concept

1. Register as a user and add a public key `K` to your account.
2. Obtain the internal transaction ID of a transaction for which `K` is a required signer.
3. Construct a `SignatureMap` containing `K` as the public key but with 64 bytes of `0xFF` as the signature value (garbage bytes).
4. Call `POST /transactions/:transactionId/signers` with this `SignatureMap` using a valid JWT.
5. Observe that:
   - The `userKeyMap` check passes (key belongs to the user).
   - `addSignature` is called without `validateSignature`.
   - `isSameBytes` is `false` (bytes changed due to garbage signature being embedded).
   - The corrupted `transactionBytes` are persisted to the database.
   - A `TransactionSigner` record is inserted for the attacker's key.
   - `processTransactionStatus` reads `_signerPublicKeys` (which now includes `K`) and, if the threshold is met, advances the transaction to `WAITING_FOR_EXECUTION`.
6. The chain service submits the transaction; the Hedera network rejects it with `INVALID_SIGNATURE`. The transaction is marked `FAILED` permanently and the fee payer's HBAR is burned. [11](#0-10) [12](#0-11)

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L131-133)
```typescript
    const transactions = await this.dataSource.manager.find(Transaction, {
      where: { id: In(transactionIds) },
    });
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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L296-298)
```typescript
      if (!isSameBytes) {
        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
        transactionsToUpdate.push({ id, transactionBytes: transaction.transactionBytes });
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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L129-146)
```typescript
  for (const transaction of transactions) {
    if (!transaction) continue;

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

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L39-39)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
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
