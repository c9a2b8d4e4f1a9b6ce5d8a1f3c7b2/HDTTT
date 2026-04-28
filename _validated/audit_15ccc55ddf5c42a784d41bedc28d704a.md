Audit Report

## Title
Missing Cryptographic Signature Verification in `uploadSignatureMaps` Allows Invalid Signatures to Advance Transaction State

## Summary

The `uploadSignatureMaps` endpoint (`POST /transactions/:id/signers`) in `SignersService` accepts and persists `SignatureMap` submissions without performing any cryptographic verification of the signature bytes. A registered user can submit their legitimate public key paired with arbitrary/garbage signature bytes. The system will accept the submission, overwrite `transactionBytes` with the corrupted data, record the user as a signer, and potentially advance the transaction to `WAITING_FOR_EXECUTION`. When the chain service later attempts to execute the transaction on the Hedera network, it will fail because the signature is cryptographically invalid.

## Finding Description

There are two distinct code paths for submitting signatures:

**Path 1 — `importSignatures` (correct, in `transactions.service.ts`):**

`importSignatures` calls `validateSignature` before accepting any signature:

```typescript
const { data: publicKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(this, sdkTransaction, map),
);
if (error) throw new BadRequestException(ErrorCodes.ISNMPN);
``` [1](#0-0) 

`validateSignature` in `transaction.ts` performs actual cryptographic verification via `publicKey.verify(bodyBytes, signature)`, throwing `'Invalid signature'` on failure: [2](#0-1) 

**Path 2 — `uploadSignatureMaps` (vulnerable, in `signers.service.ts`):**

`processTransactionSignatures` only checks that the public key belongs to the authenticated user, then immediately calls `addSignature` with no cryptographic check:

```typescript
let userKey = userKeyMap.get(raw);
if (!userKey) {
  userKey = userKeyMap.get(publicKey.toStringDer());
}
if (!userKey) throw new Error(ErrorCodes.PNY);

// Only add the signature once per unique key
sdkTransaction = sdkTransaction.addSignature(publicKey, map);
``` [3](#0-2) 

The Hedera SDK's `addSignature` unconditionally adds the public key to `_signerPublicKeys` and stores the raw bytes without any verification.

After this, `processTransactionStatus` evaluates readiness using `hasValidSignatureKey`: [4](#0-3) 

`hasValidSignatureKey` only checks whether the required public key strings are present in `_signerPublicKeys` — it does not verify the cryptographic validity of the associated signature bytes: [5](#0-4) 

If the threshold is satisfied, `processTransactionStatus` promotes the transaction to `WAITING_FOR_EXECUTION`: [6](#0-5) 

At execution time, `getValidatedSDKTransaction` in `execute.service.ts` again only checks key presence via `hasValidSignatureKey` before submitting to the Hedera network — it does not re-verify signature bytes: [7](#0-6) 

## Impact Explanation

A registered user can submit a `SignatureMap` with their legitimate public key but with garbage/forged signature bytes via `POST /transactions/:id/signers`. The system will:

1. Accept the submission — `processTransactionSignatures` only validates key ownership, not signature validity.
2. Overwrite `transaction.transactionBytes` with the corrupted signature embedded via `persistSignatureChanges`.
3. Record the user as a signer in `TransactionSigner`.
4. Potentially advance the transaction to `WAITING_FOR_EXECUTION` if the key threshold is met.
5. Cause the transaction to fail on the Hedera network at execution time with an invalid signature error.

The corrupted `transactionBytes` are persisted to the database, permanently blocking legitimate execution even if other signers later provide valid signatures, since the corrupted bytes are what gets submitted. [8](#0-7) 

## Likelihood Explanation

The attack requires only an authenticated user account with at least one registered `UserKey` that is listed as a required signer on the target transaction. No elevated privileges are needed. The endpoint `POST /transactions/:id/signers` is accessible to any verified user. The attack is trivial to execute: construct a `SignatureMap` with the correct public key but random bytes as the signature value. [9](#0-8) 

## Recommendation

In `processTransactionSignatures` within `signers.service.ts`, add a call to `validateSignature` before calling `addSignature`, mirroring the pattern already used in `importSignatures`:

```typescript
// Validate signatures cryptographically before adding
const { data: validPublicKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(this, sdkTransaction, map),
);
if (error) throw new Error(ErrorCodes.ISNMPN);
```

Only proceed with `addSignature` for keys returned by `validateSignature`. This ensures the `uploadSignatureMaps` path has the same cryptographic guarantee as `importSignatures`. [10](#0-9) 

## Proof of Concept

1. Authenticate as a user with a registered `UserKey` (public key `PK`) that is a required signer on transaction `TX_ID`.
2. Construct a `SignatureMap` containing `PK` mapped to 64 bytes of random garbage as the signature value.
3. Submit `POST /transactions/TX_ID/signers` with the malformed `SignatureMap`.
4. Observe: the server returns HTTP 201, a `TransactionSigner` record is created, and `transaction.transactionBytes` is overwritten with the garbage signature embedded.
5. If `PK` was the last required signer, observe the transaction status advance to `WAITING_FOR_EXECUTION`.
6. When the chain service executes the transaction, it will fail on the Hedera network with an `INVALID_SIGNATURE` error, and the transaction will be marked `FAILED` with the corrupted bytes permanently stored. [11](#0-10)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L546-549)
```typescript
        const { data: publicKeys, error } = safe<PublicKey[]>(
          validateSignature.bind(this, sdkTransaction, map),
        );
        if (error) throw new BadRequestException(ErrorCodes.ISNMPN);
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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L134-137)
```typescript
    const isAbleToSign = hasValidSignatureKey(
      [...sdkTransaction._signerPublicKeys],
      signatureKey
    );
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L141-145)
```typescript
    if (isAbleToSign) {
      const collatedTx = await smartCollate(transaction, signatureKey);
      if (collatedTx !== null) {
        newStatus = TransactionStatus.WAITING_FOR_EXECUTION;
      }
```

**File:** back-end/libs/common/src/utils/sdk/key.ts (L43-44)
```typescript
  } else if (key instanceof PublicKey) {
    return publicKeys.includes(key.toStringRaw());
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L219-220)
```typescript
    if (!hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey))
      throw new Error('Transaction has invalid signature.');
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
