### Title
Missing Cryptographic Signature Validation in `uploadSignatureMaps` Allows False Signer Registration and Forced Transaction Failure

### Summary
The `processTransactionSignatures` method in `SignersService` verifies that a submitted public key belongs to the authenticated user, but never cryptographically verifies that the accompanying signature bytes are a valid signature over the transaction body. A malicious registered user can submit arbitrary/invalid bytes as their signature, be recorded as a signer, and cause the transaction to permanently fail when submitted to the Hedera network. The `importSignatures` path in `TransactionsService` correctly calls `validateSignature` before accepting signatures, making this an inconsistency between two code paths handling the same operation.

### Finding Description

In `back-end/apps/api/src/transactions/signers/signers.service.ts`, the `processTransactionSignatures` method iterates over the submitted `SignatureMap`, checks that each public key belongs to the authenticated user via `userKeyMap`, then unconditionally calls `sdkTransaction.addSignature(publicKey, map)` and pushes the `userKey` into the `userKeys` array: [1](#0-0) 

The ownership check (`userKeyMap.get(raw)`) only confirms the key is registered to the user — it does not verify that the signature bytes in the map are a valid Ed25519/ECDSA signature over the transaction body.

After `processTransactionSignatures` returns, `persistSignatureChanges` uses the following guard: [2](#0-1) 

If the Hedera SDK's `addSignature` silently rejects invalid bytes (leaving `isSameBytes = true`), the condition `isSameBytes && userKeys.length === 0` is still **false** because `userKeys.length > 0`. The signer record is therefore inserted into the database even though no valid signature was added to the transaction bytes.

By contrast, the `importSignatures` path in `TransactionsService` explicitly validates signatures before accepting them: [3](#0-2) 

The `uploadSignatureMaps` path (POST `/transactions/:transactionId/signers`) has no equivalent check.

The entry point is the `SignersController`: [4](#0-3) 

The `IsSignatureMap` decorator validates structural format (account IDs, transaction IDs, non-empty byte arrays) but does not verify cryptographic correctness of the signature bytes: [5](#0-4) 

### Impact Explanation

A malicious required signer can submit a structurally valid `SignatureMap` containing their own registered public key paired with garbage signature bytes. The system records them as having signed the transaction. Once all required signers are recorded (including the attacker), the transaction advances to `WAITING_FOR_EXECUTION`. When the chain service submits the transaction to the Hedera network, the network rejects it due to the invalid/missing signature, placing the transaction in a permanent `FAILED` state. The fee payer's HBAR is consumed. The transaction cannot be re-executed. This converts a "stalled" transaction (which could be re-signed) into a permanently failed one, causing irreversible state corruption and financial loss for the fee payer.

### Likelihood Explanation

Any authenticated, verified user whose public key is a required signer for a transaction can trigger this. No privileged access is required beyond normal user registration and key upload. The attack requires only a single crafted HTTP POST to `/transactions/:transactionId/signers` with a valid JWT and a structurally valid but cryptographically invalid signature map. This is a realistic scenario in organizational multi-signature workflows where a malicious insider is a required signer.

### Recommendation

Add cryptographic signature verification in `processTransactionSignatures` before calling `addSignature` and before recording the user as a signer. A utility for this already exists in the codebase (`verifyTransactionBodyWithoutNodeAccountIdSignature` in `back-end/libs/common/src/utils/sdk/transaction.ts`): [6](#0-5) 

For each `(publicKey, signature)` pair in the submitted map, call this verification function before proceeding. Alternatively, adopt the same `validateSignature` pattern already used in `importSignatures`: [3](#0-2) 

### Proof of Concept

1. Register as a user and upload a public key `PK_A` (Ed25519 or ECDSA).
2. Obtain or create a transaction `T` that requires `PK_A` as a signer.
3. Send a POST to `/transactions/T_id/signers` with a valid JWT and the following body:
   ```json
   {
     "id": <T_id>,
     "signatureMap": {
       "0.0.3": {
         "<valid_transaction_id>": {
           "<PK_A_DER_encoded>": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
         }
       }
     }
   }
   ```
4. Observe HTTP 201 response — the server accepts the submission.
5. Query the `transaction_signer` table: a record for `PK_A` and `T_id` is present, recording the attacker as having signed.
6. Once all other required signers sign legitimately, the transaction advances to `WAITING_FOR_EXECUTION`.
7. The chain service submits the transaction to Hedera; the network rejects it due to the invalid signature.
8. The transaction transitions to `FAILED` state permanently; the fee payer's HBAR is consumed.

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L243-256)
```typescript
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
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L290-309)
```typescript
      // Skip if nothing to do - no signatures were added to the transaction
      // AND no new signers were inserted (the signature can be present on the transaction
      // if collated by an outside or 'offline' method)
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L545-549)
```typescript
        /* Validates the signatures */
        const { data: publicKeys, error } = safe<PublicKey[]>(
          validateSignature.bind(this, sdkTransaction, map),
        );
        if (error) throw new BadRequestException(ErrorCodes.ISNMPN);
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

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L266-284)
```typescript
export const verifyTransactionBodyWithoutNodeAccountIdSignature = (
  transaction: SDKTransaction,
  signature: string | Buffer,
  publicKey: string | PublicKey,
) => {
  const bodyBytes = getTransactionBodyBytes(transaction);

  /* Deserialize Public Key */
  publicKey = publicKey instanceof PublicKey ? publicKey : PublicKey.fromString(publicKey);

  /* Deserialize Signature */
  signature = typeof signature === 'string' ? decode(signature) : signature;

  try {
    return publicKey.verify(bodyBytes, signature);
  } catch (err) {
    console.log(err);
    return false;
  }
```
