### Title
Signature Bytes Not Cryptographically Verified in `uploadSignatureMaps()` / `processTransactionSignatures()`

### Summary
The `SignersService.uploadSignatureMaps()` path accepts a `SignatureMap` from an authenticated user and records the submitting user as a valid signer without explicitly verifying that the signature bytes in the map are a valid cryptographic signature over the transaction body. Other signing paths in the same codebase (`importSignatures` and `approveTransaction`) do perform explicit signature verification, making this a clear inconsistency and an exploitable integrity gap.

### Finding Description

**Root cause — missing explicit signature verification in the signers upload path**

In `signers.service.ts`, `processTransactionSignatures()` iterates over the submitted `SignatureMap`, checks that each public key belongs to the authenticated user via `userKeyMap`, and then calls `sdkTransaction.addSignature(publicKey, map)`: [1](#0-0) 

The only guard is that the public key must exist in `userKeyMap` (built from `user.keys`): [2](#0-1) 

There is **no call to `validateSignature`** or any equivalent cryptographic check that the signature bytes in the map actually sign the transaction body.

**Contrast with other paths that do verify**

`transactions.service.ts` — `importSignatures()` explicitly calls `validateSignature` before accepting any signature: [3](#0-2) 

`approvers.service.ts` — `approveTransaction()` explicitly calls `verifyTransactionBodyWithoutNodeAccountIdSignature`: [4](#0-3) 

`transactions.service.ts` — `validateAndPrepareTransaction()` calls `publicKey.verify()` on the creator's signature: [5](#0-4) 

The `uploadSignatureMaps` path is the only signing path that skips this step.

**Exploit flow**

1. Attacker registers as a normal authenticated user and registers a valid public key with the system.
2. Attacker identifies a target transaction for which their key is a required signer.
3. Attacker calls `POST /transactions/:transactionId/signers` with a `SignatureMap` that contains their legitimate public key but **garbage/zeroed signature bytes**.
4. `processTransactionSignatures` confirms the public key belongs to the user (`userKeyMap` lookup passes) and calls `sdkTransaction.addSignature(publicKey, map)` — no cryptographic check on the bytes.
5. A `TransactionSigner` record is inserted for the attacker's key, marking them as having signed.
6. `processTransactionStatus` is called; if the attacker's key was the last required signer, the transaction status advances to `WAITING_FOR_EXECUTION`.
7. The chain service submits the transaction to the Hedera network. The network rejects it because the signature is cryptographically invalid.
8. The transaction fails permanently once its `validStart` window expires. [6](#0-5) 

### Impact Explanation

A malicious authenticated user who is a required signer on a transaction can submit a structurally valid but cryptographically invalid signature. The system records them as having signed, potentially advancing the transaction to execution. The Hedera network then rejects the transaction, causing:

- **Permanent transaction failure**: once the valid-start window closes, the transaction cannot be re-submitted.
- **Integrity violation**: the system's internal state (signer records, transaction status) diverges from the actual cryptographic state of the transaction.
- **Denial of service against co-signers**: other legitimate signers who contributed valid signatures have their work wasted with no recourse.

### Likelihood Explanation

The attacker only needs to be a registered, authenticated user who is listed as a required signer on any transaction. This is a normal, reachable role in the Organization Mode workflow. No privileged access, leaked secrets, or admin keys are required. The endpoint `POST /transactions/:transactionId/signers` is protected only by JWT authentication and `VerifiedUserGuard`. [7](#0-6) 

### Recommendation

Add explicit signature verification inside `processTransactionSignatures()` before calling `addSignature`, mirroring the pattern already used in `importSignatures`:

```typescript
// In processTransactionSignatures(), after resolving userKey:
const { data: validPublicKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(null, sdkTransaction, map),
);
if (error) throw new Error(ErrorCodes.ISNMPN);
```

Alternatively, call `verifyTransactionBodyWithoutNodeAccountIdSignature` for each signature entry, consistent with the approver path.

### Proof of Concept

1. Register user A and user B in the system. User A creates a transaction requiring both A's and B's keys.
2. User B authenticates and calls:
   ```
   POST /transactions/<id>/signers
   Body: [{ id: <txId>, signatureMap: { <nodeId>: { <txId>: { <userB_pubkey>: <32 zero bytes> } } } }]
   ```
3. The server responds with HTTP 201 and a `TransactionSigner` record for user B.
4. If user A has already signed, `processTransactionStatus` advances the transaction to `WAITING_FOR_EXECUTION`.
5. The chain service submits the transaction; the Hedera network returns `INVALID_SIGNATURE`.
6. The transaction is marked `FAILED` — permanently unrecoverable. [8](#0-7)

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L269-312)
```typescript
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

      transactionsToProcess.push({ id, transaction });
      notificationsToUpdate.push({ userId: user.id, transactionId: transaction.id });
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L546-549)
```typescript
        const { data: publicKeys, error } = safe<PublicKey[]>(
          validateSignature.bind(this, sdkTransaction, map),
        );
        if (error) throw new BadRequestException(ErrorCodes.ISNMPN);
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L910-913)
```typescript
    const validSignature = publicKey.verify(dto.transactionBytes, dto.signature);
    if (!validSignature) {
      throw new BadRequestException(ErrorCodes.SNMP);
    }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L592-596)
```typescript
    /* Verify the signature matches the transaction */
    if (
      !verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTransaction, dto.signature, publicKey)
    )
      throw new BadRequestException(ErrorCodes.SNMP);
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
