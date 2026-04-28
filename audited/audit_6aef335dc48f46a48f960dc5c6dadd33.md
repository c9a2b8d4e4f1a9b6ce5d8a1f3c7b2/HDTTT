I have enough context to produce a complete analysis. Let me synthesize the findings.

The external report's vulnerability class is: **signature verification bypass — the system checks that a signer identity is valid but never verifies that the cryptographic signature bytes are actually valid for that identity.** In the EVM context this was `ecrecover` returning `address(0)`; the analog here is the `uploadSignatureMaps` path accepting any bytes as a "signature" without cryptographic verification.

---

### Title
Missing Cryptographic Signature Verification in `processTransactionSignatures` Allows Authenticated User to Falsely Register as a Transaction Signer

### Summary

`SignersService.processTransactionSignatures` verifies that the public key in a submitted `SignatureMap` belongs to the authenticated user, but never verifies that the accompanying signature bytes are cryptographically valid for that key. An authenticated user can submit a signature map containing their own registered public key paired with arbitrary/garbage bytes, and the system will accept it, persist them as a signer, and overwrite the stored transaction bytes with the invalid signature — corrupting the transaction and potentially causing it to fail on-chain when submitted.

### Finding Description

**Root cause — missing cryptographic verification in `processTransactionSignatures`:**

In `back-end/apps/api/src/transactions/signers/signers.service.ts` lines 234–258, the loop iterates over every `publicKey` in the submitted `SignatureMap`, checks that the key belongs to the authenticated user via `userKeyMap`, and then unconditionally calls `sdkTransaction.addSignature(publicKey, map)`:

```typescript
for (const publicKey of txMap.keys()) {
  const raw = publicKey.toStringRaw();
  if (processedRawKeys.has(raw)) continue;
  processedRawKeys.add(raw);

  let userKey = userKeyMap.get(raw);
  if (!userKey) userKey = userKeyMap.get(publicKey.toStringDer());
  if (!userKey) throw new Error(ErrorCodes.PNY);   // ← only ownership check

  sdkTransaction = sdkTransaction.addSignature(publicKey, map); // ← no validity check
  if (!existingSignerIds.has(userKey.id)) {
    userKeys.push(userKey);
  }
}
``` [1](#0-0) 

The Hedera SDK's `addSignature` does **not** verify the signature bytes cryptographically — it blindly appends whatever bytes are in the map to the transaction. There is no call to `PublicKey.verify()` or any equivalent before or after `addSignature`.

**Contrast with `importSignatures`**, which does perform cryptographic verification before accepting signatures:

```typescript
const { data: publicKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(this, sdkTransaction, map),
);
if (error) throw new BadRequestException(ErrorCodes.ISNMPN);
``` [2](#0-1) 

The `uploadSignatureMaps` path (exposed via `POST /transactions/:id/signers`) has no equivalent `validateSignature` call.

**Exploit flow:**

1. Attacker authenticates as a normal user and registers a public key `K` in the system.
2. Attacker constructs a `SignatureMap` containing key `K` paired with 64 bytes of garbage (e.g., all zeros).
3. Attacker POSTs this to `POST /transactions/<id>/signers`.
4. `processTransactionSignatures` finds `K` in `userKeyMap` → ownership check passes.
5. `addSignature(K, map)` appends the garbage bytes to the transaction → `isSameBytes` becomes `false`.
6. `userKeys` contains the attacker's key → they are inserted as a `TransactionSigner` in the DB.
7. The transaction's stored `transactionBytes` are overwritten with the corrupted bytes. [3](#0-2) [4](#0-3) 

### Impact Explanation

- **False signer accounting**: The system records the attacker as having signed the transaction. If the transaction requires a threshold of signers, this false entry can make the system believe the threshold is met when it is not.
- **Transaction byte corruption**: The stored `transactionBytes` are overwritten with a version containing an invalid signature. Any subsequent legitimate signer who downloads and re-signs the transaction will be working from corrupted bytes.
- **On-chain failure / DoS**: When the chain service submits the transaction to the Hedera network, the network will reject it due to the invalid signature, permanently failing the transaction. The transaction cannot be recovered because the stored bytes are already corrupted.
- **Integrity break**: The `TransactionSigner` table no longer accurately reflects who has actually signed, breaking the trust model of the multi-signature workflow.

### Likelihood Explanation

- **Preconditions**: The attacker only needs a valid JWT (authenticated user) and one registered public key — both are normal user-level capabilities with no privilege required.
- **Attack complexity**: Constructing a `SignatureMap` with a known public key and garbage signature bytes is trivial using the Hedera SDK or by crafting the protobuf directly.
- **No detection**: The system logs no error and returns a success response, so the attack is silent.
- **Reachable endpoint**: `POST /transactions/:id/signers` is a standard, documented API endpoint protected only by JWT authentication. [5](#0-4) 

### Recommendation

Add cryptographic signature verification inside `processTransactionSignatures`, mirroring what `importSignatures` already does via `validateSignature`. Before calling `addSignature`, verify each signature byte array against the transaction body using `PublicKey.verify()`:

```typescript
// After resolving userKey, before addSignature:
const sigBytes = txMap.get(publicKey);
const bodyBytes = getTransactionBodyBytes(sdkTransaction);
if (!publicKey.verify(bodyBytes, sigBytes)) {
  throw new Error(ErrorCodes.ISNMPN); // invalid signature
}
sdkTransaction = sdkTransaction.addSignature(publicKey, map);
```

Alternatively, refactor `processTransactionSignatures` to call the existing `validateSignature` utility (already used in `importSignatures`) before accepting any signature map entry.

### Proof of Concept

1. Register as a user, obtain a JWT, and register an Ed25519 or ECDSA public key `K`.
2. Find a transaction in `WAITING_FOR_SIGNATURES` status.
3. Construct a `SignatureMap` with `K` → 64 zero bytes as the signature.
4. POST to `/transactions/<id>/signers` with the crafted map.
5. **Expected (vulnerable) result**: HTTP 201, the caller appears in `TransactionSigner` table, and `transaction.transactionBytes` is updated to include the garbage signature.
6. **Expected (correct) result**: HTTP 400 with `ISNMPN` error code, no DB changes.
7. Confirm corruption: fetch the transaction bytes and attempt to submit to the Hedera testnet — the network will reject with `INVALID_SIGNATURE`. [6](#0-5)

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L290-312)
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

      transactionsToProcess.push({ id, transaction });
      notificationsToUpdate.push({ userId: user.id, transactionId: transaction.id });
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
