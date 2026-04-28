Now I have all the information needed. Let me verify the `decode` function behavior and the SECURITY.md.

Audit Report

## Title
Missing Cryptographic Signature Validity Check in `uploadSignatureMaps` Allows Malicious Signer to Corrupt Transaction State

## Summary
The `POST /transactions/:transactionId/signers` endpoint (`SignersService.uploadSignatureMaps`) accepts and persists signature maps without performing any cryptographic verification of the submitted signature bytes. The only guard — the `IsSignatureMap` decorator — rejects only zero-length decoded signatures. Any non-empty hex-encoded byte sequence (including cryptographically invalid bytes) passes this check, is added to the stored transaction via `sdkTransaction.addSignature()`, and is committed to the database. The parallel path `POST /transactions/signatures/import` (`TransactionsService.importSignatures`) correctly calls `validateSignature` before accepting any signature. The inconsistency between the two paths is the root cause.

## Finding Description

**Path 1 — `POST /transactions/signatures/import` (`TransactionsService.importSignatures`):**

`importSignatures` calls `validateSignature` before adding any signature: [1](#0-0) 

`validateSignature` calls `publicKey.verify(bodyBytes, signature)` for every entry in the map and throws on failure — a proper cryptographic check: [2](#0-1) 

**Path 2 — `POST /transactions/:transactionId/signers` (`SignersService.uploadSignatureMaps`):**

`uploadSignatureMaps` delegates to `validateAndProcessSignatures`, which calls `processTransactionSignatures`. That function iterates the map and calls `sdkTransaction.addSignature(publicKey, map)` with **no cryptographic verification** of the signature bytes: [3](#0-2) 

The only upstream guard is the `IsSignatureMap` decorator, which rejects a signature only if its decoded byte length is exactly zero: [4](#0-3) 

The `decode` function is a plain hex decoder: [5](#0-4) 

Any non-empty hex string — including `"0x" + "00".repeat(64)` (64 zero bytes), 63 bytes of garbage, or any other invalid-but-non-empty byte sequence — passes this check and is accepted into the `SignatureMap`.

After `addSignature`, the code compares resulting transaction bytes to the original to detect whether anything changed (`isSameBytes`). If the Hedera SDK's `addSignature` writes the invalid bytes into the transaction (which it does, as it performs no cryptographic validation — that is the network's responsibility), `isSameBytes` is `false` and the corrupted bytes are committed: [6](#0-5) 

A `TransactionSigner` record is also inserted, marking the user's key as having signed: [7](#0-6) 

The existing e2e test for invalid signatures (`'invalid-signature'`) only catches the zero-length case because Node.js's `Buffer.from('invalid-signature', 'hex')` returns an empty buffer (stops at the first non-hex character `'i'`), triggering the `length === 0` guard. It does **not** cover a valid-format but cryptographically invalid hex string: [8](#0-7) 

## Impact Explanation
A malicious signer submits an invalid signature via `POST /transactions/:transactionId/signers`. The transaction's stored bytes are overwritten with the corrupted signature. If the signing threshold is subsequently met by other legitimate signers, the transaction advances to `WAITING_FOR_EXECUTION`. The chain service submits it to Hedera, which rejects it with `INVALID_SIGNATURE`. If the transaction's `validStart` window expires before anyone detects and corrects the state, the transaction is permanently unexecutable. For high-value or time-sensitive transactions (e.g., `NodeCreateTransaction`, `FileUpdateTransaction` for network governance files), this constitutes permanent, unrecoverable loss of the transaction's intended effect.

## Likelihood Explanation
The attacker only needs to be an authenticated user with a registered key that is listed as a signer on the target transaction — a normal, non-privileged role. No admin access, no leaked credentials, and no special tooling are required. The attack is a single crafted HTTP POST request. The `IsSignatureMap` decorator's `length === 0` guard is trivially bypassed by supplying any non-empty hex string (e.g., `"0x" + "00".repeat(64)`).

## Recommendation
Add a `validateSignature` call inside `processTransactionSignatures` in `signers.service.ts`, mirroring the pattern already used in `importSignatures`:

```ts
// Before calling addSignature, verify cryptographic validity
const { data: publicKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(null, sdkTransaction, map),
);
if (error) throw new Error(ErrorCodes.ISNMPN);
```

This ensures both signature-upload paths enforce the same cryptographic guarantee before mutating stored transaction bytes. [9](#0-8) [10](#0-9) 

## Proof of Concept

1. Authenticate as a user with a registered key that is a required signer on a target transaction.
2. Obtain the frozen transaction bytes and construct a valid `SignatureMap` structure (correct node account ID, transaction ID, and public key), but substitute the signature value with a valid-format but cryptographically invalid hex string, e.g.:
   ```
   "0x" + "00".repeat(64)   // 64 zero bytes — passes length check, fails crypto
   ```
3. POST to `POST /transactions/:id/signers`:
   ```json
   {
     "signatureMap": {
       "0.0.3": {
         "0.0.2159149@1730378704.000000000": {
           "<your-public-key-DER>": "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         }
       }
     }
   }
   ```
4. The `IsSignatureMap` decorator decodes the hex to 64 bytes (length > 0) — passes.
5. `processTransactionSignatures` calls `sdkTransaction.addSignature(publicKey, map)` — no crypto check — invalid bytes are written into the transaction.
6. `isSameBytes` is `false`; corrupted `transactionBytes` are committed to the database.
7. A `TransactionSigner` record is inserted for the attacker's key.
8. When the threshold is met, the transaction is submitted to Hedera and rejected with `INVALID_SIGNATURE`. [11](#0-10) [12](#0-11)

### Citations

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

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L235-241)
```typescript
          const signatureValid = publicKey.verify(bodyBytes, signature);

          if (signatureValid) {
            signerPublicKeys.push(publicKey);
          } else {
            throw new Error('Invalid signature');
          }
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

**File:** back-end/libs/common/src/decorators/is-signature-map.decorator.ts (L49-59)
```typescript
            const decodedSignature = new Uint8Array(decode(signature));

            if (decodedSignature.length === 0) {
              throw new BadRequestException(ErrorCodes.ISNMP);
            }

            signatureMap.addSignature(
              AccountId.fromString(nodeAccountId),
              TransactionId.fromString(transactionId),
              PublicKey.fromString(publicKey),
              decodedSignature,
```

**File:** back-end/libs/common/src/utils/buffer.ts (L4-5)
```typescript
export const decode = (hexString: string): Buffer =>
  Buffer.from(hexString.startsWith('0x') ? hexString.slice(2) : hexString, 'hex');
```

**File:** back-end/apps/api/test/spec/transaction-signers.e2e-spec.ts (L334-351)
```typescript
      formattedSignatureMap[nodeAccountIds[0]][transactionIds[0]][publicKeys[0]] =
        'invalid-signature';

      const { status, body } = await endpoint.post(
        {
          signatureMap: formattedSignatureMap,
        },
        `${createTxResponse.body.id}/signers`,
        userAuthToken,
      );

      expect(status).toBe(400);
      expect(body).toEqual(
        expect.objectContaining({
          statusCode: 400,
          code: ErrorCodes.ISNMP,
        }),
      );
```
