### Title
Missing Proof of Possession on Key Registration Combined with No Cryptographic Signature Verification in `uploadSignatureMaps` Enables Permanent Transaction Corruption

### Summary
Any authenticated user can register an arbitrary valid Hedera public key without proving ownership of the corresponding private key. The `uploadSignatureMaps` endpoint then accepts signature map submissions for any key the user has registered, without cryptographically verifying the signature bytes. A malicious user can register a victim account's public key (before the legitimate owner does), submit garbage bytes as a "signature," and permanently corrupt a transaction that requires that key — forcing it to fail on-chain and become unrecoverable.

### Finding Description

**Root Cause 1 — No proof of possession on key registration**

`uploadKey` in `user-keys.service.ts` accepts any syntactically valid Hedera public key with no challenge-response or signature proof: [1](#0-0) 

The only uniqueness guard is that a key already registered by *another* user is rejected: [2](#0-1) 

A key not yet in the system can be claimed by anyone. Because Hedera account public keys are broadcast on-chain, any attacker can look up a target account's public key and register it first.

**Root Cause 2 — No cryptographic signature verification in `uploadSignatureMaps`**

`processTransactionSignatures` in `signers.service.ts` only checks that the public key in the submitted signature map belongs to the authenticated user's registered keys, then blindly calls `addSignature`: [3](#0-2) 

`sdkTransaction.addSignature(publicKey, map)` does not verify the signature bytes cryptographically — it simply appends whatever bytes are in the map and adds the public key to `_signerPublicKeys`. There is no call to `publicKey.verify(bodyBytes, signature)` anywhere in this path.

**Contrast with `importSignatures`** — the parallel path in `transactions.service.ts` *does* call `validateSignature`, which performs `publicKey.verify(bodyBytes, signature)` for each entry: [4](#0-3) 

The `uploadSignatureMaps` path has no equivalent check.

**Exploit chain:**

1. Attacker (authenticated user) observes a pending transaction T that requires account `0.0.X`'s signature.
2. Account `0.0.X`'s public key is public on-chain. The legitimate user has not yet registered it in the tool.
3. Attacker calls `POST /user/keys` with `0.0.X`'s public key — accepted with no proof of possession.
4. Attacker calls `POST /transactions/{T.id}/signers` with a signature map containing `0.0.X`'s public key and arbitrary garbage bytes as the signature.
5. `processTransactionSignatures` finds the key in `userKeyMap`, calls `addSignature`, and records a `TransactionSigner` row for the attacker.
6. `_signerPublicKeys` now contains `0.0.X`'s key. `hasValidSignatureKey` in `execute.service.ts` passes: [5](#0-4) 

7. The chain service submits the transaction to the Hedera network with an invalid signature for `0.0.X`.
8. Hedera rejects it with `INVALID_SIGNATURE`. The transaction is permanently marked `FAILED` and cannot be re-executed.

### Impact Explanation

The transaction is permanently corrupted and unrecoverable. Any assets or state changes it was intended to effect (transfers, account updates, file updates, node operations) are blocked. In an organization context, critical multi-sig transactions — such as system file updates or large transfers — can be sabotaged by a single malicious internal user. The `TransactionSigner` record also falsely attributes a signature to the attacker's account, corrupting audit trails.

### Likelihood Explanation

The attacker must be an authenticated, verified user in the organization (no anonymous access). They must act before the legitimate key owner registers their key. Because Hedera account public keys are publicly visible on-chain and key registration has no race-condition protection, a monitoring attacker can reliably front-run registration. No cryptographic capability is required — only the ability to submit an HTTP request with arbitrary bytes.

### Recommendation

**Fix 1 — Require proof of possession on key registration.** Before accepting a public key, require the caller to submit a signature over a server-issued challenge (e.g., a nonce tied to the user's session) using the corresponding private key. Verify it with `publicKey.verify(challenge, signature)` before persisting the key. This mirrors the pattern already used in `validateAndPrepareTransaction`: [6](#0-5) 

**Fix 2 — Add cryptographic signature verification in `processTransactionSignatures`.** Before calling `addSignature`, verify each signature entry using the same `validateSignature` utility already used in `importSignatures`: [7](#0-6) 

Replace the bare `addSignature` call with a `publicKey.verify(bodyBytes, signatureBytes)` check first, rejecting the entire submission if any signature is invalid.

### Proof of Concept

```
# Step 1: Attacker registers victim's public key (not yet in system)
POST /user/keys
Authorization: Bearer <attacker_jwt>
{ "publicKey": "<victim_account_0.0.X_public_key_hex>" }
→ 201 Created

# Step 2: Attacker submits garbage signature for that key on transaction T
POST /transactions/{T_id}/signers
Authorization: Bearer <attacker_jwt>
{
  "signatureMap": {
    "0.0.3": {
      "{T_transaction_id}": {
        "<victim_public_key_DER>": "deadbeefdeadbeefdeadbeef..."
      }
    }
  }
}
→ 201 Created  (backend accepts without verifying signature bytes)

# Result: Transaction T is submitted to Hedera with an invalid signature,
# rejected with INVALID_SIGNATURE, and permanently marked FAILED.
```

**Relevant files:**
- `back-end/apps/api/src/user-keys/user-keys.service.ts` — `uploadKey` (lines 33–66)
- `back-end/apps/api/src/transactions/signers/signers.service.ts` — `processTransactionSignatures` (lines 217–267)
- `back-end/libs/common/src/utils/sdk/transaction.ts` — `validateSignature` (lines 213–248, used in `importSignatures` but absent from `uploadSignatureMaps`)
- `back-end/libs/common/src/execute/execute.service.ts` — `getValidatedSDKTransaction` (lines 204–223)

### Citations

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L33-66)
```typescript
  async uploadKey(user: User, dto: UploadUserKeyDto): Promise<UserKey> {
    await attachKeys(user, this.repo.manager);

    // Check if the user already has the maximum number of keys
    if (user.keys.length >= MAX_USER_KEYS) {
      throw new BadRequestException(ErrorCodes.UMK);
    }

    // Find the userKey by the publicKey
    let userKey = await this.repo.findOne({
      where: { publicKey: dto.publicKey },
      withDeleted: true,
    });

    if (userKey) {
      // If the userKey found is owned by a different user,
      // or if the userKey has a non null hash or index that doesn't
      // match the hash or index provided
      // throw an error.
      if (userKey.userId !== user.id || (userKey.index && userKey.index !== dto.index)) {
        throw new BadRequestException(ErrorCodes.PU);
      }
      // Set the hash and/or index (only if the current value is null)
      Object.assign(userKey, dto);
    } else {
      userKey = await this.repo.create(dto);
      userKey.user = user;
    }

    if (userKey.deletedAt) {
      await this.repo.recover(userKey);
    }
    return this.repo.save(userKey);
  }
```

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

**File:** back-end/libs/common/src/execute/execute.service.ts (L218-221)
```typescript
    /* Checks if the transaction has valid signatureKey */
    if (!hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey))
      throw new Error('Transaction has invalid signature.');

```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L909-913)
```typescript
    // Verify signature
    const validSignature = publicKey.verify(dto.transactionBytes, dto.signature);
    if (!validSignature) {
      throw new BadRequestException(ErrorCodes.SNMP);
    }
```
