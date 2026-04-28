### Title
Malicious Required Signer Can Permanently Fail Any Organization Transaction by Submitting Cryptographically Invalid Signature Bytes

### Summary
The `uploadSignatureMaps` endpoint in `signers.service.ts` validates only that the public key in a submitted signature map belongs to the authenticated user, but never cryptographically verifies that the signature bytes are valid for the transaction body. A required signer can submit garbage bytes under their own registered public key, causing the server to embed an invalid signature into the stored transaction bytes, advance the transaction to `WAITING_FOR_EXECUTION`, and trigger a permanent `FAILED` state when the Hedera network rejects it with `INVALID_SIGNATURE`. This is the direct analog of the external report's "Insufficient TokenAccount Check" — partial attribute matching (key ownership) substituted for the canonical cryptographic check (signature validity).

### Finding Description

**Root cause — missing cryptographic verification in `uploadSignatureMaps`:**

In `back-end/apps/api/src/transactions/signers/signers.service.ts`, `processTransactionSignatures` iterates over every public key in the caller-supplied `SignatureMap`. For each key it performs exactly one check: does the key exist in the authenticated user's registered key set? [1](#0-0) 

If the key is found, the method immediately calls `sdkTransaction.addSignature(publicKey, map)` with the caller-supplied bytes — no cryptographic verification is performed: [2](#0-1) 

The Hedera SDK's `addSignature` does not verify signature validity; it only appends the bytes to the internal signature map and adds the public key to `_signerPublicKeys`. The resulting (now-corrupted) transaction bytes are then written back to the database: [3](#0-2) 

**Contrast with `importSignatures` — which does verify:**

The alternative import path in `transactions.service.ts` calls `validateSignature` before accepting any bytes: [4](#0-3) 

The primary signing endpoint (`POST /transactions/:id/signers`) has no equivalent check.

**State-machine consequence:**

After the invalid signature is stored, `processTransactionStatus` evaluates whether the accumulated `_signerPublicKeys` satisfy the required key structure via `hasValidSignatureKey`: [5](#0-4) 

Because `_signerPublicKeys` is populated by `addSignature` regardless of signature validity, the threshold check passes and the transaction is promoted to `WAITING_FOR_EXECUTION`. The chain service then submits it to the Hedera network, which rejects it with `INVALID_SIGNATURE`, and the execute service permanently marks it `FAILED`: [6](#0-5) 

A `FAILED` transaction cannot be re-executed; the organization must create an entirely new transaction.

**No access-control barrier on transaction selection:**

`loadTransactionData` fetches any transaction by ID with no membership check: [7](#0-6) 

Any authenticated user whose key happens to be a required signer on a target transaction can execute this attack.

### Impact Explanation

A required signer submits a signature map containing their own registered public key paired with 64 zero bytes (or any invalid bytes). The server accepts the submission, embeds the invalid signature into the stored transaction bytes, and — if this was the last required signature — immediately schedules the transaction for on-chain execution. The Hedera network rejects the transaction with `INVALID_SIGNATURE`. The transaction is permanently set to `FAILED` and cannot be recovered. All prior legitimate signatures and any associated organizational workflow are destroyed. The organization must recreate the transaction from scratch and collect all signatures again.

### Likelihood Explanation

The attacker needs only: (1) a valid account in the organization, (2) a registered key that is listed as a required signer on the target transaction — both are normal preconditions for any participant in the multi-sig workflow. No admin access, no leaked credentials, and no external tooling beyond a standard HTTP client are required. The `POST /transactions/:id/signers` endpoint is reachable by any verified user. [8](#0-7) 

### Recommendation

Apply the same `validateSignature` call that already exists in `importSignatures` to `processTransactionSignatures` before calling `addSignature`. Specifically, after confirming the public key belongs to the user, verify that the signature bytes in the map are cryptographically valid for the current transaction body. If validation fails, reject the entire submission with an appropriate error code (analogous to `ErrorCodes.ISNMPN`). This mirrors the fix described in the external report: derive/verify the canonical value rather than relying on a partial attribute match.

### Proof of Concept

1. Register as a normal user in an organization. Ensure your public key (`K`) is a required signer on transaction `T` (e.g., you are the fee payer or an explicit approver).
2. Obtain the stored transaction bytes for `T` (available via `GET /transactions/:id`).
3. Construct a `SignatureMap` JSON object with your node account ID, the transaction ID, your DER-encoded public key `K`, and 64 zero bytes as the signature value.
4. Submit `POST /transactions/:id/signers` with this map using your JWT.
5. The server responds `201` — the invalid signature is accepted and stored.
6. If `K` was the last required signer, observe the transaction status change to `WAITING FOR EXECUTION` within the next scheduler cycle (≤10 seconds).
7. The chain service submits the transaction to Hedera; the network returns `INVALID_SIGNATURE`.
8. The transaction status is permanently set to `FAILED` — confirmed via `GET /transactions/:id`.

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L131-133)
```typescript
    const transactions = await this.dataSource.manager.find(Transaction, {
      where: { id: In(transactionIds) },
    });
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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L296-299)
```typescript
      if (!isSameBytes) {
        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
        transactionsToUpdate.push({ id, transactionBytes: transaction.transactionBytes });
      }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L546-549)
```typescript
        const { data: publicKeys, error } = safe<PublicKey[]>(
          validateSignature.bind(this, sdkTransaction, map),
        );
        if (error) throw new BadRequestException(ErrorCodes.ISNMPN);
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L133-146)
```typescript
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

**File:** back-end/libs/common/src/execute/execute.service.ts (L173-176)
```typescript
      } else {
        transactionStatus = TransactionStatus.FAILED;
        transactionStatusCode = statusCode;
        result.error = message;
```

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L39-41)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class SignersController {
  constructor(private signaturesService: SignersService) {}
```
