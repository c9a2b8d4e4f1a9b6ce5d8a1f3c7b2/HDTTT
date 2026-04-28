All code references have been verified against the actual source. The vulnerability is confirmed.

---

Audit Report

## Title
Observer-Role Users Can Import Arbitrary Valid Signatures via Divergent Authorization Between Two Parallel Signature-Upload Code Paths

## Summary
Two parallel code paths exist for adding signatures to transactions. `SignersService.uploadSignatureMaps` (endpoint `POST /transactions/:transactionId/signers`) enforces that every public key in the submitted signature map must belong to the authenticated user's registered keys. `TransactionsService.importSignatures` (endpoint `POST /transactions/signatures/import`) performs no equivalent ownership check — its only authorization gate is `verifyAccess`, which explicitly grants access to observers. An observer can therefore inject any cryptographically valid signature obtained externally, mutate `transactionBytes` in the database, and trigger status transitions without being a designated signer.

## Finding Description

**Divergent authorization — `uploadSignatureMaps` vs `importSignatures`:**

`SignersService.validateAndProcessSignatures` builds a `userKeyMap` from `user.keys`: [1](#0-0) 

Inside `processTransactionSignatures`, if any public key in the submitted `SignatureMap` is not found in that map, it throws `ErrorCodes.PNY` ("Public key not yours"): [2](#0-1) 

`TransactionsService.importSignatures` performs no equivalent check. Its only authorization gate is `verifyAccess`: [3](#0-2) 

`verifyAccess` explicitly returns `true` for any user who is an observer of the transaction: [4](#0-3) 

After `verifyAccess` passes, `importSignatures` only validates that the submitted signature is cryptographically valid for the transaction body (via `validateSignature`), then writes the updated `transactionBytes` directly to the database and emits a `TransactionStatusUpdate` event: [5](#0-4) [6](#0-5) 

**Secondary divergence — no `TransactionSigner` record created:**

`uploadSignatureMaps` creates `TransactionSigner` rows to track who signed: [7](#0-6) 

`importSignatures` creates no such records. The signer audit trail is therefore incomplete when signatures are imported via this path, and downstream status logic operates on `transactionBytes` alone without a corresponding signer record.

## Impact Explanation
An observer — a role explicitly intended to be read-only — can modify the cryptographic state of a transaction by injecting a valid signature obtained from an offline signing session. This can:

- Advance a transaction to `WAITING_FOR_EXECUTION` without the designated signer having gone through the intended signing workflow.
- Corrupt the `TransactionSigner` audit trail (no signer record is created), breaking downstream logic that relies on signer records for notification, status, and compliance tracking.
- In a multi-signature threshold scenario, allow an observer to contribute a signature that counts toward the threshold, effectively participating in signing without authorization.

## Likelihood Explanation
The `importSignatures` endpoint is the documented mechanism for importing offline/external signatures. In any organization using offline signing (the primary use case of this tool), valid signature files are routinely shared between parties. An observer who receives such a file — even for read-only verification — can exploit this path. No privileged access is required beyond being added as an observer, which is a normal workflow action performed by the transaction creator.

## Recommendation
Apply the same public-key ownership check used in `processTransactionSignatures` to `importSignatures`. Before accepting any public key from the submitted `SignatureMap`, verify that the key exists in the authenticated user's registered keys (`user.keys`). If the key is not found, reject the request with an appropriate error (e.g., `ErrorCodes.PNY`). Additionally, consider whether `importSignatures` should create `TransactionSigner` records to maintain a consistent audit trail, or whether the endpoint should be restricted to users with a signer role rather than any user who passes `verifyAccess`.

## Proof of Concept

1. Attacker is added as an observer on a target transaction (normal workflow action by the creator).
2. A valid offline signature file (containing a cryptographically valid `SignatureMap` for the transaction body) is obtained — e.g., shared for verification purposes, which is the documented use case.
3. Attacker calls `POST /transactions/signatures/import` with the valid signature map.
4. `verifyAccess` returns `true` (observer check at line 805 passes).
5. `validateSignature` passes (signature is cryptographically valid for the transaction body).
6. `transactionBytes` is updated in the database with the injected signature (lines 595–601).
7. `emitTransactionStatusUpdate` fires (line 616); the chain service re-evaluates status and may advance the transaction to `WAITING_FOR_EXECUTION`.
8. No `TransactionSigner` record is created, so the audit trail shows no signer for this signature contribution.

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L161-165)
```typescript
    // Build user key lookup once
    const userKeyMap = new Map<string, UserKey>();
    for (const key of user.keys) {
      userKeyMap.set(key.publicKey, key);
    }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L244-248)
```typescript
          let userKey = userKeyMap.get(raw);
          if (!userKey) {
            userKey = userKeyMap.get(publicKey.toStringDer());
          }
          if (!userKey) throw new Error(ErrorCodes.PNY);
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L529-532)
```typescript
        /* Verify that the transaction exists and access is verified */
        if (!(await this.verifyAccess(transaction, user))) {
          throw new BadRequestException(ErrorCodes.TNF);
        }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L546-555)
```typescript
        const { data: publicKeys, error } = safe<PublicKey[]>(
          validateSignature.bind(this, sdkTransaction, map),
        );
        if (error) throw new BadRequestException(ErrorCodes.ISNMPN);

        for (const publicKey of publicKeys) {
          sdkTransaction.addSignature(publicKey, map);
        }

        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L616-622)
```typescript
      emitTransactionStatusUpdate(
        this.notificationsPublisher,
        updateArray.map(r => ({
          entityId: r.id,
          additionalData: { transactionId: r.transactionId, network: r.network },
        })),
      );
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L802-808)
```typescript
    return (
      userKeysToSign.length !== 0 ||
      transaction.creatorKey?.userId === user.id ||
      !!transaction.observers?.some(o => o.userId === user.id) ||
      !!transaction.signers?.some(s => s.userKey?.userId === user.id) ||
      !!transaction.approvers?.some(a => a.userId === user.id)
    );
```
