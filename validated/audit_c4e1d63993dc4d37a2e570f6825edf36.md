### Title
Observer-Role Users Can Import Arbitrary Valid Signatures via Divergent Authorization Between Two Parallel Signature-Upload Code Paths

### Summary

Two parallel code paths exist for adding signatures to transactions: `SignersService.uploadSignatureMaps` (endpoint `POST /transactions/:transactionId/signers`) and `TransactionsService.importSignatures` (endpoint `POST /transactions/signatures/import`). These paths implement divergent authorization logic. The `uploadSignatureMaps` path enforces that every public key in the submitted signature map must belong to the authenticated user's registered keys. The `importSignatures` path only calls `verifyAccess`, which grants access to observers — users with a read-only role — allowing them to inject valid signatures for keys they do not own, modifying `transactionBytes` and triggering status transitions without being a designated signer.

### Finding Description

**Root cause — duplicated, divergent authorization logic:**

`SignersService.uploadSignatureMaps` builds a `userKeyMap` from `user.keys` and, inside `processTransactionSignatures`, throws `ErrorCodes.PNY` ("Public key not yours") if any public key in the submitted `SignatureMap` is not found in that map: [1](#0-0) [2](#0-1) 

`TransactionsService.importSignatures` performs no equivalent check. Its only authorization gate is `verifyAccess`: [3](#0-2) 

`verifyAccess` returns `true` for any user who is a creator, observer, signer, or approver of the transaction: [4](#0-3) 

Observers are explicitly included in this check (`transaction.observers?.some(o => o.userId === user.id)`). An observer has a read-only role (`Role.STATUS`, `Role.FULL`, or `Role.APPROVER`) and is not a designated signer.

After `verifyAccess` passes, `importSignatures` only validates that the submitted signature is cryptographically valid for the transaction body, then writes the updated `transactionBytes` directly to the database and emits a `TransactionStatusUpdate` event: [5](#0-4) [6](#0-5) 

**Secondary divergence — no `TransactionSigner` record created:**

`uploadSignatureMaps` creates `TransactionSigner` rows to track who signed. `importSignatures` does not. This means the signer audit trail is incomplete when signatures are imported via this path, and the chain service's `processTransactionStatus` will compute status transitions based on `transactionBytes` alone, without a corresponding signer record. [7](#0-6) 

**Exploit path:**

1. Attacker registers as an observer on a target transaction (or is added as one by the creator).
2. In a multi-party signing workflow, a valid offline signature file is shared with the attacker (e.g., for verification purposes — this is the documented use case of the `importSignatures` endpoint per `front-end/docs/api.md`).
3. Attacker calls `POST /transactions/signatures/import` with the valid signature map.
4. `verifyAccess` returns `true` (observer check passes).
5. `validateSignature` passes (signature is cryptographically valid).
6. `transactionBytes` is updated with the injected signature.
7. `emitTransactionStatusUpdate` fires; the chain service re-evaluates status and may advance the transaction to `WAITING_FOR_EXECUTION`. [8](#0-7) 

### Impact Explanation

An observer — a role explicitly intended to be read-only — can modify the cryptographic state of a transaction by injecting a valid signature obtained from an offline signing session. This can:

- Advance a transaction to `WAITING_FOR_EXECUTION` without the designated signer having gone through the intended signing workflow.
- Corrupt the `TransactionSigner` audit trail (no signer record is created), breaking downstream logic that relies on signer records for notification, status, and compliance tracking.
- In a multi-signature threshold scenario, allow an observer to contribute a signature that counts toward the threshold, effectively participating in signing without authorization.

### Likelihood Explanation

The `importSignatures` endpoint is the documented mechanism for importing offline/external signatures. In any organization using offline signing (the primary use case of this tool), valid signature files are routinely shared between parties. An observer who receives such a file — even for read-only verification — can exploit this path. No privileged access is required beyond being added as an observer, which is a normal workflow action performed by the transaction creator.

### Recommendation

Apply the same key-ownership check used in `uploadSignatureMaps` to `importSignatures`. After `verifyAccess`, verify that every public key in the submitted `SignatureMap` is registered to the authenticated user:

```typescript
// In importSignatures, after verifyAccess:
const userKeyPublicKeys = new Set(user.keys.map(k => k.publicKey));
for (const [, txMap] of map) {
  for (const [, sigMap] of txMap) {
    for (const publicKey of sigMap.keys()) {
      if (!userKeyPublicKeys.has(publicKey.toStringRaw()) &&
          !userKeyPublicKeys.has(publicKey.toStringDer())) {
        throw new BadRequestException(ErrorCodes.PNY);
      }
    }
  }
}
```

Alternatively, consolidate both paths to share a single authorization helper, eliminating the duplication that caused this divergence. Also ensure `importSignatures` creates `TransactionSigner` records consistent with `uploadSignatureMaps`.

### Proof of Concept

**Preconditions:**
- User A creates a transaction requiring User B's key signature.
- User A adds User C as an observer (`Role.FULL`).
- User B signs the transaction offline and shares the signature file with User C for review.

**Steps:**
1. User C (observer) calls `POST /transactions/signatures/import` with the signature map from User B's offline signing session.
2. Server executes `verifyAccess` → returns `true` (User C is an observer).
3. Server executes `validateSignature` → returns valid (signature is cryptographically correct for User B's key).
4. Server writes updated `transactionBytes` (now containing User B's signature) to the database.
5. `emitTransactionStatusUpdate` fires; chain service advances transaction to `WAITING_FOR_EXECUTION`.

**Expected (correct) behavior:** `ErrorCodes.PNY` — the public key does not belong to User C.
**Actual behavior:** Signature is accepted; transaction state is modified by a read-only observer. [9](#0-8) [10](#0-9)

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L155-199)
```typescript
  private async validateAndProcessSignatures(
    dto: UploadSignatureMapDto[],
    user: User,
    transactionMap: Map<number, Transaction>,
    signersByTransaction: Map<number, Set<number>>
  ) {
    // Build user key lookup once
    const userKeyMap = new Map<string, UserKey>();
    for (const key of user.keys) {
      userKeyMap.set(key.publicKey, key);
    }

    return Promise.all(
      dto.map(async ({ id, signatureMap: map }) => {
        try {
          const transaction = transactionMap.get(id);
          if (!transaction) return { id, error: ErrorCodes.TNF };

          // Validate transaction status
          const statusError = this.validateTransactionStatus(transaction);
          if (statusError) return { id, error: statusError };

          // Process signatures
          const { sdkTransaction, userKeys, isSameBytes } = await this.processTransactionSignatures(
            transaction,
            map,
            userKeyMap,
            signersByTransaction.get(id) || new Set()
          );

          return {
            id,
            transaction,
            sdkTransaction,
            userKeys,
            isSameBytes,
            error: null,
          };
        } catch (err) {
          console.error(`[TX ${id}] Error:`, err.message);
          return { id, error: err.message };
        }
      })
    );
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L534-563)
```typescript
        /* Checks if the transaction is canceled */
        if (
          transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
          transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
        )
          throw new BadRequestException(ErrorCodes.TNRS);

        /* Checks if the transaction is expired */
        const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
        if (isExpired(sdkTransaction)) throw new BadRequestException(ErrorCodes.TE);

        /* Validates the signatures */
        const { data: publicKeys, error } = safe<PublicKey[]>(
          validateSignature.bind(this, sdkTransaction, map),
        );
        if (error) throw new BadRequestException(ErrorCodes.ISNMPN);

        for (const publicKey of publicKeys) {
          sdkTransaction.addSignature(publicKey, map);
        }

        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());

        results.set(id, { id });
        updates.set(id, {
          id,
          transactionBytes: transaction.transactionBytes,
          transactionId: transaction.transactionId,
          network: transaction.mirrorNetwork,
        });
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L786-808)
```typescript
  async verifyAccess(transaction: Transaction, user: User): Promise<boolean> {
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (
      [
        TransactionStatus.EXECUTED,
        TransactionStatus.EXPIRED,
        TransactionStatus.FAILED,
        TransactionStatus.CANCELED,
        TransactionStatus.ARCHIVED,
      ].includes(transaction.status)
    )
      return true;

    const userKeysToSign = await this.userKeysToSign(transaction, user, true);

    return (
      userKeysToSign.length !== 0 ||
      transaction.creatorKey?.userId === user.id ||
      !!transaction.observers?.some(o => o.userId === user.id) ||
      !!transaction.signers?.some(s => s.userKey?.userId === user.id) ||
      !!transaction.approvers?.some(a => a.userId === user.id)
    );
```

**File:** front-end/src/renderer/services/organization/transaction.ts (L133-151)
```typescript
export const importSignatures = async (
  organization: LoggedInOrganization & Organization,
  signatureImport: ISignatureImport[] | ISignatureImport,
): Promise<SignatureImportResultDto[]> => {
  const formattedMaps: { id: number; signatureMap: FormattedMap }[] = [];
  const imports = Array.isArray(signatureImport) ? signatureImport : [signatureImport];
  for (const signatureImport of imports) {
    formattedMaps.push({
      id: signatureImport.id,
      signatureMap: formatSignatureMap(signatureImport.signatureMap),
    });
  }
  return commonRequestHandler(async () => {
    const { data } = await axiosWithCredentials.post(
      `${organization.serverUrl}/${controller}/signatures/import`,
      formattedMaps,
    );
    return data;
  }, 'Failed to import signatures');
```
