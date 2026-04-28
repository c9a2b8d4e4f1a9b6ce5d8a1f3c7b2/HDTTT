I have verified all the code references in the claim. Let me confirm the key facts before rendering a verdict.

All code references have been verified against the actual source. Every claim in the report is accurate.

---

Audit Report

## Title
Authorization Bypass via Missing Key-Ownership Check in `importSignatures` — Parallel Signature-Upload Path Omits the Enforcement Present in the Primary Path

## Summary
Two HTTP endpoints accept signature maps for stored transactions. The primary path (`POST /transactions/:id/signers`) enforces that every submitted public key belongs to the authenticated user. The secondary path (`POST /transactions/signatures/import`) performs only a cryptographic validity check and omits the key-ownership guard entirely. Any authenticated user who passes the broad `verifyAccess` check (observer role qualifies) can inject cryptographically valid signatures from keys they do not own, advancing the transaction's signing state without the key owners' participation.

## Finding Description

**Primary path — key ownership enforced**

`SignersController.uploadSignatureMap` → `SignersService.uploadSignatureMaps` → `processTransactionSignatures`: [1](#0-0) 

`userKeyMap` is built exclusively from `user.keys` (the authenticated user's registered keys). Any public key not in that map causes an immediate `ErrorCodes.PNY` throw, rejecting the request. [2](#0-1) 

**Secondary path — key ownership absent**

`TransactionsController.importSignatures` → `TransactionsService.importSignatures`: [3](#0-2) 

`validateSignature` (the only gate before `addSignature`) verifies only that the supplied bytes are a valid cryptographic signature over the transaction body for the given public key: [4](#0-3) 

There is no check that the public key is registered to the calling user. Any key whose signature is cryptographically valid is accepted and written into the stored `transactionBytes`.

The endpoint is reachable by any authenticated, verified user who passes `verifyAccess`: [5](#0-4) 

`verifyAccess` grants entry to creators, signers, observers, and approvers — a much broader population than "users who own the keys being submitted": [6](#0-5) 

The API description itself documents the absence of audit records: *"No signature entities will be created."* [7](#0-6) 

## Impact Explanation
An attacker who is an observer (or any other role that passes `verifyAccess`) on a transaction can:

1. Obtain valid signature bytes over the transaction body for a key they do not own (e.g., from a `.tx2` export file shared over email or a shared folder — a first-class application feature).
2. Call `POST /transactions/signatures/import` with that signature map.
3. The backend writes the foreign signature into the stored `transactionBytes` without creating a `TransactionSigner` record, so the injection is invisible in the signing audit trail.
4. If the injected signature satisfies the remaining threshold, `processTransactionStatus` advances the transaction to `WAITING_FOR_EXECUTION`, enabling submission to the Hedera network without the key owner having explicitly approved through the normal workflow.

The result is unauthorized state advancement of a multi-party transaction and circumvention of the signing-approval workflow the platform is designed to enforce.

## Likelihood Explanation
- The attacker must be an authenticated, verified user with `verifyAccess` on the target transaction; observer role qualifies.
- Valid signature bytes for a foreign key are obtainable without breaking cryptography: the `.tx2` export/import workflow is a first-class feature of the application, and exported files contain raw signatures.
- The endpoint requires no elevated privilege and is reachable from the standard frontend client or any HTTP client.
- No rate-limiting or additional confirmation step is applied to `importSignatures`.

## Recommendation
Add a key-ownership check inside `importSignatures` analogous to the one in `processTransactionSignatures`. After `validateSignature` returns the list of `publicKeys`, verify that each public key is present in the calling user's registered keys (`user.keys`) before calling `sdkTransaction.addSignature`. If any submitted key is not owned by the caller, reject the entire request (or skip that key and return an error for it, consistent with the existing per-item error model).

Alternatively, restrict the `importSignatures` endpoint to users who own at least one of the keys present in the submitted signature map, mirroring the ownership invariant enforced by the primary path.

## Proof of Concept
```
# Prerequisites:
# - Attacker (user B) is an observer on transaction ID 42
# - A .tx2 export file for transaction 42 contains a signature from user A's key

# 1. Parse the .tx2 file to extract the raw signature map bytes for user A's key.

# 2. Format the signature map as the API expects:
POST /transactions/signatures/import
Authorization: Bearer <user_B_jwt>
Content-Type: application/json

[{
  "id": 42,
  "signatureMap": {
    "0.0.3": {
      "0.0.2159149@1730378704.000000000": {
        "<user_A_public_key_DER>": "<user_A_signature_hex>"
      }
    }
  }
}]

# 3. The server calls validateSignature, which verifies the signature is
#    cryptographically valid for user A's key — it passes.
#    sdkTransaction.addSignature is called with user A's public key.
#    transactionBytes is updated in the database.
#    No TransactionSigner record is created.

# 4. If this was the last required signature, the transaction status
#    advances to WAITING_FOR_EXECUTION without user A's explicit approval.
``` [8](#0-7) [9](#0-8)

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L161-165)
```typescript
    // Build user key lookup once
    const userKeyMap = new Map<string, UserKey>();
    for (const key of user.keys) {
      userKeyMap.set(key.publicKey, key);
    }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L217-248)
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
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L525-555)
```typescript
    for (const { id, signatureMap: map } of dto) {
      const transaction = transactionMap.get(id);

      try {
        /* Verify that the transaction exists and access is verified */
        if (!(await this.verifyAccess(transaction, user))) {
          throw new BadRequestException(ErrorCodes.TNF);
        }

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
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L786-809)
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
  }
```

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L229-241)
```typescript
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
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L83-85)
```typescript
    description:
      'Import all signatures for the specified transactions. No signature entities will be created.',
  })
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L93-107)
```typescript
  @Post('/signatures/import')
  @HttpCode(201)
  @Serialize(SignatureImportResultDto)
  async importSignatures(
    @Body() body: UploadSignatureMapDto[] | UploadSignatureMapDto,
    @GetUser() user: User,
  ): Promise<SignatureImportResultDto[]> {
    const transformedSignatureMaps = await transformAndValidateDto(
      UploadSignatureMapDto,
      body
    );

    // Delegate to service to perform the import
    return this.transactionsService.importSignatures(transformedSignatureMaps, user);
  }
```
