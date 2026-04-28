### Title
Missing Key Ownership Verification in `importSignatures` Allows Injection of Signatures from Keys Not Owned by the Authenticated User

### Summary

The `POST /transactions/signatures/import` endpoint in `back-end/apps/api/src/transactions/transactions.service.ts` validates that submitted signatures are cryptographically valid but never verifies that the public keys in the signature map belong to the authenticated user. Every other signature-submission path in the codebase enforces key ownership via the `OnlyOwnerKey` interceptor or an explicit `userKeyMap` lookup. The import path skips both checks entirely, allowing any user with access to a transaction to inject signatures from keys they do not own.

### Finding Description

**Root cause — wrong authority check used**

The external report's pattern is: a privileged action (token transfer) uses the wrong authority (`cpi_authority_pda` instead of `ctx.accounts.authority`). The analog here is: a privileged action (injecting signatures into persisted transaction bytes) uses only cryptographic validity as its authority check instead of also verifying key ownership.

**Contrast with the guarded path**

`POST /{id}/signers` → `signers.service.ts` → `processTransactionSignatures`:

```
for each publicKey in signatureMap:
    userKey = userKeyMap.get(raw)          // ownership lookup
    if (!userKey) throw ErrorCodes.PNY     // rejects non-owned keys
    sdkTransaction.addSignature(publicKey, map)
``` [1](#0-0) 

The controller also applies `@OnlyOwnerKey<ApproverChoiceDto>('userKeyId')` on the approve path: [2](#0-1) 

**The unguarded path**

`POST /transactions/signatures/import` → `transactions.controller.ts`:

```typescript
@Post('/signatures/import')
@HttpCode(201)
@Serialize(SignatureImportResultDto)
async importSignatures(
  @Body() body: UploadSignatureMapDto[] | UploadSignatureMapDto,
  @GetUser() user: User,
): Promise<SignatureImportResultDto[]> {
  // No @OnlyOwnerKey decorator
  return this.transactionsService.importSignatures(transformedSignatureMaps, user);
}
``` [3](#0-2) 

Inside `importSignatures` in `transactions.service.ts`:

```typescript
const { data: publicKeys, error } = safe<PublicKey[]>(
  validateSignature.bind(this, sdkTransaction, map),   // only checks crypto validity
);
if (error) throw new BadRequestException(ErrorCodes.ISNMPN);

for (const publicKey of publicKeys) {
  sdkTransaction.addSignature(publicKey, map);          // no ownership check
}
transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
``` [4](#0-3) 

`validateSignature` only verifies that the signature bytes are a valid cryptographic signature over the transaction body. It does not consult the database to confirm the signing public key is registered to the calling user.

**Skipped test confirms the gap is known**

A test that should enforce key-ownership on the approve path is explicitly skipped:

```typescript
it.skip('should throw if the signature key does not belong to the user', async () => {
``` [5](#0-4) 

### Impact Explanation

An authenticated user who has `verifyAccess` to a transaction (observer, approver, or signer role) and who possesses a cryptographically valid signature produced by another user's private key can:

1. Call `POST /transactions/signatures/import` with that signature.
2. The backend injects the foreign signature directly into `transaction.transactionBytes` and persists it.
3. No `TransactionSigner` record is created, so there is no audit trail linking the injection to the attacker.
4. If the injected signature satisfies the remaining threshold of a `KeyList` or `ThresholdKey`, the transaction advances to `WAITING_FOR_EXECUTION` without the legitimate key owner having explicitly submitted their signature through the authorized path.

This breaks the integrity of the multi-signature workflow: the system's invariant that "a signature is recorded only when the key owner explicitly submits it" is violated.

### Likelihood Explanation

The attacker preconditions are realistic and require no privileged access:

- **Obtain a valid signature**: Hedera transaction files (`.txsig`) are routinely shared between organization members as part of the offline signing workflow. The frontend's `importSignaturesFromV2File` function is the primary consumer of this endpoint and reads signatures from files that may be shared over chat or email. [6](#0-5) 

- **Have access to the transaction**: Any observer, approver, or signer passes `verifyAccess`.
- **No cryptographic break required**: The attacker uses a legitimately produced signature; they only need to possess the bytes.

### Recommendation

Apply the same key-ownership check used by the `/signers` path to `importSignatures`:

1. After `validateSignature` returns `publicKeys`, look up each public key in the database and confirm it is registered to the calling `user`.
2. Reject any public key not owned by the user with `ErrorCodes.PNY`, mirroring the logic in `processTransactionSignatures`.
3. Add `@OnlyOwnerKey` at the controller level if the DTO carries a `userKeyId`, or perform the ownership check inside the service using a `userKeyMap` built from `user.keys`.

The `OnlyOwnerKey` interceptor already implements the correct pattern: [7](#0-6) 

### Proof of Concept

**Preconditions**:
- `userA` and `userB` are both members of an organization.
- A transaction `T` exists in `WAITING_FOR_SIGNATURES` state.
- `userA` is a required signer; `userB` is an observer.
- `userA` signs `T` offline and shares the resulting `.txsig` file (e.g., via Slack).

**Steps**:
1. `userB` opens the `.txsig` file and extracts the `SignatureMap` containing `userA`'s signature.
2. `userB` calls:
   ```
   POST /transactions/signatures/import
   Authorization: Bearer <userB_jwt>
   Body: [{ "id": <T.id>, "signatureMap": <userA_signature_map> }]
   ```
3. The backend calls `validateSignature` — the signature is cryptographically valid, so no error is thrown.
4. `sdkTransaction.addSignature(userA_publicKey, map)` is called; `userA`'s signature is written into `transaction.transactionBytes`.
5. The database is updated. No `TransactionSigner` row is created for `userA`.
6. If `userA`'s signature was the last required signature, the transaction status advances to `WAITING_FOR_EXECUTION` — triggered by `userB`, not `userA`.

**Expected (correct) behavior**: Step 3 should also verify that `userA_publicKey` is registered to `userB`; since it is not, the request should be rejected with `ErrorCodes.PNY`.

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L244-248)
```typescript
          let userKey = userKeyMap.get(raw);
          if (!userKey) {
            userKey = userKeyMap.get(publicKey.toStringDer());
          }
          if (!userKey) throw new Error(ErrorCodes.PNY);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L65-73)
```typescript
  @Post('/approve')
  @OnlyOwnerKey<ApproverChoiceDto>('userKeyId')
  approveTransaction(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() body: ApproverChoiceDto,
  ): Promise<boolean> {
    return this.approversService.approveTransaction(body, transactionId, user);
  }
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L545-555)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.spec.ts (L1350-1373)
```typescript
    it.skip('should throw if the signature key does not belong to the user', async () => {
      const dto: ApproverChoiceDto = {
        userKeyId: 2,
        signature: Buffer.from('0x123'),
        approved: true,
      };
      const transaction = {
        id: 1,
        status: TransactionStatus.WAITING_FOR_EXECUTION,
      };

      jest.spyOn(service, 'getVerifiedApproversByTransactionId').mockResolvedValueOnce([
        {
          userId: user.id,
          transactionId: 1,
        } as TransactionApprover,
      ]);
      dataSource.manager.findOne.mockResolvedValueOnce(transaction);

      await expect(service.approveTransaction(dto, transaction.id, user)).rejects.toThrow(
        ErrorCodes.KNRS,
      );
      expect(emitTransactionStatusUpdate).not.toHaveBeenCalled();
    });
```

**File:** front-end/src/renderer/pages/Transactions/Transactions.vue (L217-243)
```vue
async function importSignaturesFromV2File(filePath: string) {
  assertIsLoggedInOrganization(user.selectedOrganization);

  const transactionFile = await readTransactionFile(filePath);
  const importInputs: ISignatureImport[] = [];
  const unknownTransactionIds = [];

  for (const item of transactionFile.items) {
    const transactionBytes = hexToUint8Array(item.transactionBytes);
    const sdkTransaction = Transaction.fromBytes(transactionBytes);

    const map = SignatureMap._fromTransaction(sdkTransaction);

    const transactionId = sdkTransaction.transactionId;
    try {
      const transaction = await transactionCache.lookup(
        transactionId!.toString(),
        user.selectedOrganization.serverUrl,
      );
      importInputs.push({
        id: transaction.id,
        signatureMap: map,
      });
    } catch {
      unknownTransactionIds.push(transactionId!.toString());
    }
  }
```

**File:** back-end/libs/common/src/interceptors/only-owner-key.interceptor.ts (L35-40)
```typescript
      const keyIdValues = this.searchForKeyIdProp(body);

      const userKeyIds = new Set(user.keys.map(key => key.id));
      if (!keyIdValues.every(keyId => userKeyIds.has(keyId))) {
        throw new BadRequestException(ErrorCodes.PNY);
      }
```
