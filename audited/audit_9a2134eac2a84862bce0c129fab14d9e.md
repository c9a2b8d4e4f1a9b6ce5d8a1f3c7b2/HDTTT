### Title
`ApproveAllController` Hardcodes `userKeys[0]` for All Group Approvals; `ApproveTransactionController` Crashes When No Mnemonic Key Exists — Wrong Key Selection Breaks Approval Workflows

### Summary
Both approval controllers in the frontend select the signing key using a hardcoded positional index rather than dynamically selecting the key that matches the approver's registered organization key for each transaction. This is the direct analog of the external report's wrong-session bug: instead of selecting the appropriate Cubist session per request, this codebase always picks the first key in the array, causing silent functional failures or unhandled crashes that permanently block the approval workflow for affected users.

### Finding Description

**Root cause 1 — `ApproveAllController.vue` (batch approval)**

`handleApproveAll` resolves the signing key once, before the per-transaction loop, by unconditionally indexing into position zero of the organization's key array:

```
const publicKey = user.selectedOrganization.userKeys[0].publicKey;   // line 76
const privateKeyRaw = await decryptPrivateKey(user.personal.id, personalPassword, publicKey);
const privateKey = getPrivateKey(publicKey, privateKeyRaw);

for (const item of group.groupItems) {
  if (await getUserShouldApprove(...)) {
    ...
    await sendApproverChoice(
      user.selectedOrganization.serverUrl,
      item.transaction.id,
      user.selectedOrganization.userKeys[0].id,   // line 92 — always first key
      signature,
      props.approved,
    );
  }
}
``` [1](#0-0) 

A user can register multiple organization keys (the backend enforces a maximum via `MAX_USER_KEYS` but allows many). If `userKeys[0]` has no corresponding local private key in SQLite (e.g., it is an externally-imported key whose private material was never stored locally, while `userKeys[1]` is the mnemonic-derived key that is stored), `decryptPrivateKey` throws and the entire batch approval fails — no transaction in the group can be approved or rejected. [2](#0-1) 

**Root cause 2 — `ApproveTransactionController.vue` (single-transaction approval)**

`performApprove` selects the key by filtering for the first entry that has a `mnemonicHash`:

```
const orgKey = user.selectedOrganization.userKeys.filter(k => k.mnemonicHash)[0];
const privateKeyRaw = await decryptPrivateKey(
  user.personal.id,
  personalPassword,
  orgKey.publicKey,   // TypeError if orgKey is undefined
);
``` [3](#0-2) 

The `UploadUserKeyDto` makes `mnemonicHash` optional — a user can upload a raw public key with no mnemonic derivation at all: [4](#0-3) 

When every organization key was imported as a raw private key (no mnemonic), `filter(k => k.mnemonicHash)` returns an empty array, `orgKey` is `undefined`, and `orgKey.publicKey` throws a `TypeError`. The approval controller crashes with an unhandled error and the transaction cannot be approved or rejected.

**Backend does not compensate**

The backend `approveTransaction` verifies the signature against whichever `userKeyId` the client submits, but it does not enforce which specific key must be used. It only checks that the key belongs to the authenticated user and that the signature is cryptographically valid: [5](#0-4) 

There is no server-side fallback that would allow approval to proceed when the client sends the wrong key or crashes before sending anything.

### Impact Explanation

- **Batch approval (`ApproveAllController`)**: Any organization user whose first registered key (`userKeys[0]`) lacks a locally-stored private key cannot approve or reject any transaction in a group via "Approve All". The entire batch is silently skipped or throws, leaving all group transactions permanently stuck in `WAITING_FOR_SIGNATURES` / `WAITING_FOR_EXECUTION` if this user is a required approver.
- **Single-transaction approval (`ApproveTransactionController`)**: Any organization user who registered their key as a raw imported key (no mnemonic) cannot approve or reject any individual transaction. The UI crashes with an unhandled `TypeError` before the API call is made.
- In both cases, if the affected user is the sole required approver (or part of a threshold that cannot be met without them), the transaction is permanently unapprovable — a functional freeze of organizational funds.

### Likelihood Explanation

Both failure conditions are reachable through normal, documented product flows:
1. A user imports a raw private key into the organization (no mnemonic) — explicitly supported by the upload API and the UI import flow.
2. A user registers multiple organization keys where the first is not the one with a local private key — supported by the multi-key architecture confirmed in the performance test comments ("The app DOES support multiple keys per user for signing").

No attacker action is required; the bug is triggered by the legitimate user's own key configuration.

### Recommendation

**`ApproveAllController.vue`**: Do not resolve the signing key once before the loop. For each transaction, determine which of the user's organization keys has a locally-stored private key and matches the key registered as the approver for that specific transaction. Iterate `user.selectedOrganization.userKeys` and select the first key for which `decryptPrivateKey` succeeds (or for which a local key pair exists in SQLite).

**`ApproveTransactionController.vue`**: Replace the blind `filter(k => k.mnemonicHash)[0]` with logic that finds the key that (a) belongs to the user's organization keys and (b) has a corresponding local key pair — regardless of whether it was mnemonic-derived or imported. Add a null-guard and surface a clear error message if no usable key is found, rather than crashing with a `TypeError`.

### Proof of Concept

**Scenario A — `ApproveAllController` failure**

1. Register user U with two organization keys: Key A (raw import, no local private key) and Key B (mnemonic-derived, local private key present). Key A is `userKeys[0]`.
2. Create a transaction group and assign U as approver.
3. U clicks "Approve All".
4. `ApproveAllController` calls `decryptPrivateKey(userId, password, keyA.publicKey)`.
5. No local key pair exists for Key A → `decryptPrivateKey` throws.
6. The catch block at line 99 shows a toast error; no `sendApproverChoice` call is made for any transaction.
7. All transactions in the group remain unapproved.

**Scenario B — `ApproveTransactionController` crash**

1. Register user U with one organization key: Key C (raw import, `mnemonicHash = null`).
2. Create a transaction and assign U as approver.
3. U opens the transaction and clicks "Approve transaction".
4. `performApprove` executes `user.selectedOrganization.userKeys.filter(k => k.mnemonicHash)` → returns `[]`.
5. `orgKey` is `undefined`; `orgKey.publicKey` throws `TypeError: Cannot read properties of undefined`.
6. The approval controller fails; the transaction cannot be approved or rejected by U. [6](#0-5) [7](#0-6)

### Citations

**File:** front-end/src/renderer/pages/TransactionGroupDetails/ApproveAllController.vue (L76-100)
```vue
      const publicKey = user.selectedOrganization.userKeys[0].publicKey;
      const privateKeyRaw = await decryptPrivateKey(user.personal.id, personalPassword, publicKey);
      const privateKey = getPrivateKey(publicKey, privateKeyRaw);

      for (const item of group.groupItems) {
        if (await getUserShouldApprove(user.selectedOrganization.serverUrl, item.transaction.id)) {
          const transactionBytes = hexToUint8Array(item.transaction.transactionBytes);
          const transaction = Transaction.fromBytes(transactionBytes);
          const signature = getTransactionBodySignatureWithoutNodeAccountId(
            privateKey,
            transaction,
          );

          await sendApproverChoice(
            user.selectedOrganization.serverUrl,
            item.transaction.id,
            user.selectedOrganization.userKeys[0].id,
            signature,
            props.approved,
          );
        }
      }
      toastManager.success(`Transactions ${props.approved ? 'approved' : 'rejected'} successfully`);
    } catch (error) {
      toastManager.error(getErrorMessage(error, `Failed to ${action.value} transactions`));
```

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L33-65)
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
```

**File:** front-end/src/renderer/pages/TransactionDetails/ApproveTransactionController.vue (L90-107)
```vue
  const orgKey = user.selectedOrganization.userKeys.filter(k => k.mnemonicHash)[0];
  const privateKeyRaw = await decryptPrivateKey(
    user.personal.id,
    personalPassword,
    orgKey.publicKey,
  );

  const privateKey = getPrivateKey(orgKey.publicKey, privateKeyRaw);

  const signature = getTransactionBodySignatureWithoutNodeAccountId(privateKey, sdkTransaction);

  await sendApproverChoice(
    user.selectedOrganization.serverUrl,
    transaction.id,
    orgKey.id,
    signature,
    props.approved,
  );
```

**File:** back-end/apps/api/src/user-keys/dtos/upload-user-key.dto.ts (L6-21)
```typescript
  @ValidateIf(val => val.index !== undefined)
  @IsDefined()
  @IsString()
  @IsNotEmpty()
  mnemonicHash?: string;

  @ValidateIf(val => val.mnemonicHash !== undefined)
  @IsDefined()
  @IsNumber()
  @IsNotEmpty()
  index?: number;

  @IsNotEmpty()
  @IsHederaPublicKey()
  @NormalizePublicKey()
  publicKey: string;
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L569-596)
```typescript
    const signatureKey = user.keys.find(key => key.id === dto.userKeyId);

    /* Gets the public key that the signature belongs to */
    const publicKey = PublicKey.fromString(signatureKey?.publicKey);

    /* Get the transaction body */
    const transaction = await this.dataSource.manager.findOne(Transaction, {
      where: { id: transactionId },
      relations: { creatorKey: true, observers: true },
    });

    /* Check if the transaction exists */
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    /* Checks if the transaction is requires approval */
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    /* Verify the signature matches the transaction */
    if (
      !verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTransaction, dto.signature, publicKey)
    )
      throw new BadRequestException(ErrorCodes.SNMP);
```
