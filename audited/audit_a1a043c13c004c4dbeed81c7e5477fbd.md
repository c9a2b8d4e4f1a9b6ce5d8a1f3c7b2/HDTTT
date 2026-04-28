### Title
Missing Proof-of-Ownership on Public Key Registration Enables Key Squatting and Signer Impersonation

### Summary
The `uploadKey` endpoint in `UserKeysService` accepts any valid Hedera public key from an authenticated user and associates it with their account without requiring any cryptographic proof that the submitter controls the corresponding private key. An attacker can register a victim's public key as their own, permanently blocking the legitimate owner from registering it and disrupting any transaction workflow that depends on that key.

### Finding Description
The root cause is in `UserKeysService.uploadKey()`. The only checks performed are:

1. The public key is a valid Hedera key format (`@IsHederaPublicKey()` in the DTO).
2. The key is not already registered to a **different** user.

No challenge-response, no signature-over-nonce, no proof of private key possession is required. [1](#0-0) 

The DTO confirms there is no signature or proof field: [2](#0-1) 

The controller is protected by JWT authentication, so the attacker must be a registered user — but any registered user can submit any public key string: [3](#0-2) 

Once the attacker's account owns the key record, the uniqueness guard in `uploadKey` rejects any subsequent attempt by the legitimate owner to register the same key: [4](#0-3) 

The `OnlyOwnerKey` interceptor and `HasKeyGuard` both rely on the `user.keys` relationship, which is now poisoned with the squatted key: [5](#0-4) [6](#0-5) 

### Impact Explanation
**Concrete impact — Key Squatting / Permanent DoS on Signer:**
An attacker registers a target's known Hedera public key (public keys are, by definition, public) before the victim does. The victim's subsequent registration attempt is rejected with `ErrorCodes.PU`. The victim can no longer participate in any multi-signature transaction workflow on the platform that requires their key, because the platform has no record of them owning it. The attacker also cannot sign (they lack the private key), so any transaction requiring that key is permanently stalled on the platform.

**Secondary impact — False identity in non-cryptographic access control:**
`approveTransaction` looks up the signer's public key via `user.keys.find(key => key.id === dto.userKeyId)`. The attacker's account now holds a `userKeyId` pointing to the victim's public key. While the downstream `verifyTransactionBodyWithoutNodeAccountIdSignature` call would reject a forged signature, the attacker appears as the registered owner of that key in all non-cryptographic access control paths (observer checks, approver lists, `getVerifiedApproversByTransactionId`). [7](#0-6) 

### Likelihood Explanation
- **Attacker precondition**: Only a valid registered account is needed. No admin access, no leaked secrets.
- **Target information**: Hedera public keys are routinely shared (they are the public half of a key pair, visible on-chain and in transaction metadata).
- **Exploit window**: The race is won by whoever registers the key first. An attacker monitoring the Hedera mirror node for new public keys can pre-register them before legitimate users onboard to the platform.
- **No rate-limit or anomaly detection** on the key upload endpoint is visible in the codebase.

### Recommendation
Require cryptographic proof of private key ownership at registration time:

1. **Challenge-response**: Before accepting `POST /user/:userId/keys`, issue a server-generated nonce (stored server-side with a short TTL). Require the client to submit `{ publicKey, signature: sign(nonce, privateKey) }`. Verify the signature server-side using the Hedera SDK's `PublicKey.verify()` before persisting the key.

2. **Alternatively**, accept a signed attestation over a deterministic message (e.g., `"register:<userId>:<timestamp>"`) so no round-trip is needed, while still proving possession.

The front-end already has `verifyKeyPair` logic that confirms private-key/public-key correspondence locally: [8](#0-7) 

This check must be enforced server-side, not only client-side.

### Proof of Concept

**Setup**: Attacker has a valid account and JWT. Victim's Hedera public key `<VICTIM_PUBKEY>` is known (e.g., from on-chain data or a prior transaction).

**Step 1 — Attacker squats the key:**
```
POST /user/keys
Authorization: Bearer <ATTACKER_JWT>
Content-Type: application/json

{ "publicKey": "<VICTIM_PUBKEY>" }
```
Response: `201 Created` — key is now associated with the attacker's account.

**Step 2 — Victim attempts to register their own key:**
```
POST /user/keys
Authorization: Bearer <VICTIM_JWT>
Content-Type: application/json

{ "publicKey": "<VICTIM_PUBKEY>" }
```
Response: `400 Bad Request` with `ErrorCodes.PU` — registration permanently blocked.

**Step 3 — Victim cannot sign or be added as a signer/approver** on any transaction that requires `<VICTIM_PUBKEY>`, because the platform has no record of the victim owning it. Any such transaction is stalled indefinitely.

### Citations

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

**File:** back-end/apps/api/src/user-keys/dtos/upload-user-key.dto.ts (L1-22)
```typescript
import { IsDefined, IsNotEmpty, IsNumber, IsString, ValidateIf } from 'class-validator';
import { IsHederaPublicKey } from '@app/common/validators/is-hedera-public-key.validator';
import { NormalizePublicKey } from '@app/common/transformers/normalize-public-key.transform';

export class UploadUserKeyDto {
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
}
```

**File:** back-end/apps/api/src/user-keys/user-keys.controller.ts (L38-41)
```typescript
  @Post()
  uploadKey(@GetUser() user: User, @Body() body: UploadUserKeyDto): Promise<UserKey> {
    return this.userKeysService.uploadKey(user, body);
  }
```

**File:** back-end/libs/common/src/interceptors/only-owner-key.interceptor.ts (L36-39)
```typescript

      const userKeyIds = new Set(user.keys.map(key => key.id));
      if (!keyIdValues.every(keyId => userKeyIds.has(keyId))) {
        throw new BadRequestException(ErrorCodes.PNY);
```

**File:** back-end/apps/api/src/guards/has-key.guard.ts (L14-26)
```typescript
    let keysCount = 0;
    try {
      keysCount = await this.userKeysService.getUserKeysCount(req.user.id);
    } catch (error) {
      console.log(error);
      return false;
    }

    if (keysCount > 0) {
      return true;
    } else {
      throw new UnauthorizedException('You should have at least one key to perform this action.');
    }
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

**File:** front-end/src/renderer/services/keyPairService.ts (L251-275)
```typescript
export const verifyKeyPair = (
  publicKey: string | PublicKey,
  privateKey: string | PrivateKey,
): boolean => {
  try {
    const { publicKey: resolvedPublicKey, keyType } = getPublicKeyAndType(publicKey);

    if (typeof privateKey === 'string') {
      switch (keyType) {
        case KeyType.ECDSA:
          privateKey = PrivateKey.fromStringECDSA(privateKey);
          break;
        case KeyType.ED25519:
          privateKey = PrivateKey.fromStringED25519(privateKey);
          break;
        default:
          throw new Error('Invalid key type');
      }
    }

    return privateKey.publicKey.toString() === resolvedPublicKey.toString();
  } catch (error) {
    logger.error('Failed to verify key pair', { error });
    return false;
  }
```
