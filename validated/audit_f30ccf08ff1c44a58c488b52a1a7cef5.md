All claims in the report are verified against the actual code. Here is the audit output:

---

Audit Report

## Title
Any Authenticated User Can Register Any Public Key Without Proof-of-Ownership, Blocking Legitimate Key Registration

## Summary
The `uploadKey` endpoint accepts any syntactically valid Hedera public key and registers it under the JWT-authenticated caller's account with no cryptographic proof that the caller controls the corresponding private key. Because the system enforces a one-owner-per-public-key constraint, an attacker who registers a victim's public key first permanently blocks the victim from registering that key.

## Finding Description

**Root cause:** `UploadUserKeyDto` applies only a syntactic validity check (`@IsHederaPublicKey()`) on the submitted public key string. No challenge-response, nonce signature, or any other proof-of-possession is required. [1](#0-0) 

The `uploadKey` service method looks up whether the public key already exists. If it does **not** exist, it creates a new `UserKey` record owned by the JWT-authenticated caller with no further checks: [2](#0-1) 

The ownership guard (`userKey.userId !== user.id`) only fires when the key is **already registered**. If the key is unregistered, the caller becomes the owner unconditionally: [3](#0-2) 

The `userId` path parameter in `POST /user/:userId/keys` is completely ignored by the controller — the key is always registered to the JWT-authenticated caller regardless of what `userId` value is supplied: [4](#0-3) 

The e2e test suite explicitly confirms this behavior — arbitrary user IDs (`123123123`, `5134`) are passed in the URL, yet the key is always registered to the authenticated user: [5](#0-4) 

**Exploit path:**
1. Attacker (any verified org member) observes a victim's Hedera public key (visible on the mirror node, in transaction bytes, or via `GET /users/public-owner/:publicKey`).
2. Attacker calls `POST /user/<any-id>/keys` with `{ "publicKey": "<victim_public_key>" }`.
3. The victim's public key is now stored in `user_key` with `userId = attacker_id`.
4. When the victim later tries to register their own key, the service finds the existing record, sees `userKey.userId !== user.id`, and throws `ErrorCodes.PU`. The victim is permanently blocked.

## Impact Explanation

1. **Denial of Service on key registration:** The victim can never register their own public key in the organization. Any workflow requiring `creatorKeyId` to reference a key owned by the submitting user is broken for the victim.

2. **Key registry corruption:** The `GET /users/public-owner/:publicKey` endpoint returns the attacker's email as the owner of the victim's public key, breaking the trust model other users rely on to verify key ownership. [6](#0-5) 

3. **Signing workflow disruption:** `keysRequiredToSign` resolves `UserKey` records by public key string to determine who must sign a transaction. With the attacker registered as owner of the victim's key, signing notifications and routing are directed to the wrong account. [7](#0-6) 

Note: The attacker cannot forge signatures (they lack the private key), so they cannot create or sign transactions on the victim's behalf. The impact is DoS and registry integrity, not direct fund theft.

## Likelihood Explanation

- **Attacker precondition:** Any verified organization member. No admin or privileged role required.
- **Key discoverability:** Hedera public keys are public by definition — visible on the mirror node, in transaction bytes, and via the organization's own `GET /users/public-owner/:publicKey` API.
- **Effort:** A single authenticated HTTP POST. No race condition or timing dependency required; the attacker simply needs to act before the victim registers their key.
- **Scalability:** An attacker can pre-register all public keys they observe, blocking multiple victims simultaneously.

## Recommendation

Implement a proof-of-possession challenge before accepting a public key registration:

1. **Challenge-response:** Issue a server-generated nonce to the client. Require the client to sign the nonce with the private key corresponding to the submitted public key, and verify the signature server-side before creating the `UserKey` record.
2. **Alternatively**, restrict key registration so that a user can only register keys that are associated with their own Hedera account (verified via mirror node lookup), though this is weaker than a direct signature check.
3. Remove or deprecate the `userId` path parameter from `POST /user/:userId/keys` since it is silently ignored, which is misleading and could cause confusion.

## Proof of Concept

```
# Step 1: Attacker (authenticated as attacker@org.com) registers victim's known public key
POST /user/1/keys
Authorization: Bearer <attacker_jwt>
Content-Type: application/json

{
  "publicKey": "<victim_hedera_public_key>"
}
# Response: 201 Created — key is now owned by attacker

# Step 2: Victim attempts to register their own key
POST /user/2/keys
Authorization: Bearer <victim_jwt>
Content-Type: application/json

{
  "publicKey": "<victim_hedera_public_key>"
}
# Response: 400 Bad Request — ErrorCodes.PU ("Public key already in use")
# Victim is permanently blocked from registering their own key.

# Step 3: Verify registry corruption
GET /users/public-owner/<victim_hedera_public_key>
Authorization: Bearer <any_jwt>
# Response: "attacker@org.com"  ← attacker's email returned as owner of victim's key
```

### Citations

**File:** back-end/apps/api/src/user-keys/dtos/upload-user-key.dto.ts (L18-21)
```typescript
  @IsNotEmpty()
  @IsHederaPublicKey()
  @NormalizePublicKey()
  publicKey: string;
```

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L42-60)
```typescript
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
```

**File:** back-end/apps/api/src/user-keys/user-keys.controller.ts (L38-41)
```typescript
  @Post()
  uploadKey(@GetUser() user: User, @Body() body: UploadUserKeyDto): Promise<UserKey> {
    return this.userKeysService.uploadKey(user, body);
  }
```

**File:** back-end/apps/api/test/spec/user-keys.e2e-spec.ts (L78-92)
```typescript
    it('(POST) should upload your key if verified whatever user id is passed', async () => {
      const { mnemonicHash, publicKeyRaw, index } = await generatePrivateKey();

      await endpoint
        .post({ mnemonicHash, publicKey: publicKeyRaw, index }, '/123123123/keys', userAuthToken)
        .expect(201);

      const { publicKeyRaw: publicKeyRaw2 } = await generatePrivateKey();

      await endpoint.post({ publicKey: publicKeyRaw2 }, '/5134/keys', userAuthToken).expect(201);

      const actualUserKeys = await getUserKeys(user.id);

      expect(actualUserKeys).toHaveLength(3); // 2 keys + 1 default key
    });
```

**File:** back-end/apps/api/src/users/users.service.ts (L118-124)
```typescript
  async getOwnerOfPublicKey(publicKey: string): Promise<string | null> {
    const existingUser = await this.repo.findOne({
      where: { keys: { publicKey } },
      relations: ['keys'],
    });
    return existingUser ? existingUser.email : null;
  }
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L86-90)
```typescript
      results = await entityManager.find(UserKey, {
        where: { publicKey: In(flatPublicKeys) },
        relations: ['user'],
      });
    }
```
