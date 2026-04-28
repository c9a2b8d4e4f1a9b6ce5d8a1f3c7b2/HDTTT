All code references check out. The vulnerability is real and in scope. Here is the audit report:

---

Audit Report

## Title
Unauthenticated Public Key Squatting Enables Permanent DoS on Organization Signing Flow

## Summary
Any verified organization member can register an arbitrary Hedera public key — including one belonging to another user — without proving ownership of the corresponding private key. Because the registration endpoint enforces a first-write-wins uniqueness constraint with no proof-of-possession, an attacker who registers a victim's public key first permanently blocks the victim from registering it. The victim is subsequently unable to use the normal `uploadSignatureMaps` signing flow for any transaction requiring that key.

## Finding Description

**Root cause — `uploadKey` in `back-end/apps/api/src/user-keys/user-keys.service.ts`:**

The function accepts any syntactically valid Hedera public key string (`dto.publicKey`) and registers it under the authenticated user with no cryptographic proof of ownership: [1](#0-0) 

The only ownership check is at line 52:

```ts
if (userKey.userId !== user.id || (userKey.index && userKey.index !== dto.index)) {
  throw new BadRequestException(ErrorCodes.PU);
}
``` [2](#0-1) 

This check only prevents a *different* user from claiming a key that is **already registered**. It does not require the registering user to prove they hold the corresponding private key (e.g., via a cryptographic challenge-response / sign-over-nonce). There is no proof-of-possession mechanism anywhere in the registration flow.

**The DTO accepts any valid public key with no ownership proof:** [3](#0-2) 

**Exploit path:**

1. Attacker (a verified org member) obtains the victim's public key. Public keys are trivially discoverable: `getUserKeysRestricted` returns them for any verified member via `GET /user/:id/keys`, and they are visible on the Hedera mirror node for any account ID. [4](#0-3) 

2. Attacker calls `POST /user/keys` with `{ publicKey: <victim_public_key> }` before the victim does. The key is registered under the attacker's account.

3. Victim later tries to register the same key. The service finds it already exists with `userId !== victim.id` and throws `ErrorCodes.PU` ("Public key already used"). [5](#0-4) 

4. When the victim tries to sign a transaction via `uploadSignatureMaps`, the service builds `userKeyMap` exclusively from the victim's registered keys: [6](#0-5) 

Since the victim's actual public key is not in their registered keys (it is registered to the attacker), the lookup fails and throws `ErrorCodes.PNY` ("Provided key/s not yours"): [7](#0-6) 

5. The attacker cannot produce a valid signature for the squatted key (no private key), so any transaction requiring the victim's key signature is permanently stalled in `WAITING_FOR_SIGNATURES`.

**The e2e test confirms any verified user can register any key:** [8](#0-7) 

## Impact Explanation
A malicious verified organization member can permanently block any other member from registering their public key. Any transaction that requires the victim's key signature will be stuck in `WAITING_FOR_SIGNATURES` indefinitely (until expiry). For organizations managing critical Hedera accounts (system file updates, account key rotations, large transfers), this is a permanent DoS on the signing workflow. The `importSignatures` endpoint offers a partial workaround (offline signing), but the `TransactionSigner` record is never created for the victim, and the normal notification/status-update flow is broken.

## Likelihood Explanation
The attacker only needs to be a verified organization member — a realistic baseline for a malicious insider. Public keys are not secret: they are returned by the organization's own API (`GET /user/:id/keys`) and are visible on the Hedera mirror node for any account ID. The attack requires a single API call before the victim registers their key, which is trivially achievable.

## Recommendation
Implement a **proof-of-possession** mechanism for public key registration:

1. **Challenge-response**: Before accepting a `POST /user/keys` request, issue a server-generated nonce tied to the session. Require the client to submit a signature over that nonce using the private key corresponding to the public key being registered. Verify the signature server-side before persisting the key.
2. **Alternatively**: Allow a user to "reclaim" a key registered by another user if they can demonstrate ownership via the same challenge-response mechanism, overwriting the squatted registration.

This mirrors standard proof-of-possession patterns used in certificate issuance (e.g., ACME protocol challenges) and eliminates the first-write-wins attack surface entirely.

## Proof of Concept

```
# Step 1: Attacker obtains victim's public key
GET /user/<victim_id>/keys
Authorization: Bearer <attacker_token>
# Response includes victim's publicKey, e.g. "e0c8ec2758a5879ffac226a13c0c516b799e72e35141a0dd828f94d37988a4b7"

# Step 2: Attacker squats the key
POST /user/keys
Authorization: Bearer <attacker_token>
Content-Type: application/json
{ "publicKey": "e0c8ec2758a5879ffac226a13c0c516b799e72e35141a0dd828f94d37988a4b7" }
# Response: 201 Created — key now registered under attacker's userId

# Step 3: Victim attempts to register their own key
POST /user/keys
Authorization: Bearer <victim_token>
Content-Type: application/json
{ "publicKey": "e0c8ec2758a5879ffac226a13c0c516b799e72e35141a0dd828f94d37988a4b7" }
# Response: 400 Bad Request — ErrorCodes.PU ("Public key already used")

# Step 4: Victim attempts to sign a transaction
POST /transactions/<tx_id>/signers
Authorization: Bearer <victim_token>
Content-Type: application/json
{ "id": <tx_id>, "signatureMap": { ... signed with victim's private key ... } }
# Response: Error — ErrorCodes.PNY ("Provided key/s not yours")
# Because victim's public key is not in their registered keys → userKeyMap lookup fails
``` [9](#0-8) [10](#0-9)

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

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L69-81)
```typescript
  async getUserKeysRestricted(user: User, userId: number): Promise<UserKey[]> {
    if (!userId) return [];
    return this.repo.find({
      where: { userId },
      select: {
        id: true,
        userId: true,
        mnemonicHash: user.id === userId,
        index: user.id === userId,
        publicKey: true,
      },
    });
  }
```

**File:** back-end/apps/api/src/user-keys/dtos/upload-user-key.dto.ts (L18-21)
```typescript
  @IsNotEmpty()
  @IsHederaPublicKey()
  @NormalizePublicKey()
  publicKey: string;
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L162-165)
```typescript
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
