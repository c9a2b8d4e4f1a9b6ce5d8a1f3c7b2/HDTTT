### Title
Any Authenticated User Can Squat Another User's Public Key, Permanently Blocking Them From the Organization Signing Workflow

### Summary
The `uploadKey` endpoint (`POST /user/:userId/keys`) in the organization backend accepts a raw `publicKey` value and registers it under the authenticated caller's account with no cryptographic proof that the caller controls the corresponding private key. Because the uniqueness constraint on `publicKey` is enforced globally, any authenticated user who registers a victim's public key first permanently prevents the victim from registering that key under their own account, locking them out of the multi-signature transaction workflow.

### Finding Description

**Root cause**

`UploadUserKeyDto` accepts only `publicKey`, `mnemonicHash`, and `index`. No challenge-response or signature-over-identity is required. [1](#0-0) 

`UserKeysService.uploadKey()` looks up the submitted `publicKey` in the database. If it is already owned by a different user, it throws `ErrorCodes.PU` and returns 400. If it is not yet registered, it creates a new `UserKey` record owned by the **caller**, not the key's true owner. [2](#0-1) 

**Exploit flow**

1. Victim generates an ED25519 key pair `(privKey_V, pubKey_V)`. The public key is visible on the Hedera network (e.g., embedded in any transaction the victim has signed or in their account info on the mirror node).
2. Attacker (any verified organization user) calls `POST /user/<any_id>/keys` with `{ "publicKey": "<pubKey_V>" }`. The `:userId` path parameter is ignored — the controller always uses the JWT-authenticated caller's identity.
3. The server creates a `UserKey` row linking `pubKey_V` to the attacker's `userId`.
4. Victim later calls `POST /user/<victim_id>/keys` with `{ "publicKey": "<pubKey_V>" }`. The service finds the existing row, sees `userKey.userId !== user.id`, and throws `BadRequestException(ErrorCodes.PU)`.
5. The victim is permanently blocked from registering their own key.

The e2e test suite explicitly confirms this blocking behavior: [3](#0-2) 

**Why the `:userId` path parameter does not help**

The controller route is `@Controller('user/:userId?/keys')` but the `uploadKey` handler uses `@GetUser()` (the JWT-authenticated user), not the path parameter. The e2e test at line 78–92 explicitly verifies that "whatever user id is passed" the key is always registered to the authenticated caller. [4](#0-3) [5](#0-4) 

### Impact Explanation

Once the attacker squats the victim's public key:

- **Permanent DoS on key registration**: The victim can never register `pubKey_V` under their own account. The only recovery path would require an admin to manually delete the attacker's `UserKey` row.
- **Exclusion from multi-sig workflows**: `SignersService.validateAndProcessSignatures` builds `userKeyMap` from the authenticated submitter's registered keys. Because the victim's key is not in their own key map, the victim cannot submit signatures for transactions that require `pubKey_V`, even though they hold the private key. [6](#0-5) [7](#0-6) 

- **Organizational integrity break**: The `UserKey` entity is the authoritative link between a Hedera public key and an organization user. Squatting corrupts this mapping, causing the system to attribute signing authority to the wrong user. [8](#0-7) 

### Likelihood Explanation

- **Attacker precondition**: Any verified organization account. No admin or privileged role required.
- **Information required**: The victim's public key — which is inherently public. It appears in Hedera transaction bytes, mirror node account queries, and is shared during normal multi-sig coordination.
- **Attack complexity**: A single authenticated HTTP POST. No race condition or timing dependency is required; the attacker simply needs to register the key before the victim does.
- **Detection difficulty**: The attack is indistinguishable from a normal key upload at the API level.

### Recommendation

Require the caller to prove possession of the private key before registering a public key. The standard approach is a **challenge-response**:

1. The server issues a short-lived, user-bound challenge (e.g., `HMAC(userId || timestamp || nonce)`).
2. The client signs the challenge with the private key.
3. The `uploadKey` endpoint accepts the signature alongside the `publicKey` and verifies it with `PublicKey.verify(challenge, signature)` before persisting the record.

This ensures that only the holder of the private key can register the corresponding public key, mirroring the fix applied in the referenced Augur PR #5564 (binding the signed payload to the intended account).

### Proof of Concept

```
# Step 1 – Attacker learns victim's public key (from mirror node, shared transaction, etc.)
VICTIM_PUBKEY="e0c8ec2758a5879ffac226a13c0c516b799e72e35141a0dd828f94d37988a4b7"

# Step 2 – Attacker (authenticated as attacker_token) squats the key
curl -X POST https://<org-server>/user/1/keys \
  -H "Authorization: Bearer <attacker_token>" \
  -H "Content-Type: application/json" \
  -d '{"publicKey": "'$VICTIM_PUBKEY'"}'
# → 201 Created  (key now owned by attacker)

# Step 3 – Victim tries to register their own key
curl -X POST https://<org-server>/user/2/keys \
  -H "Authorization: Bearer <victim_token>" \
  -H "Content-Type: application/json" \
  -d '{"publicKey": "'$VICTIM_PUBKEY'"}'
# → 400 Bad Request: "PU" (Public key in use)
# Victim is permanently locked out of the organization signing workflow.
```

### Citations

**File:** back-end/apps/api/src/user-keys/dtos/upload-user-key.dto.ts (L5-22)
```typescript
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

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L42-65)
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

    if (userKey.deletedAt) {
      await this.repo.recover(userKey);
    }
    return this.repo.save(userKey);
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

**File:** back-end/apps/api/test/spec/user-keys.e2e-spec.ts (L180-190)
```typescript
    it('(POST) should not be able to upload key already added key by other user', async () => {
      const { mnemonicHash, publicKeyRaw, index } = await generatePrivateKey();

      await endpoint
        .post({ mnemonicHash, publicKey: publicKeyRaw, index }, '/2/keys', userAuthToken)
        .expect(201);

      await endpoint
        .post({ mnemonicHash, publicKey: publicKeyRaw, index }, '/2/keys', adminAuthToken)
        .expect(400);
    });
```

**File:** back-end/apps/api/src/user-keys/user-keys.controller.ts (L38-41)
```typescript
  @Post()
  uploadKey(@GetUser() user: User, @Body() body: UploadUserKeyDto): Promise<UserKey> {
    return this.userKeysService.uploadKey(user, body);
  }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L162-165)
```typescript
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

**File:** back-end/libs/common/src/database/entities/user-key.entity.ts (L17-48)
```typescript
export class UserKey {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => User, user => user.keys)
  @JoinColumn({ name: 'userId' })
  user: User;

  @Column()
  userId: number;

  @Column({ nullable: true })
  mnemonicHash: string;

  @Column({ nullable: true })
  index: number;

  @Column({ length: 128 })
  @Index()
  publicKey: string;

  @DeleteDateColumn()
  deletedAt: Date;

  @OneToMany(() => Transaction, transaction => transaction.creatorKey)
  createdTransactions: Transaction[];

  @OneToMany(() => TransactionApprover, approver => approver.userKey)
  approvedTransactions: TransactionApprover[];

  @OneToMany(() => TransactionSigner, signer => signer.userKey)
  signedTransactions: TransactionSigner[];
```
