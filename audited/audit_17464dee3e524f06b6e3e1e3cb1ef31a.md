### Title
Missing Proof-of-Private-Key-Ownership on Public Key Registration Allows Key Squatting and Signing Workflow Disruption

### Summary
Any authenticated, verified organization member can register an arbitrary Hedera public key as their own via `POST /user/:userId?/keys` without providing any cryptographic proof that they hold the corresponding private key. This is the direct analog of the external report: the external snap required a front-end signature check that the backend did not enforce; here, no ownership proof is required at any layer at all.

### Finding Description
The `uploadKey` method in `back-end/apps/api/src/user-keys/user-keys.service.ts` accepts a `publicKey` field from the request body, checks only that the key is not already claimed by a *different* user, and then permanently associates it with the authenticated user's account. [1](#0-0) 

The `UploadUserKeyDto` validates only that the submitted value is a well-formed Hedera public key; it requires no signature, no challenge-response, and no proof that the submitter controls the corresponding private key. [2](#0-1) 

The controller exposes this endpoint to every `VerifiedUser` (JWT-authenticated, email-verified member): [3](#0-2) 

An attacker can discover target public keys trivially: the `GET /user/:userId/keys` endpoint returns the `publicKey` field for any user in the organization to any verified member. [4](#0-3) 

Once a key is registered by the attacker, the legitimate owner's subsequent registration attempt is rejected with `ErrorCodes.PU` ("Public key in use"): [5](#0-4) 

The e2e test suite itself documents that the `userId` path parameter is completely ignored — the key is always bound to the JWT-authenticated caller, regardless of what `userId` is supplied — confirming that the only binding is the JWT identity, not any proof of key ownership: [6](#0-5) 

### Impact Explanation
`UserKey` records are the authoritative source for the entire signing and notification pipeline:

- `keysRequiredToSign` resolves which users must sign a transaction by looking up `UserKey` rows matching the required public keys. [7](#0-6) 

- The notifications service uses the same `UserKey`-to-user mapping to determine who receives signing notifications. [8](#0-7) 

Concrete consequences of key squatting:

1. **Denial of Service against the legitimate key owner**: The legitimate owner can never register their own key; every attempt returns `ErrorCodes.PU`. They cannot participate in any organization signing workflow that requires that key.
2. **Notification hijacking**: The attacker receives all signing-request notifications intended for the legitimate key owner.
3. **Signing workflow stall**: The system marks the attacker as a required signer. The attacker cannot produce a valid signature (no private key), so the transaction can never reach the required signature threshold, permanently blocking execution.
4. **`creatorKey` impersonation**: If the squatted key is later used as a `creatorKeyId` in a transaction, the attacker's account becomes the recorded creator, affecting all creator-gated operations (cancel, modify approvers, etc.). [9](#0-8) 

### Likelihood Explanation
- **Attacker prerequisites**: Only a valid JWT (verified organization member). No admin role required.
- **Target key discovery**: Trivially achieved via `GET /user/:userId/keys`, which is accessible to all verified members and returns `publicKey` in plaintext.
- **Race condition**: The attacker must register the key before the legitimate owner. In practice, new organization members are invited and their keys are uploaded during onboarding — a window the attacker can exploit by observing the invitation flow or the mirror node.
- **No detection**: The legitimate owner receives no notification that their key was claimed by someone else.

### Recommendation
Require cryptographic proof of private-key possession before accepting a key registration. The standard approach is a **challenge-response**:

1. The server issues a short-lived, user-specific nonce (e.g., stored in Redis with a TTL).
2. The client signs the nonce with the private key corresponding to the public key being registered.
3. The server verifies the signature using the submitted public key before persisting the `UserKey` record.

This mirrors the fix suggested in the external report (moving ownership proof into the trusted execution context) and is consistent with how the transaction-creation endpoint already verifies the creator's signature over the transaction bytes: [10](#0-9) 

The same `PublicKey.verify()` pattern should be applied to key registration.

### Proof of Concept

```
# Step 1 – Attacker logs in as a verified org member and obtains JWT
POST /auth/login  { "email": "attacker@org.com", "password": "..." }
→ { "accessToken": "<ATTACKER_JWT>" }

# Step 2 – Attacker enumerates victim's public keys
GET /user/2/keys
Authorization: Bearer <ATTACKER_JWT>
→ [ { "id": 5, "publicKey": "e0c8ec2758a5879ffac226a13c0c516b799e72e35141a0dd828f94d37988a4b7", ... } ]

# Step 3 – Attacker registers victim's public key as their own
POST /user/keys
Authorization: Bearer <ATTACKER_JWT>
Content-Type: application/json
{ "publicKey": "e0c8ec2758a5879ffac226a13c0c516b799e72e35141a0dd828f94d37988a4b7" }
→ 201 Created  { "id": 99, "userId": <ATTACKER_ID>, "publicKey": "e0c8ec..." }

# Step 4 – Victim attempts to register their own key
POST /user/keys
Authorization: Bearer <VICTIM_JWT>
{ "publicKey": "e0c8ec2758a5879ffac226a13c0c516b799e72e35141a0dd828f94d37988a4b7" }
→ 400 Bad Request  { "code": "PU" }   ← permanently locked out

# Step 5 – Any transaction requiring that key now routes signing notifications
#           to the attacker, and can never reach execution threshold.
```

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

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L68-81)
```typescript
  // Get the list of user keys for the provided userId
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

**File:** back-end/apps/api/src/user-keys/user-keys.controller.ts (L23-41)
```typescript
@ApiTags('User Keys')
@Controller('user/:userId?/keys')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
@Serialize(UserKeyDto)
export class UserKeysController {
  constructor(private userKeysService: UserKeysService) {}

  @ApiOperation({
    summary: 'Upload a user key',
    description: 'Upload a user key for the current user.',
  })
  @ApiResponse({
    status: 201,
    type: UserKeyDto,
  })
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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L49-91)
```typescript
  if (userKeys) {
    results = userKeys.filter(publicKey =>
        flatPublicKeys.includes(publicKey.publicKey)
    );
  } else {
    if (cache) {
      const cachedKeys: Set<UserKey> = new Set();
      const missingPublicKeys: Set<string> = new Set();

      for (const publicKey of flatPublicKeys) {
        const cached = cache.get(publicKey);
        if (cached) {
          cachedKeys.add(cached);
        } else {
          missingPublicKeys.add(publicKey);
        }
      }

      let fetchedKeys: UserKey[] = [];
      if (missingPublicKeys.size > 0) {
        try {
          fetchedKeys = await entityManager.find(UserKey, {
            where: { publicKey: In([...missingPublicKeys]) },
            relations: ['user'],
          });
          // Store fetched keys in cache
          for (const key of fetchedKeys) {
            cache.set(key.publicKey, key);
          }
        } catch (error) {
          console.error('Error fetching missing user keys:', error);
          throw error;
        }
      }

      results = [...cachedKeys, ...fetchedKeys];
    } else {
      results = await entityManager.find(UserKey, {
        where: { publicKey: In(flatPublicKeys) },
        relations: ['user'],
      });
    }
  }
```

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L130-167)
```typescript
  // --- Participant / recipient resolution -------------------------------

  private async getTransactionParticipants(
    entityManager: EntityManager,
    transaction: Transaction,
    approvers: TransactionApprover[],
    keyCache: Map<string, UserKey>,
  ) {
    // If the creatorKey is deleted, it will not be included
    const creatorId = transaction.creatorKey?.userId;
    const signerUserIds = transaction.signers.map(s => s.userId);
    const observerUserIds = transaction.observers.map(o => o.userId);
    const requiredUserIds = await this.getUsersIdsRequiredToSign(entityManager, transaction, keyCache);

    const approversUserIds = approvers.map(a => a.userId);
    const approversGaveChoiceUserIds = approvers
      .filter(a => a.approved !== null)
      .map(a => a.userId)
      .filter(Boolean);
    const approversShouldChooseUserIds = [
      TransactionStatus.WAITING_FOR_EXECUTION,
      TransactionStatus.WAITING_FOR_SIGNATURES,
    ].includes(transaction.status)
      ? approvers
        .filter(a => a.approved === null)
        .map(a => a.userId)
        .filter(Boolean)
      : [];

    const participants = [
      ...new Set([
        creatorId,
        ...signerUserIds,
        ...observerUserIds,
        ...approversUserIds,
        ...requiredUserIds,
      ].filter(Boolean)),
    ];
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L623-644)
```typescript
  /* Get the transaction by id and verifies that the user is the creator */
  async getCreatorsTransaction(
    transactionId: number,
    user: User,
    entityManager?: EntityManager,
  ): Promise<Transaction> {
    const find: FindOneOptions<Transaction> = {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user'],
    };

    const transaction = await (entityManager
      ? entityManager.findOne(Transaction, find)
      : this.dataSource.manager.findOne(Transaction, find));

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to modify it');

    return transaction;
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L907-913)
```typescript
    const publicKey = PublicKey.fromString(creatorKey.publicKey);

    // Verify signature
    const validSignature = publicKey.verify(dto.transactionBytes, dto.signature);
    if (!validSignature) {
      throw new BadRequestException(ErrorCodes.SNMP);
    }
```
