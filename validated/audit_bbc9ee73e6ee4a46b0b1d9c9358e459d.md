### Title
Any Authenticated User Can Pre-Register Another User's Public Key, Permanently Blocking Their Key Registration (DoS)

### Summary
The `uploadKey` function in `UserKeysService` enforces a global uniqueness constraint on `publicKey` across all users. Because public keys are observable on the Hedera network, any authenticated organization member can register a victim's public key under their own account before the victim does. Once claimed, the legitimate owner receives a `BadRequestException` on every subsequent registration attempt, permanently preventing them from linking their key to the platform.

### Finding Description
In `back-end/apps/api/src/user-keys/user-keys.service.ts`, the `uploadKey` method performs a global lookup by `publicKey` alone:

```typescript
// line 42-45
let userKey = await this.repo.findOne({
  where: { publicKey: dto.publicKey },
  withDeleted: true,
});
```

If a record is found, ownership is checked at line 52:

```typescript
if (userKey.userId !== user.id || (userKey.index && userKey.index !== dto.index)) {
  throw new BadRequestException(ErrorCodes.PU);
}
```

The endpoint is `POST /user/:userId/keys`, guarded only by `JwtAuthGuard` and `VerifiedUserGuard` — any verified organization member can call it.

**Exploit path:**
1. Attacker registers an account on the organization server (or is already a member).
2. Attacker observes the victim's ED25519/ECDSA public key — it is visible on the Hedera network in any transaction the victim has signed, or via the organization's user-key listing endpoint (`GET /user/:userId/keys`).
3. Attacker calls `POST /user/<attacker_id>/keys` with `{ publicKey: <victim_public_key> }`.
4. The key is now stored with `userId = attacker_id`.
5. Victim calls `POST /user/<victim_id>/keys` with the same `publicKey`.
6. `userKey.userId` (attacker) ≠ `user.id` (victim) → `BadRequestException(ErrorCodes.PU)` is thrown every time.
7. Victim can never register their key.

The `UserKey` entity has no unique DB constraint on `publicKey` alone (only an `@Index()`), so the application-layer check at line 52 is the sole gatekeeper — and it is bypassable by whoever registers first. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
A victim whose public key has been pre-claimed by an attacker:
- Cannot register their key with the organization server.
- Cannot be assigned as a transaction signer, approver, or creator — all of which require a valid `UserKey` record linked to their account.
- Is effectively locked out of all multi-signature workflows in Organization Mode.

The lock is permanent: the attacker's record persists (soft-delete only), and even after soft-deletion the `withDeleted: true` flag on line 44 means the deleted record is still found and the same ownership check fires. [4](#0-3) [5](#0-4) 

### Likelihood Explanation
- **Attacker precondition**: Must be a verified user on the same organization server — a low bar, as user registration is admin-controlled but any existing member qualifies.
- **Information required**: The victim's public key — trivially obtained from any Hedera transaction the victim has signed, or from `GET /user/:userId/keys` which returns public keys of other users.
- **Effort**: A single authenticated HTTP POST request.
- **No race condition required**: The attacker simply needs to act before the victim registers their key, which is easy when targeting a newly invited user. [6](#0-5) [7](#0-6) 

### Recommendation
Bind the uniqueness check to the requesting user's identity. The simplest fix is to include `userId` in the lookup so that the same public key can only conflict within the same user's scope:

```typescript
let userKey = await this.repo.findOne({
  where: { publicKey: dto.publicKey, userId: user.id },
  withDeleted: true,
});
```

If the business requirement is that a public key must be globally unique across all users (e.g., to prevent key sharing), then the error message must not be surfaced to the requester in a way that confirms the key is registered to someone else, and the design must accept that any user can be DoS'd by a malicious peer. In that case, the correct fix is to require cryptographic proof of key ownership (e.g., a signature over a server-issued challenge) before accepting a key registration.

### Proof of Concept

**Setup**: Two accounts exist — `attacker@org.com` (userId=2) and `victim@org.com` (userId=3). The victim has an ED25519 key pair with public key `302a300506032b6570032100<victim_pubkey_hex>`.

**Step 1 — Attacker observes victim's public key** (from Hedera Mirror Node or `GET /user/3/keys`).

**Step 2 — Attacker pre-registers the key**:
```http
POST /user/2/keys HTTP/1.1
Authorization: Bearer <attacker_jwt>
Content-Type: application/json

{
  "publicKey": "302a300506032b6570032100<victim_pubkey_hex>"
}
```
Response: `201 Created` — key stored with `userId=2`.

**Step 3 — Victim attempts to register their own key**:
```http
POST /user/3/keys HTTP/1.1
Authorization: Bearer <victim_jwt>
Content-Type: application/json

{
  "publicKey": "302a300506032b6570032100<victim_pubkey_hex>"
}
```
Response: `400 Bad Request` — `ErrorCodes.PU` — every subsequent attempt returns the same error.

**Expected outcome**: Victim is permanently unable to register their key and cannot participate in any organization transaction workflow. [8](#0-7)

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

**File:** back-end/libs/common/src/database/entities/user-key.entity.ts (L34-36)
```typescript
  @Column({ length: 128 })
  @Index()
  publicKey: string;
```

**File:** back-end/apps/api/src/user-keys/user-keys.controller.ts (L24-41)
```typescript
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
