All cited code references are confirmed accurate. Here is the audit report:

---

Audit Report

## Title
Any Authenticated User Can Pre-Register Another User's Public Key, Permanently Blocking Their Key Registration (DoS)

## Summary
The `uploadKey` method in `UserKeysService` performs a global uniqueness lookup on `publicKey` across all users. Because any verified organization member can call the key-upload endpoint, an attacker can register a victim's public key under their own account before the victim does. Once claimed, every subsequent registration attempt by the legitimate owner throws a `BadRequestException`, permanently preventing them from linking their key to the platform — including after soft-deletion of the attacker's record.

## Finding Description
In `back-end/apps/api/src/user-keys/user-keys.service.ts`, `uploadKey` performs a global lookup by `publicKey` alone:

```typescript
let userKey = await this.repo.findOne({
  where: { publicKey: dto.publicKey },
  withDeleted: true,
});
``` [1](#0-0) 

If a record is found, ownership is checked:

```typescript
if (userKey.userId !== user.id || (userKey.index && userKey.index !== dto.index)) {
  throw new BadRequestException(ErrorCodes.PU);
}
``` [2](#0-1) 

The `UserKey` entity declares only a non-unique `@Index()` on `publicKey` — there is no database-level uniqueness constraint preventing two users from holding the same key: [3](#0-2) 

The endpoint is `POST /user/:userId?/keys`, guarded only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. Critically, the `user` object passed to `uploadKey` comes from `@GetUser()` (the JWT-authenticated caller), **not** from the `:userId` URL parameter — so any verified member can register any public key under their own account: [4](#0-3) 

The `withDeleted: true` flag means that even if the attacker's record is soft-deleted, it is still returned by `findOne`, and the ownership check still fires — making the block permanent: [5](#0-4) 

## Impact Explanation
A victim whose public key has been pre-claimed by an attacker:
- Cannot register their key with the organization server.
- Cannot be assigned as a transaction creator, signer, or approver — all of which require a valid `UserKey` record linked to their account.
- Is effectively locked out of all multi-signature workflows in Organization Mode.

The lock is permanent: the attacker's record persists (soft-delete only), and the `withDeleted: true` flag ensures the deleted record is still found and the same ownership check fires on every subsequent attempt by the victim. [6](#0-5) 

## Likelihood Explanation
- **Attacker precondition**: Must be a verified user on the same organization server — a low bar, as any existing member qualifies.
- **Information required**: The victim's public key — trivially obtained from any Hedera transaction the victim has signed, or from `GET /user/:userId/keys`, which returns `publicKey` for any user: [7](#0-6) 
- **Effort**: A single authenticated HTTP POST request.
- **No race condition required**: The attacker simply needs to act before the victim registers their key, which is trivial when targeting a newly invited user.

## Recommendation
1. **Scope the uniqueness check to the user**: Change the `findOne` query to filter by both `publicKey` and `userId`, so a key is only considered "already registered" if it belongs to the requesting user:
   ```typescript
   let userKey = await this.repo.findOne({
     where: { publicKey: dto.publicKey, userId: user.id },
     withDeleted: true,
   });
   ```
2. **Add a composite unique DB constraint**: Add a `@Index(['userId', 'publicKey'], { unique: true })` on the `UserKey` entity to enforce uniqueness at the database level, preventing the same user from registering the same key twice while allowing different users to hold the same key if the business logic permits it.
3. **Alternatively, enforce global uniqueness correctly**: If the intent is that a public key can only ever belong to one user globally, add a `unique: true` DB constraint on `publicKey` and document this as a design decision. The current state — no DB constraint but an application-layer check — is the worst of both worlds.

## Proof of Concept
```
# Step 1: Attacker (userId=2) observes victim's public key from GET /user/1/keys
GET /user/1/keys
# Response includes: { "publicKey": "e0c8ec2758a5879ffac226a13c0c516b799e72e35141a0dd828f94d37988a4b7", ... }

# Step 2: Attacker registers the victim's key under their own account
POST /user/keys
Authorization: Bearer <attacker_jwt>
Content-Type: application/json
{ "publicKey": "e0c8ec2758a5879ffac226a13c0c516b799e72e35141a0dd828f94d37988a4b7" }
# Response: 201 Created — key now stored with userId=2

# Step 3: Victim attempts to register their own key
POST /user/keys
Authorization: Bearer <victim_jwt>
Content-Type: application/json
{ "publicKey": "e0c8ec2758a5879ffac226a13c0c516b799e72e35141a0dd828f94d37988a4b7" }
# Response: 400 Bad Request — ErrorCodes.PU (key in use by different user)

# Step 4: Attacker soft-deletes their key — victim still blocked
DELETE /user/keys/<key_id>
Authorization: Bearer <attacker_jwt>
# Response: 200 OK

# Step 5: Victim retries — still blocked (withDeleted: true finds the soft-deleted record)
POST /user/keys
Authorization: Bearer <victim_jwt>
{ "publicKey": "e0c8ec2758a5879ffac226a13c0c516b799e72e35141a0dd828f94d37988a4b7" }
# Response: 400 Bad Request — ErrorCodes.PU (permanent block)
``` [8](#0-7)

### Citations

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

**File:** back-end/libs/common/src/database/entities/user-key.entity.ts (L34-36)
```typescript
  @Column({ length: 128 })
  @Index()
  publicKey: string;
```

**File:** back-end/apps/api/src/user-keys/user-keys.controller.ts (L25-41)
```typescript
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
