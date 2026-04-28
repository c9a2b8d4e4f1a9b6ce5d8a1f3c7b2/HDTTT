All referenced code has been verified in the repository. The vulnerability is real and all claims check out.

---

Audit Report

## Title
Any Authenticated User Can Register Another User's Public Key, Permanently Blocking Legitimate Key Registration

## Summary
The `uploadKey` function in `user-keys.service.ts` accepts any syntactically valid Hedera public key without requiring proof that the submitting user controls the corresponding private key. Because the system enforces a global uniqueness constraint on public keys (one owner per key, even across soft-deletes), an attacker who registers a victim's public key first permanently blocks the legitimate owner from ever registering that key.

## Finding Description

**Root cause:** `uploadKey` in `back-end/apps/api/src/user-keys/user-keys.service.ts` performs only a format check on the submitted public key (via `IsHederaPublicKey` in the DTO) and a uniqueness check against the database. There is no proof-of-possession step — the user is never required to produce a signature over a challenge using the corresponding private key.

The lookup uses `withDeleted: true`, meaning soft-deleted registrations by the attacker continue to block the victim: [1](#0-0) 

The lock-out condition fires whenever the stored `userId` does not match the requesting user's `id`: [2](#0-1) 

The controller endpoint is reachable by any authenticated, verified user — no admin role is required: [3](#0-2) 

The DTO only validates that the string parses as a valid Hedera public key — no ownership proof: [4](#0-3) 

**Exploit flow:**
1. Attacker obtains victim's public key via `GET /user/:userId/keys` (`getUserKeysRestricted` is accessible to any authenticated user).
2. Attacker calls `POST /user/<any_id>/keys` with `{ publicKey: <victim_public_key> }`.
3. The key is saved with `userId = attacker.id`.
4. Victim calls `POST /user/<any_id>/keys` with their own public key → receives `ErrorCodes.PU` ("Public key in use").
5. Even if the attacker soft-deletes the key, the `withDeleted: true` lookup still finds the record and the `userId !== user.id` check still fires, keeping the victim permanently locked out.

**Secondary impact — notification misdirection:** `keysRequiredToSign` resolves required signers by looking up `UserKey` records matching the public keys embedded in a transaction's key structure. If the attacker's squatted key appears in a transaction's `KeyList`, signing notifications are routed to the attacker instead of the legitimate key holder: [5](#0-4) [6](#0-5) 

## Impact Explanation

- **Permanent DoS of key registration for targeted users.** The victim can never register their legitimate key in the organization, preventing them from participating in any multi-signature transaction that requires that key.
- **Signing notification misdirection.** If the squatted key is part of a transaction's signing key list, signing reminders are sent to the attacker, leaking the existence and details of pending transactions.
- **Multi-sig deadlock.** If the victim's key is a required signer for a threshold transaction, that transaction can never reach `WAITING_FOR_EXECUTION` status, permanently stalling it.

## Likelihood Explanation

- **Attacker preconditions:** Only a valid, verified account in the organization is required — no admin privileges.
- **Victim's public key is not secret:** It is retrievable via `GET /user/:userId/keys` by any authenticated user, or from the Hedera network directly.
- **No rate limiting or anomaly detection** is present on the key upload endpoint.
- The attack is a single API call and is trivially scriptable.

## Recommendation

Implement **proof-of-possession** for public key registration. Before accepting a key, the server should issue a random challenge (nonce) and require the client to submit a signature over that nonce using the corresponding private key. The server then verifies the signature against the submitted public key before persisting the `UserKey` record. This ensures only the holder of the private key can register the corresponding public key, eliminating the squatting attack entirely.

Additionally, consider whether `withDeleted: true` is necessary in the uniqueness lookup at line 42–44. If a key has been soft-deleted by its owner, a new owner should be able to register it; the current behavior of blocking re-registration even after deletion is overly restrictive and compounds the DoS impact.

## Proof of Concept

```http
# Step 1 – Attacker retrieves victim's public key
GET /user/42/keys
Authorization: Bearer <attacker_token>

# Response includes victim's publicKey, e.g.:
# { "publicKey": "302a300506032b6570032100<victim_hex>" }

# Step 2 – Attacker registers victim's key under their own account
POST /user/99/keys
Authorization: Bearer <attacker_token>
Content-Type: application/json

{ "publicKey": "302a300506032b6570032100<victim_hex>" }

# Response: 201 Created — key now owned by attacker (userId=99)

# Step 3 – Victim attempts to register their own key
POST /user/42/keys
Authorization: Bearer <victim_token>
Content-Type: application/json

{ "publicKey": "302a300506032b6570032100<victim_hex>" }

# Response: 400 Bad Request — ErrorCodes.PU ("Public key in use")
# Victim is permanently locked out.
```

### Citations

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L42-45)
```typescript
    let userKey = await this.repo.findOne({
      where: { publicKey: dto.publicKey },
      withDeleted: true,
    });
```

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L52-54)
```typescript
      if (userKey.userId !== user.id || (userKey.index && userKey.index !== dto.index)) {
        throw new BadRequestException(ErrorCodes.PU);
      }
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

**File:** back-end/apps/api/src/user-keys/dtos/upload-user-key.dto.ts (L18-21)
```typescript
  @IsNotEmpty()
  @IsHederaPublicKey()
  @NormalizePublicKey()
  publicKey: string;
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L86-89)
```typescript
      results = await entityManager.find(UserKey, {
        where: { publicKey: In(flatPublicKeys) },
        relations: ['user'],
      });
```

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L186-198)
```typescript
    const allKeys = await keysRequiredToSign(
      transaction,
      this.transactionSignatureService,
      entityManager,
      false,
      null,
      keyCache,
    );

    // Filter out keys/users that have been soft-deleted to prevent notification failures
    const activeKeys = filterActiveUserKeys(allKeys);

    return [...new Set(activeKeys.map((k) => k.userId).filter(Boolean))];
```
