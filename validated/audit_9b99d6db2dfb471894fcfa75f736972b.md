All code references check out. The vulnerability is confirmed across multiple files. Here is the audit report:

---

Audit Report

## Title
Missing Proof-of-Ownership in Public Key Registration Allows Unauthorized Transaction Access and Key Squatting

## Summary
The `uploadKey` endpoint accepts any syntactically valid Hedera public key from any authenticated, email-verified user with no cryptographic challenge proving the registrant controls the corresponding private key. Because transaction visibility and signing-notification routing are derived entirely from the `UserKey` table, an attacker who registers a victim's public key before the legitimate owner gains unauthorized read access to every transaction that requires that key, receives signing notifications for those transactions, and permanently blocks the legitimate owner from registering their own key.

## Finding Description

**Root cause — `uploadKey` in `user-keys.service.ts`**

The only guard against claiming a foreign key is a database uniqueness check: if the public key string is already present in `user_key` and its `userId` differs from the caller's, the request is rejected. If the key is **not yet registered**, any authenticated user may claim it unconditionally. [1](#0-0) 

No signature challenge, no challenge-response, no proof of private-key control is performed at any point.

**Entry point — `UserKeysController.uploadKey`**

The controller is protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. Any verified organization member can POST to this endpoint with an arbitrary `publicKey` string. [2](#0-1) 

**Downstream impact path 1 — unauthorized transaction visibility**

`verifyAccess` grants a user read access to a transaction if `userKeysToSign` returns a non-empty list for that user: [3](#0-2) 

`userKeysToSign` delegates to `userKeysRequiredToSign`, which loads the user's registered keys via `attachKeys` and then filters them against the transaction's required-signer set: [4](#0-3) 

Because the attacker's `UserKey` row now holds the stolen public key, the attacker's key appears in `user.keys`, matches the transaction's required-signer set, and `verifyAccess` returns `true`, exposing the full transaction to the attacker.

**Downstream impact path 2 — key squatting / denial-of-service**

Once the attacker's row exists, the legitimate owner's subsequent `uploadKey` call hits the `userKey.userId !== user.id` branch and receives `ErrorCodes.PU` (Public Key in Use): [5](#0-4) 

The legitimate owner is permanently locked out of registering their own key in the organization, breaking their ability to participate in any multi-sig workflow that requires it.

**Downstream impact path 3 — signing notification fan-out**

The notification service routes signing requests to users whose keys appear in `keysRequiredToSign`. The attacker receives every signing notification for transactions that require the stolen key, leaking transaction metadata (amounts, counterparties, schedules) via the notification payload. [6](#0-5) 

## Impact Explanation

| Impact | Severity |
|---|---|
| Unauthorized read access to private organizational transactions | High |
| Permanent denial-of-service against the legitimate key owner | High |
| Signing notification leakage (transaction metadata exposure) | Medium |

The attacker cannot forge cryptographic signatures (the Hedera SDK verifies signatures on-chain), so they cannot unilaterally execute transactions. However, they can observe all transaction details, block the legitimate signer from participating, and stall multi-sig workflows indefinitely.

## Likelihood Explanation

- **Attacker preconditions**: a valid, verified organization account — no admin or privileged access required.
- **Target information**: Hedera public keys are on-chain public data; any account's key can be looked up via the mirror node API before the legitimate user registers it.
- **Timing**: the attack window is the period between a key being used on-chain and its owner registering it in the organization. For new organization members this window is always open.
- **Automation**: the attack is a single authenticated POST request and can be scripted to race against legitimate registrations.

## Recommendation

Require cryptographic proof-of-ownership at registration time. The standard approach is a **sign-then-register** challenge-response:

1. The server issues a short-lived, user-scoped nonce (e.g., stored in Redis with a TTL).
2. The client signs the nonce with the private key corresponding to the public key being registered.
3. The server verifies the signature against the submitted public key using the Hedera SDK before persisting the `UserKey` row.

This ensures only the holder of the private key can register the corresponding public key, eliminating both the unauthorized-access and key-squatting attack paths entirely.

## Proof of Concept

```
# Step 1 — Attacker looks up victim's Hedera public key via mirror node
GET https://testnet.mirrornode.hedera.com/api/v1/accounts/0.0.<victim_account_id>
# Response contains: "key": { "key": "<victim_raw_public_key_hex>" }

# Step 2 — Attacker registers the victim's public key under their own account
POST /user/keys
Authorization: Bearer <attacker_jwt>
Content-Type: application/json

{
  "publicKey": "<victim_raw_public_key_hex>"
}
# Response: 201 Created — UserKey row created with userId = attacker's id

# Step 3 — Victim attempts to register their own key
POST /user/keys
Authorization: Bearer <victim_jwt>
Content-Type: application/json

{
  "publicKey": "<victim_raw_public_key_hex>"
}
# Response: 400 Bad Request — ErrorCodes.PU ("Public Key in Use")
# Victim is permanently locked out.

# Step 4 — Any transaction T requiring <victim_raw_public_key_hex> now:
#   - Returns true from verifyAccess() for the attacker
#   - Routes TRANSACTION_WAITING_FOR_SIGNATURES notifications to the attacker
#   - Exposes full transaction details (amounts, counterparties, schedule) to the attacker
```

The attack requires no elevated privileges, no race condition beyond the registration window, and is fully scriptable.

### Citations

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L800-808)
```typescript
    const userKeysToSign = await this.userKeysToSign(transaction, user, true);

    return (
      userKeysToSign.length !== 0 ||
      transaction.creatorKey?.userId === user.id ||
      !!transaction.observers?.some(o => o.userId === user.id) ||
      !!transaction.signers?.some(s => s.userKey?.userId === user.id) ||
      !!transaction.approvers?.some(a => a.userId === user.id)
    );
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L96-114)
```typescript
export const userKeysRequiredToSign = async (
  transaction: Transaction,
  user: User,
  transactionSignatureService: TransactionSignatureService,
  entityManager: EntityManager,
  showAll: boolean = false,
): Promise<number[]> => {
  await attachKeys(user, entityManager);
  if (user.keys.length === 0) return [];

  const userKeysRequiredToSign = await keysRequiredToSign(
    transaction,
    transactionSignatureService,
    entityManager,
    showAll,
    user.keys
  );

  return userKeysRequiredToSign.map(k => k.id);
```

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L181-199)
```typescript
  private async getUsersIdsRequiredToSign(
    entityManager: EntityManager,
    transaction: Transaction,
    keyCache?: Map<string, UserKey>,
  ) {
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
  }
```
