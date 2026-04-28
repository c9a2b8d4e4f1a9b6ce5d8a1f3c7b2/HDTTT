### Title
Missing Proof-of-Ownership in Public Key Registration Allows Unauthorized Transaction Access and Key Squatting

### Summary
The `uploadKey` endpoint in the back-end API accepts any valid Hedera public key from any authenticated user without requiring cryptographic proof that the registrant controls the corresponding private key. Because transaction visibility and signer routing are derived entirely from the `UserKey` table, an attacker who registers a foreign public key before its legitimate owner gains unauthorized read access to every transaction that requires that key, receives signing notifications for those transactions, and permanently blocks the legitimate owner from registering their own key.

### Finding Description

**Root cause — `uploadKey` in `user-keys.service.ts`** [1](#0-0) 

The only guard against claiming a foreign key is a database uniqueness check: if the public key string is already present in the `user_key` table and its `userId` differs from the caller's, the request is rejected. If the key is **not yet registered**, any authenticated user may claim it unconditionally — no signature challenge, no challenge-response, nothing.

**Entry point — `UserKeysController.uploadKey`** [2](#0-1) 

The controller is protected only by JWT authentication and email-verification guards. Any verified organization member can POST to this endpoint with an arbitrary `publicKey` string.

**Downstream impact path 1 — unauthorized transaction visibility**

`verifyAccess` grants a user read access to a transaction if `userKeysToSign` returns a non-empty list for that user: [3](#0-2) 

`userKeysToSign` calls `keysRequiredToSign`, which queries the `UserKey` table for any registered key whose `publicKey` string appears in the transaction's required-signer set: [4](#0-3) 

Because the attacker's `UserKey` row now holds the stolen public key, the attacker is returned as a required signer and `verifyAccess` returns `true`, exposing the full transaction to them.

**Downstream impact path 2 — key squatting / denial-of-service**

Once the attacker's row exists, the legitimate owner's subsequent `uploadKey` call hits the `userKey.userId !== user.id` branch and receives `ErrorCodes.PU` (Public Key in Use): [5](#0-4) 

The legitimate owner is permanently locked out of registering their own key in the organization, breaking their ability to participate in any multi-sig workflow that requires it.

**Downstream impact path 3 — signing notification fan-out**

The notification system routes signing requests to users whose keys appear in `keysRequiredToSign`. The attacker receives every signing notification for transactions that require the stolen key, leaking transaction metadata (amounts, counterparties, schedules) via the notification payload.

### Impact Explanation

| Impact | Severity |
|---|---|
| Unauthorized read access to private organizational transactions | High |
| Permanent denial-of-service against the legitimate key owner | High |
| Signing notification leakage (transaction metadata exposure) | Medium |

The attacker cannot forge cryptographic signatures (the Hedera SDK verifies signatures on-chain), so they cannot unilaterally execute transactions. However, they can observe all transaction details, block the legitimate signer from participating, and stall multi-sig workflows indefinitely.

### Likelihood Explanation

- **Attacker preconditions**: a valid, verified organization account — no admin or privileged access required.
- **Target information**: Hedera public keys are on-chain public data; any account's key can be looked up via the mirror node API before the legitimate user registers it.
- **Timing**: the attack window is the period between a key being used on-chain and its owner registering it in the organization. For new organization members this window is always open.
- **Automation**: the attack is a single authenticated POST request and can be scripted to race against legitimate registrations.

### Recommendation

Require the caller to prove possession of the private key at registration time. The standard approach is a **sign-then-verify challenge**:

1. The server issues a short-lived, user-specific nonce.
2. The client signs the nonce with the private key it claims to own.
3. `uploadKey` verifies the signature against `dto.publicKey` before persisting the row.

```typescript
// Pseudocode addition to uploadKey
const isValid = PublicKey.fromString(dto.publicKey).verify(
  Buffer.from(dto.ownershipChallenge),   // server-issued nonce
  Buffer.from(dto.ownershipSignature, 'hex'),
);
if (!isValid) throw new BadRequestException(ErrorCodes.IPK);
```

This is the direct analog to the external report's fix: replace the wrong/missing check with a verification against the correct authority (the private key holder, not just the database row).

### Proof of Concept

1. **Setup**: Attacker (`attacker@org.com`) and victim (`victim@org.com`) are both verified members of the same organization. Victim controls Hedera account `0.0.12345` whose public key is `abc123…` (visible on the mirror node).

2. **Key squatting**: Attacker sends:
   ```
   POST /user/999/keys
   Authorization: Bearer <attacker_jwt>
   { "publicKey": "abc123…" }
   ```
   Response: `201 Created`. The `user_key` row now has `userId = attacker_id`, `publicKey = "abc123…"`.

3. **Victim locked out**: Victim sends the same request. Response: `400 Bad Request { code: "PU" }`. Victim cannot register their own key.

4. **Transaction exposure**: A transaction creator adds `0.0.12345` as a required signer. `keysRequiredToSign` returns the attacker's `UserKey`. `verifyAccess` returns `true` for the attacker. The attacker can now call `GET /transactions/:id` and read the full transaction body, including amounts, memo, and all counterparty account IDs.

5. **Workflow stall**: Because the victim cannot register their key, they cannot submit signatures. The transaction stalls at `WAITING_FOR_SIGNATURES` until it expires, permanently blocking execution.

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

**File:** back-end/apps/api/src/user-keys/user-keys.controller.ts (L38-41)
```typescript
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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L86-91)
```typescript
      results = await entityManager.find(UserKey, {
        where: { publicKey: In(flatPublicKeys) },
        relations: ['user'],
      });
    }
  }
```
