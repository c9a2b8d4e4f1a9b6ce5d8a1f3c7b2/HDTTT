All code references check out. Let me verify the exact lines before rendering the final output.

The `uploadKey` function at lines 42–54 of `user-keys.service.ts` confirms the ownership check without any proof-of-ownership: [1](#0-0) 

The `withDeleted: true` flag at line 44 confirms soft-deleted records still block the victim: [2](#0-1) 

The entity uses `@Index()` without `{ unique: true }`, confirming enforcement is application-level only: [3](#0-2) 

The DTO validates only key format, with no proof-of-ownership: [4](#0-3) 

Nothing in `SECURITY.md` places this out of scope — it is not a DDoS, not a theoretical impact, and requires no privileged access. [5](#0-4) 

---

# Audit Report

## Title
Any Verified User Can Permanently Block Another User's Public Key Registration via Pre-Registration

## Summary
The `uploadKey` method in `UserKeysService` enforces public key uniqueness at the application level only. Because no proof-of-private-key-ownership is required, any authenticated user can register any syntactically valid Hedera public key — including keys belonging to other users. Once registered under the attacker's account (including in a soft-deleted state), the legitimate owner is permanently blocked from registering that key, locking them out of all organization transaction workflows.

## Finding Description

**Root cause:** `uploadKey` in `back-end/apps/api/src/user-keys/user-keys.service.ts` performs a `findOne` lookup on `publicKey` with `withDeleted: true` and rejects the request if the found record belongs to a different user — but there is no proof-of-ownership check. Any authenticated user can submit any syntactically valid Hedera public key string.

```typescript
// user-keys.service.ts lines 42–54
let userKey = await this.repo.findOne({
  where: { publicKey: dto.publicKey },
  withDeleted: true,          // ← soft-deleted records are included
});

if (userKey) {
  if (userKey.userId !== user.id || ...) {
    throw new BadRequestException(ErrorCodes.PU);  // ← blocks victim
  }
}
``` [1](#0-0) 

The DTO validates only that the submitted string is a valid Hedera public key format; it does not require any signature or challenge proving control of the corresponding private key: [4](#0-3) 

The entity definition uses `@Index()` without `{ unique: true }`, confirming the uniqueness guarantee is entirely application-level with no database-level enforcement: [3](#0-2) 

**Why the block is permanent:** The `findOne` uses `withDeleted: true`, so even if the attacker soft-deletes their `user_key` record, the deleted row is still returned and the ownership check (`userKey.userId !== user.id`) still fails for the victim. The victim has no recourse — the system provides no mechanism to reclaim a key registered by another user. [6](#0-5) 

## Impact Explanation

Without a registered `user_key`, a victim user cannot:
- **Create transactions** — `createTransaction` requires a `creatorKeyId` that must be a registered key belonging to the user.
- **Be added as a signer or approver** — signers and approvers are identified by their registered `user_key` records, as reflected by the `OneToMany` relations on the entity. [7](#0-6) 

This constitutes a permanent, unrecoverable denial-of-service against a targeted user's ability to participate in any organization transaction workflow. The attacker does not need to use the key for anything — the sole purpose is to occupy the slot.

## Likelihood Explanation

- **Attacker preconditions:** Only a verified organization account is required — no admin or privileged role.
- **Key discovery:** Hedera public keys are public by design. Any key used to sign a Hedera transaction is visible on the mirror node. An attacker can also enumerate keys already registered in the organization via `GET /user/:id/keys`, which exposes `publicKey` fields. [8](#0-7) 
- **Effort:** A single HTTP POST request per targeted key. An attacker can pre-register keys for all known organization members in bulk.
- **No timing constraint:** The attack can be performed at any time before the victim registers their key, including before the victim even joins the organization.

## Recommendation

1. **Proof-of-ownership challenge:** Require the client to sign a server-issued nonce with the private key corresponding to the submitted `publicKey`. Verify the signature server-side before persisting the record. This is the standard approach for key registration in cryptographic systems.
2. **Enforce uniqueness at the database level:** Add `{ unique: true }` to the `@Index()` decorator (or a dedicated `@Unique()` constraint) on `publicKey` in the `UserKey` entity. This prevents race conditions and provides a defense-in-depth layer independent of application logic.
3. **Reclaim mechanism:** If proof-of-ownership is implemented, allow a user who can prove ownership of a key to reclaim it from another account, including soft-deleted records.

## Proof of Concept

```
# Step 1: Attacker (authenticated) registers victim's public key
POST /user/keys
Authorization: Bearer <attacker_token>
Content-Type: application/json

{ "publicKey": "<victim_hedera_public_key>" }

# Response: 201 Created — key stored with userId = attacker_id

# Step 2: Victim attempts to register their own key
POST /user/keys
Authorization: Bearer <victim_token>
Content-Type: application/json

{ "publicKey": "<victim_hedera_public_key>" }

# Response: 400 Bad Request — ErrorCodes.PU
# Reason: findOne({ where: { publicKey: ... }, withDeleted: true })
#         returns attacker's record; userKey.userId !== victim.id → throws

# Step 3: Attacker soft-deletes their record (does NOT help victim)
DELETE /user/keys/<attacker_key_id>

# Step 4: Victim retries — still blocked
POST /user/keys  →  400 Bad Request (ErrorCodes.PU)
# Reason: withDeleted: true still returns the soft-deleted attacker record
```

### Citations

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L42-54)
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
```

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L62-65)
```typescript
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

**File:** back-end/libs/common/src/database/entities/user-key.entity.ts (L41-47)
```typescript
  @OneToMany(() => Transaction, transaction => transaction.creatorKey)
  createdTransactions: Transaction[];

  @OneToMany(() => TransactionApprover, approver => approver.userKey)
  approvedTransactions: TransactionApprover[];

  @OneToMany(() => TransactionSigner, signer => signer.userKey)
```

**File:** back-end/apps/api/src/user-keys/dtos/upload-user-key.dto.ts (L18-21)
```typescript
  @IsNotEmpty()
  @IsHederaPublicKey()
  @NormalizePublicKey()
  publicKey: string;
```

**File:** SECURITY.md (L1-55)
```markdown
# Common Vulnerability Exclusion List

## Out of Scope & Rules

These are the default impacts recommended to projects to mark as out of scope for their bug bounty program. The actual list of out-of-scope impacts differs from program to program.

### General

- Impacts requiring attacks that the reporter has already exploited themselves, leading to damage.
- Impacts caused by attacks requiring access to leaked keys/credentials.
- Impacts caused by attacks requiring access to privileged addresses (governance, strategist), except in cases where the contracts are intended to have no privileged access to functions that make the attack possible.
- Impacts relying on attacks involving the depegging of an external stablecoin where the attacker does not directly cause the depegging due to a bug in code.
- Mentions of secrets, access tokens, API keys, private keys, etc. in GitHub will be considered out of scope without proof that they are in use in production.
- Best practice recommendations.
- Feature requests.
- Impacts on test files and configuration files, unless stated otherwise in the bug bounty program.

### Smart Contracts / Blockchain DLT

- Incorrect data supplied by third-party oracles.
- Impacts requiring basic economic and governance attacks (e.g. 51% attack).
- Lack of liquidity impacts.
- Impacts from Sybil attacks.
- Impacts involving centralization risks.

Note: This does not exclude oracle manipulation/flash-loan attacks.

### Websites and Apps

- Theoretical impacts without any proof or demonstration.
- Impacts involving attacks requiring physical access to the victim device.
- Impacts involving attacks requiring access to the local network of the victim.
- Reflected plain text injection (e.g. URL parameters, path, etc.).
- This does not exclude reflected HTML injection with or without JavaScript.
- This does not exclude persistent plain text injection.
- Any impacts involving self-XSS.
- Captcha bypass using OCR without impact demonstration.
- CSRF with no state-modifying security impact (e.g. logout CSRF).
- Impacts related to missing HTTP security headers (such as `X-FRAME-OPTIONS`) or cookie security flags (such as `httponly`) without demonstration of impact.
- Server-side non-confidential information disclosure, such as IPs, server names, and most stack traces.
- Impacts causing only the enumeration or confirmation of the existence of users or tenants.
- Impacts caused by vulnerabilities requiring unprompted, in-app user actions that are not part of the normal app workflows.
- Lack of SSL/TLS best practices.
- Impacts that only require DDoS.
- UX and UI impacts that do not materially disrupt use of the platform.
- Impacts primarily caused by browser/plugin defects.
- Leakage of non-sensitive API keys (e.g. Etherscan, Infura, Alchemy, etc.).
- Any vulnerability exploit requiring browser bugs for exploitation (e.g. CSP bypass).
- SPF/DMARC misconfigured records.
- Missing HTTP headers without demonstrated impact.
- Automated scanner reports without demonstrated impact.
- UI/UX best practice recommendations.
- Non-future-proof NFT rendering.

## Prohibited Activities
```
