### Title
Malicious Organization Member Can Permanently Block Victim's Public Key Registration via Pre-emption DoS

---

### Summary

The `uploadKey` function in `user-keys.service.ts` enforces a global uniqueness constraint on `publicKey` across all users. Any authenticated organization member can register any public key — including one belonging to another user — before that user does. Once the attacker claims the key, the victim's subsequent upload attempt is permanently rejected with `ErrorCodes.PU` ("Public key in use"), blocking the victim from participating in any multi-signature workflow on that organization server.

---

### Finding Description

**Vulnerability class:** DoS via state pre-emption (registry slot squatting).

**Root cause — global uniqueness with no ownership proof:**

The `UserKey` entity declares a globally unique index on `publicKey`: [1](#0-0) 

`uploadKey` looks up the key by `publicKey` alone, then rejects the upload if the found record belongs to a different user: [2](#0-1) 

There is no proof-of-possession check. Any authenticated user can supply an arbitrary `publicKey` string in the request body and claim it as their own. The endpoint does not require the caller to demonstrate they hold the corresponding private key.

**Attack path:**

1. Attacker is a legitimate (non-admin) member of the organization.
2. Attacker observes the victim's Hedera public key — it is visible on the Hedera mirror node and also exposed through the organization's own contact-list API (`GET /users/:id/keys` returns `publicKey` for every member).
3. Attacker calls `POST /users/<attacker_id>/keys` with `{ publicKey: <victim_public_key> }`.
4. `uploadKey` finds no existing record, creates a new `UserKey` row with `userId = attacker.id` and `publicKey = victim_public_key`.
5. Victim later calls `POST /users/<victim_id>/keys` with their own public key.
6. `uploadKey` finds the existing row, evaluates `userKey.userId !== user.id` → `true`, and throws `BadRequestException(ErrorCodes.PU)`.
7. Victim is permanently blocked from registering their key on this server. [3](#0-2) 

**Why admin remediation does not fully mitigate:**

An admin can soft-delete the attacker's key record via `removeKey`. However, the attacker can immediately re-register the same public key after deletion, creating a persistent, repeatable DoS with no rate-limiting barrier beyond the general throttler. [4](#0-3) 

---

### Impact Explanation

A victim who cannot register their public key:

- Cannot be added as a signer or approver to any organization transaction.
- Cannot sign transactions already assigned to them (their `UserKey` record does not exist under their `userId`).
- Is effectively excluded from all multi-signature workflows on the organization server.

This constitutes a **permanent, targeted denial of service** against a specific user's ability to participate in the organization's core function (multi-sig transaction orchestration), achievable by any peer member with no elevated privileges.

---

### Likelihood Explanation

- **Attacker preconditions:** Only requires a valid organization account (non-admin). Any invited member qualifies.
- **Key discovery:** Victim public keys are publicly visible on the Hedera mirror node and are returned by the organization's own user/key listing endpoints.
- **Effort:** A single authenticated HTTP POST request. No cryptographic capability required.
- **Persistence:** The attack re-applies immediately after any admin cleanup, making it a sustained DoS.

Likelihood is **high** given the trivial execution and the fact that public keys are, by definition, public.

---

### Recommendation

Enforce **proof-of-possession** before accepting a public key registration. The server should issue a challenge (e.g., a random nonce) that the client must sign with the private key corresponding to the submitted public key. Only if the signature verifies against the submitted public key should the registration be accepted. This mirrors the "active ownership acceptance" pattern recommended in the external report — the key cannot be claimed by a party that does not hold the private key.

Alternatively, scope the uniqueness constraint to `(publicKey, userId)` rather than `publicKey` alone, and remove the cross-user collision check. Each user would then maintain their own key namespace, and squatting by another user would have no effect on the victim's registration.

---

### Proof of Concept

**Setup:** Two organization accounts — `attacker` (auth token `A`) and `victim` (auth token `V`). The victim's Hedera public key is `<victim_pubkey>` (observable from the mirror node or the org contact list).

**Step 1 — Attacker claims victim's key:**
```
POST /users/<attacker_id>/keys
Authorization: Bearer <A>
{ "publicKey": "<victim_pubkey>" }
→ 201 Created
```

**Step 2 — Victim attempts to register their own key:**
```
POST /users/<victim_id>/keys
Authorization: Bearer <V>
{ "publicKey": "<victim_pubkey>" }
→ 400 Bad Request  { "message": "PU" }
```

**Result:** The victim's key is permanently squatted. The victim cannot be assigned as a signer or approver in any transaction. The attacker can repeat Step 1 immediately after any admin-initiated cleanup, sustaining the DoS indefinitely. [5](#0-4)

### Citations

**File:** back-end/libs/common/src/database/entities/user-key.entity.ts (L34-36)
```typescript
  @Column({ length: 128 })
  @Index()
  publicKey: string;
```

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

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L83-93)
```typescript
  // Remove the user key for the provided userKeyId.
  // This is a soft remove, meaning that the deleted timestamp will be set.
  async removeKey(id: number): Promise<boolean> {
    const userKey = await this.getUserKey({ id });
    if (!userKey) {
      throw new BadRequestException(ErrorCodes.KNF);
    }
    await this.repo.softRemove(userKey);

    return true;
  }
```
