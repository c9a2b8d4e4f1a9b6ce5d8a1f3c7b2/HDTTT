### Title
`uploadKey()` Index Immutability Bypass via JavaScript Falsy Check on `index === 0`

### Summary
In `back-end/apps/api/src/user-keys/user-keys.service.ts`, the `uploadKey()` function is intended to prevent an authenticated user from changing the `index` of an already-registered key. The guard condition uses a JavaScript truthy check on `userKey.index`, which silently skips the protection when the stored index is `0` — the most common initial value. An authenticated user can therefore overwrite their own key's `index` (and `mnemonicHash`) after it has been set, corrupting the key-derivation record stored in the backend.

### Finding Description

The guard at line 52 reads:

```typescript
if (userKey.userId !== user.id || (userKey.index && userKey.index !== dto.index)) {
  throw new BadRequestException(ErrorCodes.PU);
}
Object.assign(userKey, dto);   // overwrites mnemonicHash AND index unconditionally
```

The sub-expression `(userKey.index && userKey.index !== dto.index)` evaluates the stored `index` as a boolean. When `userKey.index === 0` (the first key a user ever registers, and the most common case), `0` is falsy in JavaScript, so the entire sub-expression short-circuits to `false`. The outer `||` condition therefore reduces to `userKey.userId !== user.id`, which is `false` for the key's legitimate owner. No exception is thrown, and `Object.assign(userKey, dto)` overwrites both `mnemonicHash` and `index` with the attacker-supplied values.

The code comment on line 55 explicitly states the intent: *"Set the hash and/or index (only if the current value is null)"* — but the implementation does not enforce this; it always overwrites.

**Exploit path:**
1. Authenticated user registers key: `POST /users/:id/keys` with `{ publicKey: X, mnemonicHash: H1, index: 0 }` → stored as `index=0`.
2. Same user re-submits: `POST /users/:id/keys` with `{ publicKey: X, mnemonicHash: H2, index: 99 }`.
3. Guard: `(0 && 0 !== 99)` → `false`; no error thrown.
4. `Object.assign` overwrites: backend now stores `index=99, mnemonicHash=H2` for that public key. [1](#0-0) 

### Impact Explanation

The `index` field records which BIP-32 derivation slot was used to produce the key pair. Corrupting it in the backend breaks the linkage between the stored public key and the derivation path the front-end uses to reconstruct the private key. Downstream effects include:

- **Transaction signing failure**: backend logic that relies on `index` to match a key to a derivation path will reference the wrong slot, causing signature verification to fail for any transaction that requires this key.
- **`mnemonicHash` overwrite**: the hash is used by `accountSetupRequired()` to determine whether a user has completed key setup. Replacing it with an arbitrary value can force the account back into setup state or bypass the check entirely.
- **Permanent state corruption**: once overwritten, the original `index=0` value is gone; there is no recovery path without admin intervention. [2](#0-1) 

### Likelihood Explanation

- Requires only a valid authenticated session — no admin or privileged role.
- The affected index value (`0`) is the default for every first key registered, making virtually every user's primary key vulnerable.
- The API endpoint is reachable via normal product flow (`POST /users/:id/keys`).
- The existing e2e test at `back-end/apps/api/test/spec/user-keys.e2e-spec.ts` line 126–142 only tests index-change rejection when the stored index is non-zero (e.g., `333`), leaving the `index=0` case untested and undetected. [3](#0-2) 

### Recommendation

Replace the falsy truthy check with an explicit `null`/`undefined` check:

```typescript
// Before (broken for index === 0):
if (userKey.userId !== user.id || (userKey.index && userKey.index !== dto.index)) {

// After (correct):
if (
  userKey.userId !== user.id ||
  (userKey.index != null && userKey.index !== dto.index)
) {
```

Additionally, the `Object.assign(userKey, dto)` on line 56 unconditionally overwrites all fields. Align the implementation with the stated intent ("only if the current value is null"):

```typescript
if (userKey.mnemonicHash == null) userKey.mnemonicHash = dto.mnemonicHash;
if (userKey.index == null) userKey.index = dto.index;
``` [2](#0-1) 

### Proof of Concept

```
# Step 1 – Register key with index 0
POST /users/2/keys
Authorization: Bearer <user_token>
{ "publicKey": "abc123", "mnemonicHash": "original_hash", "index": 0 }
→ 201 Created; DB: index=0, mnemonicHash="original_hash"

# Step 2 – Re-upload same public key with different index
POST /users/2/keys
Authorization: Bearer <user_token>
{ "publicKey": "abc123", "mnemonicHash": "attacker_hash", "index": 99 }
→ 201 Created (expected: 400 Bad Request)
→ DB: index=99, mnemonicHash="attacker_hash"   ← state corrupted

# Verify: guard expression at line 52
# userKey.index = 0  →  (0 && 0 !== 99)  →  false
# userKey.userId === user.id  →  false
# Combined: false || false  →  false  →  no exception thrown
``` [4](#0-3)

### Citations

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L42-66)
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
  }
```

**File:** back-end/apps/api/test/spec/user-keys.e2e-spec.ts (L126-142)
```typescript
    it('(POST) should not update index if uploading existing key and is users', async () => {
      const { mnemonicHash, publicKeyRaw, index } = await generatePrivateKey();

      await endpoint
        .post({ mnemonicHash, publicKey: publicKeyRaw, index }, '/2/keys', userAuthToken)
        .expect(201);

      const newIndex = 123;

      await endpoint
        .post({ mnemonicHash, publicKey: publicKeyRaw, index: newIndex }, '/2/keys', userAuthToken)
        .expect(400);

      const actualUserKeys = await getUserKeys(user.id);

      expect(actualUserKeys[actualUserKeys.length - 1].index).toEqual(index);
    });
```
