### Title
Critically Low PBKDF2 Iteration Count Enables Rapid Brute-Force of Encrypted Private Keys

### Summary
The primary key derivation function used to encrypt all local private keys in the Hedera Transaction Tool desktop application uses only **2,560 PBKDF2-SHA512 iterations** — roughly 82× to 234× below current minimum recommendations. An attacker who obtains the local SQLite database file can brute-force the user's password at extremely high speed, recovering all encrypted Hedera private keys and gaining full control of associated funds.

---

### Finding Description

The `deriveKey` function in `front-end/src/main/utils/crypto.ts` is the sole key derivation primitive used to protect private keys at rest:

```ts
export function deriveKey(password: string, salt: Buffer) {
  const iterations = 2560;   // ← critically low
  const keyLength = 32;
  return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha512');
}
``` [1](#0-0) 

This function is called by `encrypt()` and `decrypt()` in the same file, which are in turn called by every path that stores or reads a private key:

- `storeKeyPair` in `front-end/src/main/services/localUser/keyPairs.ts` — encrypts private keys before writing to SQLite. [2](#0-1) 

- `changeDecryptionPassword` — decrypts then re-encrypts all key pairs. [3](#0-2) 

- `encryptData` in `front-end/src/main/services/localUser/organizationCredentials.ts` — encrypts stored organization credentials. [4](#0-3) 

The same flawed `deriveKey` with 2,560 iterations is also duplicated verbatim in the automation utility at `automation/utils/crypto/crypto.ts`. [5](#0-4) 

For comparison, the **data migration path** (`decryptMnemonic`) correctly uses Argon2id with 256 MB memory cost and 3 time iterations — a strong KDF — but this protection is absent from the primary production encryption path. [6](#0-5) 

The password strength check enforced at registration requires only a minimum of 10 characters with no complexity requirements:

```ts
const validationRegex = [
  /.{10,}/, // min 10 letters
];
``` [7](#0-6) 

This means a user with a 10-character lowercase password (e.g., `hederatools`) is protected by only 2,560 PBKDF2-SHA512 rounds.

---

### Impact Explanation

OWASP currently recommends **210,000 iterations** for PBKDF2-SHA512. The application uses 2,560 — approximately **82× fewer**. On a modern GPU (e.g., RTX 4090), PBKDF2-SHA512 at 2,560 iterations can be computed at hundreds of millions to billions of attempts per second. An attacker who obtains the SQLite database file (stored at a predictable path in the user's application data directory) can exhaust a large portion of the realistic password space in minutes to hours, recovering all plaintext private keys. Since private keys control Hedera accounts directly, this results in complete and irreversible loss of all user funds.

---

### Likelihood Explanation

The SQLite database is a local file on the user's machine. It is reachable via:
- Malware or RAT with filesystem access
- Theft of a laptop or unencrypted disk backup
- Cloud backup services (e.g., iCloud, OneDrive) that sync the application data directory

No network access to the Hedera backend is required. The attacker only needs the database file and the user's email (which is stored in plaintext in the same database). The 2,560-iteration KDF provides negligible resistance to offline brute-force on any modern hardware.

---

### Recommendation

1. **Immediate**: Replace the `deriveKey` PBKDF2 call with Argon2id (already available in the project as a dependency and already used in `dataMigration.ts`). Use parameters consistent with the migration path: `memoryCost: 262144`, `timeCost: 3`, `parallelism: 1`.
2. **On next login**: Re-derive and re-encrypt all stored private keys with the new KDF, prompting the user for their password once.
3. **If PBKDF2 must be retained**: Increase iterations to at least 210,000 (OWASP minimum for PBKDF2-SHA512).

---

### Proof of Concept

1. Locate the SQLite database at the Electron app's user data path (e.g., `~/Library/Application Support/<AppName>/prisma/local.db` on macOS).
2. Extract the `private_key` column from the `KeyPair` table (base64-encoded ciphertext with salt prepended).
3. Parse the first 64 bytes as the salt, bytes 64–80 as IV, bytes 80–96 as GCM auth tag, remainder as ciphertext.
4. Run hashcat or a custom GPU script using PBKDF2-SHA512 with **2,560 iterations** against a dictionary or brute-force space.
5. At ~2,560 iterations, a single RTX 4090 can test tens of millions of candidate passwords per second. A 10-character lowercase password space (~26^10 ≈ 1.4×10^14) is large, but common passwords, dictionary words, and low-complexity patterns are exhausted in seconds to minutes.
6. On a successful match, use the recovered key to decrypt the AES-256-GCM ciphertext, yielding the raw ED25519 private key.
7. Use the private key to sign Hedera transactions and drain the associated account.

### Citations

**File:** front-end/src/main/utils/crypto.ts (L5-9)
```typescript
export function deriveKey(password: string, salt: Buffer) {
  const iterations = 2560;
  const keyLength = 32;

  return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha512');
```

**File:** front-end/src/main/services/localUser/keyPairs.ts (L75-76)
```typescript
      } else if (password) {
        keyPair.private_key = encrypt(keyPair.private_key, password);
```

**File:** front-end/src/main/services/localUser/keyPairs.ts (L100-103)
```typescript
  for (let i = 0; i < keyPairs.length; i++) {
    const keyPair = keyPairs[i];
    const decryptedPrivateKey = decrypt(keyPair.private_key, oldPassword);
    const encryptedPrivateKey = encrypt(decryptedPrivateKey, newPassword);
```

**File:** front-end/src/main/services/localUser/organizationCredentials.ts (L300-301)
```typescript
  } else if (encryptPassword) {
    return encrypt(data, encryptPassword);
```

**File:** automation/utils/crypto/crypto.ts (L4-8)
```typescript
function deriveKey(password: crypto.BinaryLike, salt: crypto.BinaryLike) {
  const iterations = 2560;
  const keyLength = 32;

  return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha512');
```

**File:** front-end/src/main/services/localUser/dataMigration.ts (L87-97)
```typescript
export async function generateArgon2id(password: string, salt: Buffer) {
  const options = {
    type: argon2.argon2id,
    memoryCost: 262144, // 256MB
    timeCost: 3, // iterations
    parallelism: 1, // threads
    salt,
    raw: true, // get the raw bytes
  };
  return argon2.hash(password, options);
}
```

**File:** front-end/src/renderer/utils/validator.ts (L11-13)
```typescript
  const validationRegex = [
    /.{10,}/, // min 10 letters
  ];
```
