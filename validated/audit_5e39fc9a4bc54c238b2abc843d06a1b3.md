All code references verified. The vulnerability is real and all claims are accurate.

**SECURITY.md check:** The exclusions for "physical access" cover one of the listed attack vectors, but the primary vector (malware/same-user process reading the Electron app data directory) is not excluded. The low iteration count is not a "best practice recommendation" — it is a concrete, exploitable cryptographic weakness with a clear attack path.

---

Audit Report

## Title
Critically Low PBKDF2 Iteration Count (2560) in Private Key Encryption Enables Offline Brute-Force Recovery of Hedera Private Keys

## Summary
The Hedera Transaction Tool desktop application derives encryption keys for at-rest private key storage using PBKDF2-SHA512 with only **2560 iterations** — approximately 82× below the OWASP minimum of 210,000 for SHA-512. Any attacker who obtains the local SQLite database can brute-force the application password offline at GPU speeds and recover plaintext Hedera private keys.

## Finding Description

**Root cause — `deriveKey` in `front-end/src/main/utils/crypto.ts`:**

The `deriveKey` function hardcodes `iterations = 2560`: [1](#0-0) 

This function is called by both `encrypt()` and `decrypt()` in the same file, which are the sole cryptographic protection layer for sensitive data at rest: [2](#0-1) 

**Sensitive data protected by this weak KDF:**

1. **Hedera private keys** — `storeKeyPair()` in `front-end/src/main/services/localUser/keyPairs.ts` calls `encrypt(keyPair.private_key, password)` when `useKeychain` is `false`: [3](#0-2) 

2. **Organization credentials** (passwords) — `encryptData()` in `front-end/src/main/services/localUser/organizationCredentials.ts` calls `encrypt(data, encryptPassword)` when keychain is not used: [4](#0-3) 

3. **Duplication in automation utilities** — the identical weak KDF is duplicated verbatim in `automation/utils/crypto/crypto.ts`: [5](#0-4) 

**Users NOT affected:** Those who opted into macOS Keychain mode (`useKeychain = true`), whose keys are protected by Electron `safeStorage`: [6](#0-5) 

## Impact Explanation
An attacker who obtains the SQLite database file — via malware running as the same OS user, a compromised backup, or exfiltration — can recover plaintext Hedera private keys entirely offline. The recovered key grants full signing authority over the associated Hedera account: token transfers, account deletion, smart contract calls. This constitutes direct theft of cryptographic assets. **Impact: High.**

## Likelihood Explanation
The SQLite database is stored in the Electron app data directory, readable by any process running as the same OS user. Malware, a compromised browser extension, or a rogue npm package in the same user session can silently exfiltrate the database. At 2560 iterations of PBKDF2-SHA512, a single consumer GPU can test tens of millions of password candidates per second, making even moderately complex passwords crackable in minutes to hours. **Likelihood: High** for users with weak-to-moderate passwords; **Medium** for users with strong random passwords.

## Recommendation
Increase the PBKDF2 iteration count in `front-end/src/main/utils/crypto.ts` and `automation/utils/crypto/crypto.ts` to at minimum **210,000** (OWASP recommendation for PBKDF2-SHA512). Consider migrating to **Argon2id** (already a dependency in the project, used in the `hash()` function in the same file) which provides stronger memory-hard resistance. A migration path for existing encrypted data (re-encrypt on next successful login with the new KDF parameters) should be implemented alongside the fix. [7](#0-6) 

## Proof of Concept

1. Locate the SQLite database in the Electron app data directory (e.g., `~/.config/<app>/databases/`).
2. Extract the `private_key` column value from the `KeyPair` table (base64-encoded blob).
3. Decode: first 64 bytes = salt, bytes 64–80 = IV, bytes 80–96 = GCM auth tag, remainder = ciphertext. [8](#0-7) 
4. Run offline PBKDF2-SHA512 brute-force with 2560 iterations per candidate (e.g., using hashcat mode `-m 20300`).
5. On successful password recovery, call `decrypt(ciphertext, recoveredPassword)` to obtain the plaintext ED25519/ECDSA private key.
6. Use the private key to sign arbitrary Hedera transactions and drain the associated account.

### Citations

**File:** front-end/src/main/utils/crypto.ts (L5-10)
```typescript
export function deriveKey(password: string, salt: Buffer) {
  const iterations = 2560;
  const keyLength = 32;

  return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha512');
}
```

**File:** front-end/src/main/utils/crypto.ts (L12-25)
```typescript
export function encrypt(data: string, password: string) {
  const iv = crypto.randomBytes(16);
  const salt = crypto.randomBytes(64);

  const key = deriveKey(password, salt);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);

  const tag = cipher.getAuthTag();

  return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
}
```

**File:** front-end/src/main/utils/crypto.ts (L28-35)
```typescript
  const bData = Buffer.from(data, 'base64');

  const salt = bData.subarray(0, 64);
  const iv = bData.subarray(64, 80);
  const tag = bData.subarray(80, 96);
  const text = bData.subarray(96).toString('base64');

  const key = deriveKey(password, salt);
```

**File:** front-end/src/main/utils/crypto.ts (L45-53)
```typescript
export async function hash(data: string, usePseudoSalt = false): Promise<string> {
  let pseudoSalt: Buffer | undefined;
  if (usePseudoSalt) {
    const paddedData = data.padEnd(16, 'x');
    pseudoSalt = Buffer.from(paddedData.slice(0, 16));
  }
  return await argon2.hash(data, {
    salt: pseudoSalt,
  });
```

**File:** front-end/src/main/services/localUser/keyPairs.ts (L69-79)
```typescript
    if (!encrypted) {
      const useKeychain = await getUseKeychainClaim();

      if (useKeychain) {
        const buffer = safeStorage.encryptString(keyPair.private_key);
        keyPair.private_key = buffer.toString('base64');
      } else if (password) {
        keyPair.private_key = encrypt(keyPair.private_key, password);
      } else {
        throw new Error('Password is required to store unencrypted key pair');
      }
```

**File:** front-end/src/main/services/localUser/organizationCredentials.ts (L294-305)
```typescript
async function encryptData(data: string, encryptPassword?: string | null) {
  const useKeychain = await getUseKeychainClaim();

  if (useKeychain) {
    const passwordBuffer = safeStorage.encryptString(data);
    return passwordBuffer.toString('base64');
  } else if (encryptPassword) {
    return encrypt(data, encryptPassword);
  } else {
    throw new Error('Password is required to store sensitive data');
  }
}
```

**File:** automation/utils/crypto/crypto.ts (L4-9)
```typescript
function deriveKey(password: crypto.BinaryLike, salt: crypto.BinaryLike) {
  const iterations = 2560;
  const keyLength = 32;

  return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha512');
}
```
