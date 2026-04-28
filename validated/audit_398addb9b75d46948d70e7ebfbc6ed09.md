The code is confirmed. Let me verify the exact line references and details against the actual file before rendering a verdict.

**Verified facts from the actual code:**

- Line 108: `const salt = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);` — hardcoded static salt, confirmed.
- Line 110: `crypto.pbkdf2Sync(password, salt, iterationCount, keyLength, 'sha256')` — PBKDF2-SHA256 with 65536 iterations and the static salt, confirmed.
- Line 113: `crypto.createDecipheriv('aes-256-ecb', key, null)` — AES-256-ECB with `null` IV, confirmed.
- Lines 173–174: `decryptMigrationMnemonic` calls `decryptLegacyMnemonic` when `isLegacy === true`, confirmed reachable.
- Lines 142–143: `decryptMnemonic` uses `aes-256-gcm` with a real IV and auth tag — the secure contrast is accurate.

**SECURITY.md scope check:** None of the exclusions apply. This is not theoretical (concrete crypto parameters are confirmed), does not require physical access (file exfiltration via malware is standard), and is not a best-practice recommendation (it is a concrete, exploitable cryptographic weakness with a known static salt that eliminates per-user cost).

---

Audit Report

## Title
AES-256-ECB with Hardcoded Static Salt Used to Decrypt Legacy Mnemonic Seed Phrase

## Summary
`decryptLegacyMnemonic` in `front-end/src/main/services/localUser/dataMigration.ts` decrypts the user's BIP-39 mnemonic seed phrase using AES-256-ECB (no IV, no authentication) and derives the key via PBKDF2-SHA256 with a hardcoded 8-byte static salt `[1,2,3,4,5,6,7,8]`. An attacker who obtains the `recovery.aes` file can perform a fully offline brute-force attack using a single pre-computed PBKDF2 dictionary that applies to every legacy user, recovering the seed phrase and gaining irrevocable control over all associated Hedera accounts.

## Finding Description

**Hardcoded static salt** (`dataMigration.ts`, line 108):
```ts
const salt = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
``` [1](#0-0) 

The PBKDF2 key derivation uses a fixed, globally-known 8-byte salt. The derived key is therefore a pure function of the password alone. An attacker can pre-compute `PBKDF2(candidate, [1,2,3,4,5,6,7,8], 65536, 32, sha256)` for every entry in a password dictionary once, and reuse that table against any `recovery.aes` file from any legacy user.

**AES-256-ECB mode** (`dataMigration.ts`, line 113):
```ts
const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
``` [2](#0-1) 

ECB has no IV (the `null` third argument is the explicit confirmation), no authentication tag, and is fully deterministic. Identical 16-byte plaintext blocks produce identical ciphertext blocks. There is no integrity check — a tampered ciphertext silently produces garbage output rather than raising an error.

**Reachable trigger path** (`dataMigration.ts`, lines 163–177): [3](#0-2) 

`decryptMigrationMnemonic` reads `user.properties`, checks `legacy === true`, and calls `decryptLegacyMnemonic` with the path to `recovery.aes`. This is a user-triggered, reachable code path in the data migration flow.

**Contrast with the secure path** (`dataMigration.ts`, lines 121–153): [4](#0-3) 

`decryptMnemonic` correctly uses AES-256-GCM with a random per-user IV, an authentication tag, and Argon2id key derivation with a per-user salt extracted from the token. The legacy path has none of these protections.

## Impact Explanation

The `recovery.aes` file contains the BIP-39 mnemonic seed phrase, which is the root secret for all Hedera private keys derived from it. Recovering this phrase gives an attacker complete, irrevocable control over all associated Hedera accounts and assets.

The combination of ECB + static salt produces compounding failures:
- **No per-file randomness**: every legacy user with the same password produces the same derived key and the same ciphertext for the same plaintext blocks.
- **Pre-computable attack**: a single PBKDF2 dictionary built against the static salt applies to every legacy `recovery.aes` file ever created — the per-user cost of attack is zero once the table exists.
- **No integrity check**: a tampered or partially corrupted file cannot be detected; decryption silently succeeds with corrupted output.

## Likelihood Explanation

The attacker must obtain the `recovery.aes` file. This does not require physical access:
- Malware or RAT on the user's machine (standard threat model for desktop crypto wallets)
- Cloud backup/sync exposure (iCloud Drive, Google Drive, OneDrive automatically syncing the Documents folder where `TransactionTools/` resides)
- Compromised backup media

Once the file is obtained, the attack is entirely offline. PBKDF2-SHA256 with 65,536 iterations is GPU-acceleratable (bcrypt/Argon2id are not), making brute-force of common passwords practical. The static salt removes all per-user cryptographic cost.

**Likelihood: Medium** — file exfiltration is a standard capability of commodity malware targeting desktop crypto wallets; the static salt and ECB mode remove all per-user cryptographic protection once the file is obtained.

## Recommendation

The `decryptLegacyMnemonic` function is a read-only migration path for files produced by the old tool. The encryption parameters cannot be changed retroactively (the old tool produced those files). The recommended mitigations are:

1. **Immediately after successful migration**, delete or securely overwrite the `recovery.aes` file so it cannot be exfiltrated post-migration.
2. **Warn the user** during the migration flow that the legacy file uses weak encryption and that migration should be completed promptly.
3. **Document the known weakness** in the migration code with a comment explaining that the static salt and ECB mode are inherited from the legacy tool format and are not a design choice of the current tool.
4. **Do not extend** the `decryptLegacyMnemonic` path to any new functionality; ensure it remains strictly a one-time migration helper.

## Proof of Concept

```python
import hashlib, hmac, struct
from Crypto.Cipher import AES

# Static salt is globally known from the source code
STATIC_SALT = bytes([1, 2, 3, 4, 5, 6, 7, 8])
ITERATIONS  = 65536
KEY_LEN     = 32

# Attacker reads recovery.aes from exfiltrated file
with open("recovery.aes", "rb") as f:
    ciphertext = f.read()

# Pre-computed dictionary attack — same table works for ALL legacy users
for candidate in open("rockyou.txt"):
    password = candidate.strip()
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), STATIC_SALT, ITERATIONS, KEY_LEN)
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        plaintext = cipher.decrypt(ciphertext)
        # BIP-39 words are ASCII; check for plausible mnemonic
        if all(32 <= b < 127 for b in plaintext[:20]):
            print(f"[+] Password: {password}")
            print(f"[+] Mnemonic: {plaintext.decode('utf-8', errors='replace')}")
            break
    except Exception:
        continue
```

No interaction with the live application or network is required. The attack is fully offline and the static salt means the dictionary is computed once and reused against any number of stolen `recovery.aes` files.

### Citations

**File:** front-end/src/main/services/localUser/dataMigration.ts (L108-110)
```typescript
  const salt = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);

  const key = crypto.pbkdf2Sync(password, salt, iterationCount, keyLength, 'sha256');
```

**File:** front-end/src/main/services/localUser/dataMigration.ts (L113-115)
```typescript
    const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
    const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
    return decrypted.toString('utf-8');
```

**File:** front-end/src/main/services/localUser/dataMigration.ts (L121-153)
```typescript
export async function decryptMnemonic(
  inputPath: string,
  token: string,
  password: string,
): Promise<string | null> {
  /* Read the encrypted data from the file */
  const data = await fs.promises.readFile(inputPath, { flag: 'r' });

  /* Get the salt from the token */
  const salt = getSalt(token);

  /* Generate the key from the password and the salt */
  const key = await generateArgon2id(password, salt);

  /* Get the header, auth tag, encrypted text, and IV from the data */
  const header = Buffer.from('AES|256|CBC|PKCS5Padding|', 'utf8');
  const authTag = data.subarray(data.length - AUTH_TAG_LENGTH);
  const encryptedText = data.subarray(header.length + IV_LENGTH, data.length - AUTH_TAG_LENGTH);
  const iv = data.subarray(header.length, header.length + IV_LENGTH);

  /* Create a decipher, set the auth tag */
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, new Uint8Array(iv));
  decipher.setAuthTag(new Uint8Array(authTag));

  try {
    /* Decrypt the encrypted text */
    const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
    return decrypted.toString('utf-8');
  } catch (error) {
    logger.error('Error decrypting mnemonic', { error });
    return null;
  }
}
```

**File:** front-end/src/main/services/localUser/dataMigration.ts (L163-177)
```typescript
export async function decryptMigrationMnemonic(password: string): Promise<string[] | null> {
  const content = await fs.promises.readFile(getPropertiesPath(), { encoding: 'utf-8', flag: 'r' });
  const parsedContent = parseUserProperties(content);

  const token = parsedContent.hash;
  if (!token) throw Error('No hash found at location');

  const isLegacy = parsedContent.legacy;

  let words: string | null;
  if (isLegacy) {
    words = await decryptLegacyMnemonic(getMnemonicPath(), password);
  } else {
    words = await decryptMnemonic(getMnemonicPath(), token, password);
  }
```
