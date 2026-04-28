The code is confirmed. All referenced lines exist exactly as described. Let me verify the scope rules and produce the output.

**Scope check against SECURITY.md:**
- The "Websites and Apps" out-of-scope list includes *"Impacts involving attacks requiring physical access to the victim device."* However, the claim explicitly enumerates non-physical vectors: malware, cloud backup sync (iCloud/OneDrive), and compromised backups — none of which require physical access. The vulnerability is not exclusively dependent on physical access.
- It is not a "best practice recommendation" — it is a concrete, exploitable cryptographic flaw with a confirmed static artifact in the source.
- It is not theoretical — the code is present and the exploit path is mechanically straightforward.

---

Audit Report

## Title
Hardcoded Static Salt in Legacy Mnemonic PBKDF2 Key Derivation Enables Precomputed Password Attacks

## Summary
`decryptLegacyMnemonic` in `front-end/src/main/services/localUser/dataMigration.ts` uses a hardcoded, publicly known 8-byte salt for PBKDF2 key derivation when decrypting the legacy `recovery.aes` mnemonic file. Because the salt is identical for every user and disclosed in the open-source repository, an attacker who obtains the encrypted file can precompute password candidates against this exact salt, eliminating the per-user cost that salts are designed to impose. The derived key is then used with AES-256-ECB — a deterministic, IV-less cipher mode — compounding the weakness.

## Finding Description
In `front-end/src/main/services/localUser/dataMigration.ts`, `decryptLegacyMnemonic` (lines 99–119) derives an AES key as follows:

```typescript
const salt = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);  // line 108 — hardcoded, globally known
const key = crypto.pbkdf2Sync(password, salt, iterationCount, keyLength, 'sha256');  // line 110
// ...
const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);  // line 113 — ECB, no IV
``` [1](#0-0) 

The salt `[1,2,3,4,5,6,7,8]` is identical for every legacy-migrated user. Since the repository is public, this value is globally known. The call chain `decryptMigrationMnemonic` (line 163) → `decryptLegacyMnemonic` (line 174) is triggered during the data migration flow when `parsedContent.legacy` is true. [2](#0-1) 

By contrast, the newer `decryptMnemonic` function (lines 121–153) correctly uses a per-user random salt extracted from the token and Argon2id for key derivation, with AES-256-GCM — demonstrating that the project is aware of proper practices but did not apply them to the legacy path. [3](#0-2) 

## Impact Explanation
Recovery of the mnemonic phrase grants complete, irrecoverable access to all Hedera accounts derived from it. The attacker can transfer all funds, replace keys, and permanently lock the legitimate owner out. The static salt eliminates per-user brute-force cost: a single precomputed PBKDF2 table (salt `[1,2,3,4,5,6,7,8]`, 65536 iterations, SHA-256, 32 bytes) is reusable against every legacy-migrated user's `recovery.aes` file. AES-256-ECB further leaks block-level plaintext patterns and is fully deterministic, making ciphertext comparison trivial.

**Impact: High** — full wallet compromise for any legacy-migrated user whose `recovery.aes` file is obtained.

## Likelihood Explanation
The attacker must obtain `recovery.aes` from `<Documents>/TransactionTools/Files/.System/recovery.aes`. For a desktop Electron application, realistic non-physical vectors include: malware with filesystem read access, cloud backup sync (iCloud/OneDrive automatically syncing the Documents folder), or a compromised backup. No privileged application access is required — only filesystem read access to the Documents directory. The salt and algorithm are fully disclosed in the public repository.

**Likelihood: Medium** — filesystem access is a realistic precondition for a desktop app; the static salt then makes password cracking significantly cheaper than with a random per-user salt.

## Recommendation
1. **Replace the static salt** with a cryptographically random per-user salt (minimum 16 bytes), stored alongside the ciphertext in `recovery.aes`. The existing `decryptMnemonic` path already demonstrates this pattern via `getSalt(token)`.
2. **Replace PBKDF2 with Argon2id**, as already used in `generateArgon2id` (lines 87–97), to increase memory-hardness against GPU-accelerated attacks.
3. **Replace AES-256-ECB with AES-256-GCM**, as already used in `decryptMnemonic` (line 142), to provide authenticated encryption and eliminate ECB's determinism and pattern-leakage issues. [4](#0-3) 

## Proof of Concept
```python
import hashlib, hmac, struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Step 1: Read the victim's recovery.aes file
with open("recovery.aes", "rb") as f:
    ciphertext = f.read()

# Step 2: Known static parameters (from public source code)
salt = bytes([1, 2, 3, 4, 5, 6, 7, 8])
iterations = 65536
key_length = 32  # 256 bits

# Step 3: For each password candidate, derive key and attempt decryption
password_candidates = ["password123", "hedera2023", "mypassword"]  # extend with wordlist

for password in password_candidates:
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=key_length)
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(ciphertext), 16)
        mnemonic = decrypted.decode('utf-8')
        print(f"[+] Password found: {password}")
        print(f"[+] Mnemonic: {mnemonic}")
        break
    except Exception:
        continue
```

Because the salt is static and public, the PBKDF2 derivation step can be precomputed once for all candidates and reused against any number of `recovery.aes` files from different users — a single rainbow table serves the entire legacy user population.

### Citations

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

**File:** front-end/src/main/services/localUser/dataMigration.ts (L106-115)
```typescript
  const iterationCount = 65536;
  const keyLength = 32; // 256 bits
  const salt = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);

  const key = crypto.pbkdf2Sync(password, salt, iterationCount, keyLength, 'sha256');
  const header = Buffer.from('AES|256|CBC|PKCS5Padding|', 'utf-8');
  if (data.length < header.length || !header.equals(data.slice(0, header.length))) {
    const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
    const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
    return decrypted.toString('utf-8');
```

**File:** front-end/src/main/services/localUser/dataMigration.ts (L121-143)
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
