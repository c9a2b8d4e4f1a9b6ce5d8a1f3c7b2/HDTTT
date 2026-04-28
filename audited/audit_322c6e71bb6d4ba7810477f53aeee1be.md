### Title
Hardcoded Private Keys for Localnet Accounts Committed to Source Repository

### Summary
The repository contains five hardcoded private keys for Hedera localnet accounts directly committed in test utility files. Additionally, a performance-seeding helper writes generated private keys and mnemonics to plaintext files on disk. This mirrors the exact vulnerability class described in the external report: private key material stored in source code that is distributed as part of the repository.

### Finding Description

**Location 1 — `back-end/apps/api/test/utils/hederaUtils.ts` (lines 35–55)**

Five private keys are hardcoded as string literals and exported as module-level constants:

```
Account 0.0.2   (ED25519): 302e020100300506032b65700422042091132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137
Account 0.0.1002 (ECDSA):  0x7f109a9e3b0d8ecfba9cc23a3614433ce0fa7ddcc80f2a8f10b222179a5a80d6
Account 0.0.1003 (ECDSA):  0x6ec1f2e7d126a74a1d2ff9e1c5d90b92378c725e506651ff8bb8616a5c724628
Account 0.0.1004 (ECDSA):  0xb4d7f7e82f61d81c95985771b8abf518f9328d019c36849d4214b5f995d13814
Account 0.0.1022 (ED25519): 0xa608e2130a0a3cb34f86e757303c862bee353d9ab77ba4387ec084f881d420d4
```

These are exported and consumed directly by E2E test specs such as `transaction.e2e-spec.ts`. [1](#0-0) [2](#0-1) 

**Location 2 — `automation/k6/helpers/create-complex-accounts.ts` (line 59)**

The same account `0.0.2` key is hardcoded again as a fallback default in `LOCALNET_CONFIG.operatorKey`, meaning it is used even when no environment variable is set:

```ts
operatorKey:
  process.env.OPERATOR_KEY ||
  '302e020100300506032b65700422042091132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137',
``` [3](#0-2) 

**Location 3 — `automation/k6/helpers/seed-perf-data.ts` (lines 910–921)**

The `savePrivateKey()` function writes a generated private key and mnemonic phrase to plaintext files on disk (`data/test-private-key.txt` and `data/test-mnemonic.txt`). No `.gitignore` file was found in the repository to exclude these paths, meaning these files can be committed. [4](#0-3) 

### Impact Explanation

The hardcoded keys in `hederaUtils.ts` are explicitly scoped to `local-node` (Hedera local-node, a local test environment). The account `0.0.2` key is the well-known genesis key for Hedera local-node and is publicly documented. However:

1. Any developer or CI pipeline that clones this repository immediately has all five private keys. If any of these accounts are ever funded on testnet or mainnet (e.g., by a developer who reuses the same key material), an attacker with repository access can drain them.
2. The fallback pattern in `create-complex-accounts.ts` (`process.env.OPERATOR_KEY || '<hardcoded>'`) is particularly dangerous: if the environment variable is not set in a staging or CI environment, the hardcoded key silently takes effect.
3. The `savePrivateKey()` disk-write pattern, if the output files are not gitignored, results in key material being committed to version history — persistent and irrevocable exposure.

**Impact: 4 / 10** — Keys are scoped to localnet by default, but the pattern creates a direct path to real-key exposure through developer error or CI misconfiguration.

### Likelihood Explanation

The repository is public. The keys are in committed source files with no obfuscation. The fallback default in `create-complex-accounts.ts` means the key is used automatically when `OPERATOR_KEY` is unset. The disk-write function runs as part of the seeding workflow with no guard against committing its output.

**Likelihood: 5 / 10** — Exploitation requires either the same key being reused on a funded network, or the disk-written files being committed, both of which are realistic developer mistakes.

### Recommendation

1. **Remove all hardcoded private key strings** from `hederaUtils.ts` and `create-complex-accounts.ts`. Replace them with environment variable reads that fail loudly (throw an error) when unset, rather than falling back to a hardcoded value.
2. **Add a `.gitignore`** entry covering `automation/k6/data/` to prevent `test-private-key.txt` and `test-mnemonic.txt` from being committed.
3. **Rotate** any of the non-genesis keys (`0.0.1002`–`0.0.1022`) if they have ever been used on testnet or mainnet.
4. **Add a pre-commit hook or CI secret-scanning step** (e.g., `gitleaks`, `truffleHog`) to catch future key commits.

### Proof of Concept

```
# Clone the public repository
git clone https://github.com/0xOyakhilome/hedera-transaction-tool--018

# All five private keys are immediately readable:
grep -n "setPrivateKey\|operatorKey" \
  back-end/apps/api/test/utils/hederaUtils.ts \
  automation/k6/helpers/create-complex-accounts.ts
```

Output reveals five full private key hex strings. Any of these keys can be loaded into the Hedera SDK to sign and submit transactions on behalf of the corresponding account on any network where that account exists and is funded:

```ts
import { PrivateKey, Client, TransferTransaction } from '@hiero-ledger/sdk';
const key = PrivateKey.fromString('0xa608e2130a0a3cb34f86e757303c862bee353d9ab77ba4387ec084f881d420d4');
// key is now usable to sign transactions for account 0.0.1022
``` [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** back-end/apps/api/test/utils/hederaUtils.ts (L35-63)
```typescript
export const localnet2 = new HederaAccount()
  .setAccountId('0.0.2')
  .setPrivateKey(
    '302e020100300506032b65700422042091132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137',
  );

export const localnet1002 = new HederaAccount()
  .setAccountId('0.0.1002')
  .setPrivateKey('0x7f109a9e3b0d8ecfba9cc23a3614433ce0fa7ddcc80f2a8f10b222179a5a80d6', 'ECDSA');

export const localnet1003 = new HederaAccount()
  .setAccountId('0.0.1003')
  .setPrivateKey('0x6ec1f2e7d126a74a1d2ff9e1c5d90b92378c725e506651ff8bb8616a5c724628', 'ECDSA');

export const localnet1004 = new HederaAccount()
  .setAccountId('0.0.1004')
  .setPrivateKey('0xb4d7f7e82f61d81c95985771b8abf518f9328d019c36849d4214b5f995d13814', 'ECDSA');

export const localnet1022 = new HederaAccount()
  .setAccountId('0.0.1022')
  .setPrivateKey('0xa608e2130a0a3cb34f86e757303c862bee353d9ab77ba4387ec084f881d420d4', 'ED25519');

export const generateMnemonic = () => {
  return Mnemonic.generate();
};

[localnet2, localnet1002, localnet1003, localnet1004, localnet1022].forEach(account => {
  account.setNetwork('local-node');
});
```

**File:** back-end/apps/api/test/spec/transaction.e2e-spec.ts (L40-44)
```typescript
  localnet1002,
  localnet1003,
  localnet2,
  updateAccount,
} from '../utils/hederaUtils';
```

**File:** automation/k6/helpers/create-complex-accounts.ts (L54-60)
```typescript
const LOCALNET_CONFIG = {
  // Default localnet operator (account 0.0.2 with well-known key)
  operatorId: process.env.OPERATOR_ID || '0.0.2',
  operatorKey:
    process.env.OPERATOR_KEY ||
    '302e020100300506032b65700422042091132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137',
  network: 'local-node' as const,
```

**File:** automation/k6/helpers/seed-perf-data.ts (L910-922)
```typescript
function savePrivateKey(): void {
  const dataDir = path.join(__dirname, '../data');
  fs.mkdirSync(dataDir, { recursive: true });

  const keyPath = path.join(dataDir, 'test-private-key.txt');
  fs.writeFileSync(keyPath, testPrivateKey.toStringRaw());
  console.log(`  Saved private key to: ${keyPath}`);

  // Save mnemonic for Account Setup import during UI tests
  const mnemonicPath = path.join(dataDir, 'test-mnemonic.txt');
  fs.writeFileSync(mnemonicPath, testMnemonic.toString());
  console.log(`  Saved mnemonic to: ${mnemonicPath}`);
}
```
