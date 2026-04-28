### Title
Hardcoded Private Keys and Weak Secrets Committed to Repository

### Summary
Multiple Hedera private keys are hardcoded directly in test utility files and automation constants, and a committed `.env.test` file contains trivially weak JWT and OTP secrets. Any party with repository access — including anyone who forks or clones it — permanently possesses these credentials via git history.

### Finding Description
Three distinct locations contain hardcoded secrets:

**1. `back-end/apps/api/test/utils/hederaUtils.ts` — five hardcoded private keys**

Five localnet `HederaAccount` objects are constructed with literal private key strings:

- Account `0.0.2` (ED25519): `302e020100300506032b65700422042091132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137`
- Account `0.0.1002` (ECDSA): `0x7f109a9e3b0d8ecfba9cc23a3614433ce0fa7ddcc80f2a8f10b222179a5a80d6`
- Account `0.0.1003` (ECDSA): `0x6ec1f2e7d126a74a1d2ff9e1c5d90b92378c725e506651ff8bb8616a5c724628`
- Account `0.0.1004` (ECDSA): `0xb4d7f7e82f61d81c95985771b8abf518f9328d019c36849d4214b5f995d13814`
- Account `0.0.1022` (ED25519): `0xa608e2130a0a3cb34f86e757303c862bee353d9ab77ba4387ec084f881d420d4` [1](#0-0) 

**2. `automation/constants/transactionEnvironment.constants.ts` — operator key**

The same key as account `0.0.2` above appears again in raw hex form as `DEFAULT_LOCALNET_OPERATOR_KEY`:

```
0x91132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137
``` [2](#0-1) 

This constant is consumed by `automation/services/LocalnetPayerProvisioner.ts` to import the operator key and sign real transactions against a localnet node. [3](#0-2) 

**3. `back-end/apps/api/.env.test` — committed weak application secrets**

The file is tracked in the repository and contains:
- `JWT_SECRET=13123`
- `OTP_SECRET=123` [4](#0-3) 

### Impact Explanation
Any attacker who clones or forks the repository immediately obtains working private keys for multiple Hedera accounts. Because git history is immutable, even if the values are removed in a future commit the keys remain accessible in every historical clone. The operator key (`0.0.2`) is the genesis/treasury account on a localnet, giving full signing authority over that environment. The weak JWT/OTP secrets allow forging authentication tokens and bypassing OTP verification in any deployment that reuses these values.

**Impact: 3**

### Likelihood Explanation
The repository is publicly accessible. No exploitation technique beyond `git clone` and reading a source file is required. The keys are in plain text with no obfuscation. The same operator key appears in two separate files, indicating it is actively used across the automation suite.

**Likelihood: 3**

### Recommendation
1. **Rotate all exposed keys immediately.** Treat every key listed above as compromised.
2. **Purge secrets from git history** using `git filter-repo` or BFG Repo Cleaner; a simple commit deletion is insufficient.
3. **Add `.env.test` to `.gitignore`** and provide only an `example.env.test` with placeholder values (the pattern already used in `automation/example.env`).
4. **Replace hardcoded key literals** in `hederaUtils.ts` and `transactionEnvironment.constants.ts` with environment variable reads (e.g., `process.env.LOCALNET_OPERATOR_KEY`).
5. **Add a pre-commit secret scanner** (e.g., `gitleaks`, `truffleHog`) to the CI pipeline to prevent recurrence.

### Proof of Concept

```
# Clone the repository
git clone https://github.com/0xOyakhilome/hedera-transaction-tool--017

# Immediately read operator private key — no further steps needed
grep -r "DEFAULT_LOCALNET_OPERATOR_KEY" automation/constants/transactionEnvironment.constants.ts
# → 0x91132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137

# Read all five account private keys
grep "setPrivateKey" back-end/apps/api/test/utils/hederaUtils.ts
# → five literal private key strings for accounts 0.0.2, 0.0.1002, 0.0.1003, 0.0.1004, 0.0.1022

# Read weak application secrets
cat back-end/apps/api/.env.test
# → JWT_SECRET=13123 / OTP_SECRET=123
```

### Citations

**File:** back-end/apps/api/test/utils/hederaUtils.ts (L35-55)
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
```

**File:** automation/constants/transactionEnvironment.constants.ts (L3-4)
```typescript
export const DEFAULT_LOCALNET_OPERATOR_KEY =
  '0x91132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137';
```

**File:** automation/services/LocalnetPayerProvisioner.ts (L34-44)
```typescript
  async provisionPayerAccount(operatorKey: string): Promise<string> {
    await this.keyImportNavigator.importEd25519PrivateKey(operatorKey, OPERATOR_ACCOUNT_NICKNAME);

    const { publicKey, privateKey } = this.generateKeyPair();

    await this.createLocalnetPayerAccount(publicKey);
    await this.keyImportNavigator.deleteKeyPairAtIndex(1);
    await this.keyImportNavigator.reopenEd25519Import();
    await this.keyImportNavigator.importEd25519PrivateKey(privateKey, PAYER_ACCOUNT_NICKNAME);

    return privateKey;
```

**File:** back-end/apps/api/.env.test (L11-17)
```text
JWT_SECRET=13123
# Temporary, expiration in days
JWT_EXPIRATION=365

# One time password settings
OTP_SECRET=123
# OTP expiration in minutes
```
