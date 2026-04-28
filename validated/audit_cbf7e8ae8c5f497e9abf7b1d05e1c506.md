### Title
Hardcoded Private Keys and Weak Secrets Committed to Repository

### Summary
The repository contains hardcoded Hedera private keys directly in a test utility source file, and a committed `.env.test` file with actual (non-placeholder) weak secrets. This mirrors the external report's vulnerability class: sensitive credentials embedded in version-controlled files.

### Finding Description

**Location 1 — Hardcoded private keys in source code:**

`back-end/apps/api/test/utils/hederaUtils.ts` defines five Hedera accounts with their private keys hardcoded as string literals: [1](#0-0) 

Specifically:
- `localnet2` — DER-encoded ED25519 key: `302e020100300506032b657004220420911...`
- `localnet1002` — ECDSA key: `0x7f109a9e3b0d8ecfba9cc23a3614433ce0fa7ddcc80f2a8f10b222179a5a80d6`
- `localnet1003` — ECDSA key: `0x6ec1f2e7d126a74a1d2ff9e1c5d90b92378c725e506651ff8bb8616a5c724628`
- `localnet1004` — ECDSA key: `0xb4d7f7e82f61d81c95985771b8abf518f9328d019c36849d4214b5f995d13814`
- `localnet1022` — ED25519 key: `0xa608e2130a0a3cb34f86e757303c862bee353d9ab77ba4387ec084f881d420d4`

**Location 2 — Committed `.env.test` with actual weak secrets:**

`back-end/apps/api/.env.test` is a committed, non-example `.env` file containing real values for authentication secrets: [2](#0-1) 

- `JWT_SECRET=13123` — trivially short and guessable
- `OTP_SECRET=123` — single-digit entropy

Unlike the `example.env` files (which use placeholder strings like `some-very-secret-string`), this file is the actual `.env.test` loaded during test runs. [3](#0-2) 

### Impact Explanation

**Private keys:** The five hardcoded keys control Hedera localnet genesis accounts (`0.0.2`, `0.0.1002`–`0.0.1022`). These are well-known Hedera local-node default accounts — analogous to Hardhat's default test accounts — and do not control real mainnet/testnet funds. However, if any operator reuses these keys on testnet or mainnet (e.g., by copy-paste during setup), the keys are already publicly exposed in the repository, granting any observer full control over the associated address.

**JWT/OTP secrets:** `JWT_SECRET=13123` means any party with repository read access can forge valid JWT tokens for any user in any environment that accidentally inherits this file. `OTP_SECRET=123` similarly allows pre-computation of all OTP codes.

### Likelihood Explanation

- The private keys are in a committed source file visible to all repository contributors and, if the repo is public, to anyone on the internet.
- The `.env.test` file is committed (not gitignored), so it is present in every clone. CI/CD pipelines that copy env files (as seen in the workflow) could inadvertently propagate these weak secrets to staging environments. [4](#0-3) 

### Recommendation

1. **Remove hardcoded private keys** from `back-end/apps/api/test/utils/hederaUtils.ts`. Load them from environment variables (e.g., `process.env.LOCALNET_KEY_1002`) and document them only in `example.env` files with empty values.
2. **Remove or gitignore** `back-end/apps/api/.env.test`. Replace hardcoded secret values with environment variable references or generate them dynamically in test setup.
3. **Rotate** any secrets that have been committed, even if they appear to be test-only values, since they are now part of git history.
4. Add a pre-commit hook or CI secret-scanning step (e.g., `gitleaks`, `trufflehog`) to prevent future credential commits.

### Proof of Concept

Any person with repository access can:

1. Open `back-end/apps/api/test/utils/hederaUtils.ts` lines 35–55 and extract the five raw private keys.
2. Use any Hedera SDK to instantiate a `PrivateKey` from those strings and sign transactions on behalf of those accounts on any network where the keys are reused.
3. Open `back-end/apps/api/.env.test` lines 11–18, read `JWT_SECRET=13123`, and craft a valid JWT:
   ```js
   const jwt = require('jsonwebtoken');
   const token = jwt.sign({ sub: 'admin-user-id', role: 'admin' }, '13123', { expiresIn: '365d' });
   // token is accepted by any backend instance running with JWT_SECRET=13123
   ```
   This forged token would be accepted by the API without any credentials. [5](#0-4) [6](#0-5)

### Citations

**File:** back-end/apps/api/test/utils/hederaUtils.ts (L35-56)
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

**File:** back-end/apps/api/.env.test (L1-18)
```text
# Externally exposed port
HTTP_PORT=3000

# Internally exposed port
TCP_PORT=3001

# NATS Messaging URL
NATS_URL=nats://nats:4222

# JSON web token settings
JWT_SECRET=13123
# Temporary, expiration in days
JWT_EXPIRATION=365

# One time password settings
OTP_SECRET=123
# OTP expiration in minutes
OTP_EXPIRATION=20
```

**File:** back-end/apps/api/example.env (L11-16)
```text
JWT_SECRET=some-very-secret-string
# Temporary, expiration in days
JWT_EXPIRATION=365

# One time password settings
OTP_SECRET=some-very-secret-string-otp
```

**File:** .github/workflows/test-frontend.yaml (L221-223)
```yaml
          for dir in . apps/api apps/chain apps/notifications typeorm scripts; do
            cp "${dir}/example.env" "${dir}/.env"
          done
```
