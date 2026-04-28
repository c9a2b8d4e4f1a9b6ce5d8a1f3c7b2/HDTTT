### Title
Missing Runtime Validation of Mirror Node API Responses Causes Back-End Crash and Front-End Hang

### Summary

The codebase contains the same vulnerability class as the external report: mirror node API responses are consumed without runtime schema validation, and the front-end makes all mirror node requests without timeout controls. Additionally, the back-end `parseAccountProperty` function dereferences `accountInfo.key._type` without null-checking `accountInfo.key`, which crashes the signature service whenever the mirror node legitimately returns `key: null` for an account.

### Finding Description

**Issue 1 — Null dereference crash in `parseAccountProperty` (back-end)**

`AccountInfo` declares `key: Key | null`. The back-end `parseAccountProperty` function handles the `'key'` case by immediately accessing `accountInfo.key._type` without a null guard:

```typescript
case 'key':
  switch (accountInfo.key._type) {   // ← crashes if key is null
```

This is called unconditionally from `parseAccountInfo`, which is called from `MirrorNodeClient.fetchAccountInfo`, which feeds `AccountCacheService` and ultimately `TransactionSignatureService`. Any account whose mirror node record has `key: null` (a valid Hedera state) causes an unhandled `TypeError` that propagates up and crashes the signature pipeline for that transaction.

**Issue 2 — No timeout on front-end axios calls**

Every function in `mirrorNodeDataService.ts` — `getAccountInfo`, `getAccountAllowances`, `getExchangeRateSet`, `getTransactionInfo`, `getNetworkNodes`, `getNodeInfo`, `getAccountsByPublicKey` — calls `axios.get()` with only an optional `AbortController` signal and no `timeout` option. The mirror node base URL is fully user-configurable via Settings → Network → Custom. A slow or unresponsive mirror node (or a user-configured malicious one) will cause the Electron renderer to hang indefinitely.

**Issue 3 — No runtime schema validation anywhere**

Both layers use TypeScript type assertions as the sole "validation":
- Front-end: `const rawAccountInfo: AccountInfo = data;` — compile-time only
- Back-end: `fetchWithRetry<AccountInfo>(url, etag)` — generic type parameter, no runtime check
- `const allowances: CryptoAllowance[] = data.allowances;` — no check that `data.allowances` is an array

Neither layer uses Zod or any equivalent runtime schema parser.

### Impact Explanation

- **Back-end DoS**: Any transaction that references an account with `key: null` in the mirror node response will crash `TransactionSignatureService`. Because the crash is a TypeError thrown inside `parseAccountInfo`, it propagates through `fetchAndSaveAccountInfo` → `performRefreshForClaimedAccount` → `getAccountInfoForTransaction`, disrupting signature verification for that transaction and potentially blocking the entire cache-refresh flow for that account.
- **Front-end hang**: With no timeout, a slow or adversarially configured mirror node causes the Electron UI to freeze on any page that calls `getAccountInfo`, `getNetworkNodes`, etc.
- **Data integrity**: Without runtime validation, a malformed mirror node response (e.g., `accounts` not being an array, `balance` being a string) can silently produce wrong parsed values that flow into transaction construction and display.

### Likelihood Explanation

- The null key crash is triggered by a **legitimate Hedera network condition** (accounts with no key set), not just by a malicious actor. Any such account processed by the back-end will reproduce it.
- The front-end timeout issue is triggered by any slow or user-configured custom mirror node. The Settings UI explicitly exposes a "Mirror Node Base URL" input field with no restrictions beyond basic URL format.
- The back-end does have a 5 000 ms module-level timeout (`HttpModule.register({ timeout: 5000 })`), so the back-end hanging issue is mitigated there — but the null-key crash is not.

### Recommendation

1. Add a null guard in `parseAccountProperty` before accessing `accountInfo.key._type`:
   ```typescript
   case 'key':
     if (!accountInfo.key) return null;
     switch (accountInfo.key._type) { ... }
   ```
2. Add per-request `timeout` to every `axios.get()` call in `mirrorNodeDataService.ts` (e.g., `{ timeout: 10000, signal: controller?.signal }`).
3. Introduce Zod (or equivalent) schemas for `AccountInfo`, `NetworkNodesResponse`, `CryptoAllowance`, and `NetworkExchangeRateSetResponse` and parse responses through them before use in both the front-end service and the back-end `MirrorNodeClient`.

### Proof of Concept

**Crash path (back-end)**:

1. A Hedera account `0.0.X` exists on the network with `key: null`.
2. A transaction referencing `0.0.X` is submitted to the back-end.
3. `TransactionSignatureService` calls `AccountCacheService.getAccountInfoForTransaction`.
4. `MirrorNodeClient.fetchAccountInfo` returns `{ account: "0.0.X", key: null, ... }`.
5. `parseAccountInfo` calls `parseAccountProperty(accountInfo, 'key')`.
6. Line 90 of `account.ts` executes `accountInfo.key._type` → `TypeError: Cannot read properties of null (reading '_type')`.
7. The error propagates; the signature service fails for this transaction.

**Hang path (front-end)**:

1. User sets a custom mirror node URL pointing to a server that accepts connections but never responds.
2. Any component that calls `getAccountInfo(accountId, mirrorNodeLink)` (e.g., `AccountByIdCache.load`) issues `axios.get(url, { signal: controller?.signal })` with no timeout.
3. The promise never resolves or rejects; the renderer hangs.

---

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** back-end/libs/common/src/utils/sdk/account.ts (L4-29)
```typescript
export const parseAccountInfo = (accountInfo: AccountInfo) => {
  const accountInfoParsed: AccountInfoParsed = {
    accountId: parseAccountProperty(accountInfo, 'account'),
    alias: accountInfo.alias,
    balance: parseAccountProperty(accountInfo, 'balance'),
    declineReward: parseAccountProperty(accountInfo, 'decline_reward'),
    deleted: parseAccountProperty(accountInfo, 'deleted'),
    ethereumNonce: parseAccountProperty(accountInfo, 'ethereum_nonce'),
    evmAddress: parseAccountProperty(accountInfo, 'evm_address'),
    createdTimestamp: parseAccountProperty(accountInfo, 'created_timestamp'),
    expiryTimestamp: parseAccountProperty(accountInfo, 'expiry_timestamp'),
    key: parseAccountProperty(accountInfo, 'key'),
    maxAutomaticTokenAssociations: parseAccountProperty(
      accountInfo,
      'max_automatic_token_associations',
    ),
    memo: accountInfo.memo,
    pendingRewards: parseAccountProperty(accountInfo, 'pending_reward'),
    receiverSignatureRequired: parseAccountProperty(accountInfo, 'receiver_sig_required'),
    stakedAccountId: parseAccountProperty(accountInfo, 'staked_account_id'),
    stakedNodeId: parseAccountProperty(accountInfo, 'staked_node_id'),
    autoRenewPeriod: accountInfo.auto_renew_period,
  };

  return accountInfoParsed;
};
```

**File:** back-end/libs/common/src/utils/sdk/account.ts (L89-99)
```typescript
    case 'key':
      switch (accountInfo.key._type) {
        case KeyType.ProtobufEncoded:
          return decodeProtobufKey(accountInfo.key.key);
        case KeyType.ED25519:
          return PublicKey.fromStringED25519(accountInfo.key.key);
        case KeyType.ECDSA_SECP256K1:
          return PublicKey.fromStringECDSA(accountInfo.key.key);
        default:
          return null;
      }
```

**File:** back-end/libs/common/src/transaction-signature/mirror-node.client.ts (L54-67)
```typescript
      const response = await this.fetchWithRetry<AccountInfo>(url, etag);

      if (response.status === HTTP_STATUS.NOT_MODIFIED) {
        return { data: null, etag };
      }

      const accountInfoParsed = parseAccountInfo(response.data);
      const newEtag = response.etag ?? null;

      return { data: accountInfoParsed, etag: newEtag };
    } catch (error) {
      this.logger.error(`Failed to fetch account ${accountId}: ${error.message}`);
      throw error;
    }
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.module.ts (L58-60)
```typescript
    HttpModule.register({
      timeout: 5000,
    }),
```

**File:** front-end/src/renderer/services/mirrorNodeDataService.ts (L73-82)
```typescript
export const getAccountInfo = async (
  accountId: string,
  mirrorNodeLink: string,
  controller?: AbortController,
) => {
  const { data } = await axios.get(`${withAPIPrefix(mirrorNodeLink)}/accounts/${accountId}`, {
    signal: controller?.signal,
  });

  const rawAccountInfo: AccountInfo = data;
```

**File:** front-end/src/renderer/services/mirrorNodeDataService.ts (L130-138)
```typescript
  const { data } = await axios.get(
    `${withAPIPrefix(mirrorNodeLink)}/accounts/${accountId}/allowances/crypto`,
    {
      signal: controller?.signal,
    },
  );

  const allowances: CryptoAllowance[] = data.allowances;

```

**File:** front-end/src/renderer/services/mirrorNodeDataService.ts (L185-193)
```typescript
  const { data } = await axios.get<TransactionByIdResponse>(
    `${withAPIPrefix(mirrorNodeLink)}/transactions/${transactionId}`,
    {
      signal: controller?.signal,
    },
  );

  return data;
};
```

**File:** front-end/src/renderer/services/mirrorNodeDataService.ts (L196-218)
```typescript
export const getNetworkNodes = async (mirrorNodeURL: string) => {
  let networkNodes: NetworkNode[] = [];

  try {
    let nextUrl: string | null = `${withAPIPrefix(mirrorNodeURL)}/network/nodes?limit=100`;

    while (nextUrl) {
      const res = await axios.get(nextUrl);
      const data: NetworkNodesResponse = res.data;
      networkNodes = networkNodes.concat(data.nodes || []);

      if (data.links?.next) {
        nextUrl = `${withAPIPrefix(mirrorNodeURL)}${data.links.next.slice(data.links.next.indexOf('/network'))}`;
      } else {
        nextUrl = null;
      }
    }

    return networkNodes;
  } catch (error) {
    logger.error('Failed to get network nodes', { error });
    return networkNodes;
  }
```

**File:** front-end/src/shared/interfaces/HederaSchema.ts (L10-17)
```typescript
export interface AccountInfo {
  account: string | null; // Network entity ID in the format of shard.realm.num
  auto_renew_period: number | null;
  balance: Balance | null;
  created_timestamp: string | null;
  deleted: boolean | null;
  expiry_timestamp: string | null;
  key: Key | null;
```
