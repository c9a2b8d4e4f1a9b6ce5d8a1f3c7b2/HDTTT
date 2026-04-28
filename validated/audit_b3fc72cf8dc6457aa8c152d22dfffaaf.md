### Title
Inconsistent Staleness Check in Mirror-Node Cache Allows Stale Account/Node Key Data to Drive Signature Requirements

### Summary
`getAccountInfoForTransaction` and `getNodeInfoForTransaction` apply an `isFresh` check in one code path but silently bypass it in a second reachable path, returning known-stale data to the signature-requirement engine. Additionally, `refreshAccount` and `refreshNode` collapse four semantically distinct outcomes (`!claimed`, `NOT_MODIFIED`, `DATA_UNCHANGED`, `NOT_FOUND`) into a single `false` return, causing the cache-management caller to treat a "account not found on mirror node" result identically to "no update needed." This is the direct structural analog of the FEI H03 finding: inconsistent use of the oracle-freshness signal and ambiguous boolean semantics.

### Finding Description

**Inconsistent `isFresh` check — primary path vs. contended-claim path**

In `getAccountInfoForTransaction`: [1](#0-0) 

`isFresh` is checked before returning cached data. If the check fails (data is stale), the code falls through to attempt a refresh claim: [2](#0-1) 

When `claimed=false` (another process holds the lock), the function returns the stale data at line 104 **without any freshness check**. The caller already knows the data failed `isFresh` at line 87, yet the stale value is returned unconditionally. The identical pattern exists in `getNodeInfoForTransaction`: [3](#0-2) 

**Ambiguous boolean return from `refreshAccount` / `refreshNode`**

Both functions return `false` for four distinct conditions: [4](#0-3) 

`RefreshStatus.NOT_FOUND`, `NOT_MODIFIED`, and `DATA_UNCHANGED` all collapse to `false`. The cache-management cron job treats every `false` as "no update needed": [5](#0-4) 

When an account is deleted from Hedera (`NOT_FOUND`), the stale key data remains in the cache and linked transactions are never notified, so the system continues presenting the deleted account's old key as a required signer.

**Where stale data causes harm**

The stale `AccountInfoParsed` / `NodeInfoParsed` is consumed directly by `computeSignatureKey`: [6](#0-5) 

For receiver accounts, `receiverSignatureRequired` from stale cache determines whether a receiver's key is added to the required set: [7](#0-6) 

For node-update transactions, stale `node_account_id` drives the HIP-1299 case selection (Case 1 vs. Case 3), which determines whether a 1-of-2 threshold key is built: [8](#0-7) 

### Impact Explanation

1. **Wrong signature set presented to users.** If an account's key was rotated on-chain and the stale key is returned during the contended-claim window, the multi-sig coordination workflow collects signatures from the wrong key holders. The assembled transaction will be rejected by the Hedera network, permanently blocking execution until the cache refreshes and the workflow is restarted.

2. **Receiver-signature bypass.** If `receiverSignatureRequired` flipped from `false` to `true` on-chain and stale data is served, the receiver's key is omitted from the required set. The transaction is submitted without the receiver's mandatory signature and fails on-chain.

3. **Incorrect HIP-1299 case selection for node-update transactions.** Stale `node_account_id` causes the wrong threshold structure to be built, either omitting the current account key (Case 3 treated as Case 2) or unnecessarily requiring it (Case 2 treated as Case 3), corrupting the governance signing flow for node management.

4. **Silent NOT_FOUND suppression.** When an account is deleted from Hedera, `refreshAccount` returns `false` and the cron job emits no transaction update. The stale key data persists in cache indefinitely (until the next successful refresh), and all linked transactions continue to display the deleted account's key as required.

### Likelihood Explanation

The contended-claim window is bounded by `CACHE_CLAIM_TIMEOUT_MS` (default 10 seconds) and the cron fires every 30 seconds. Any request that arrives while the background cron holds the refresh lock for a stale entry hits the vulnerable path. In a multi-instance deployment (multiple Chain Service pods), contention is more frequent. No attacker privilege is required — any user who triggers `computeSignatureKey` for a transaction whose cached account/node data is stale and currently being refreshed by another pod will receive stale data. The NOT_FOUND suppression is permanent until the next successful mirror-node response.

### Recommendation

1. **Apply `isFresh` consistently in the contended-claim path.** When `claimed=false` and the data is known to be stale, either wait briefly and retry, or return `null` so callers can handle the absence of fresh data explicitly, rather than silently serving stale values.

2. **Distinguish `refreshAccount`/`refreshNode` return semantics.** Return the full `RefreshStatus` enum (or a typed result object) instead of a bare `boolean`. The cache-management caller must handle `NOT_FOUND` differently from `NOT_MODIFIED` — at minimum, `NOT_FOUND` should still trigger a transaction-update notification so the UI reflects the missing account.

3. **Add a staleness guard in `computeSignatureKey`.** Before using `AccountInfoParsed` or `NodeInfoParsed` for signature computation, verify the data is fresh or explicitly document and enforce the acceptable staleness bound.

### Proof of Concept

**Stale-data path (inconsistent `isFresh`):**

1. Account `0.0.100` has key `K_old` cached with `updatedAt = now - 15s` (stale; threshold is 10 s).
2. Background cron claims the refresh lock for `0.0.100` (sets `refreshToken`).
3. Concurrently, a user triggers `computeSignatureKey` for a transaction whose fee payer is `0.0.100`.
4. `getAccountInfoForTransaction` reaches line 87: `isFresh` returns `false` (stale).
5. `tryClaimAccountRefresh` returns `{ claimed: false, data: claimedAccount }` because the cron holds the lock.
6. Line 103: `hasCompleteData(claimedAccount)` is `true` → `parseCachedAccount` returns `K_old`.
7. `computeSignatureKey` adds `K_old` to the required key list.
8. On-chain, `0.0.100` now has key `K_new` (rotated after the cache was populated). The transaction is submitted with `K_old`'s signature and rejected by the Hedera network.

**NOT_FOUND suppression:**

1. Account `0.0.200` is deleted from Hedera. Its `CachedAccount` row still exists with stale key data.
2. Cron calls `refreshAccount({ account: '0.0.200', ... })`.
3. Mirror node returns 404 (no etag) → `performRefreshForClaimedAccount` returns `{ status: NOT_FOUND, data: null }`.
4. `refreshAccount` returns `false` (line 62: `status !== REFRESHED`).
5. `cache-management.service.ts` line 180: `wasRefreshed` is `false` → no `transactionsToUpdate` entry → no notification emitted.
6. All transactions linked to `0.0.200` continue to display the deleted account's key as a required signer indefinitely. [9](#0-8) [10](#0-9)

### Citations

**File:** back-end/libs/common/src/transaction-signature/account-cache.service.ts (L57-62)
```typescript
    if (!claimed) {
      return false; // Didn't refresh (someone else did it)
    }

    const { status } = await this.performRefreshForClaimedAccount(claimedAccount);
    return status === RefreshStatus.REFRESHED;
```

**File:** back-end/libs/common/src/transaction-signature/account-cache.service.ts (L87-91)
```typescript
    if (this.hasCompleteData(cached) && isFresh(cached.updatedAt, this.cacheTtlMs)) {
      // Link to transaction even if using cache
      await this.linkTransactionToAccount(transaction.id, cached.id, isReceiver);
      return this.parseCachedAccount(cached);
    }
```

**File:** back-end/libs/common/src/transaction-signature/account-cache.service.ts (L97-110)
```typescript
    const { data: claimedAccount, claimed } = await this.tryClaimAccountRefresh(account, mirrorNetwork);

    if (!claimed) {
      // Link to transaction
      await this.linkTransactionToAccount(transaction.id, claimedAccount.id, isReceiver);

      if (this.hasCompleteData(claimedAccount)) {
        return this.parseCachedAccount(claimedAccount);
      }

      // No cached data
      // This should never happen
      return null;
    }
```

**File:** back-end/libs/common/src/transaction-signature/node-cache.service.ts (L86-113)
```typescript
    if (this.hasCompleteData(cached) && isFresh(cached.updatedAt, this.cacheTtlMs)) {
      // Link to transaction even if using cache
      await this.linkTransactionToNode(transaction.id, cached.id);
      return this.parseCachedNode(cached);
    }

    // Cache is stale or doesn't exist - fetch new data
    this.logger.debug(`Fetching node ${nodeId} from mirror node (cache ${cached ? 'stale' : 'missing'})`);

    // Try to claim the node for refresh, create the node if none exists
    const { data: claimedNode, claimed } = await this.tryClaimNodeRefresh(nodeId, mirrorNetwork);

    if (!claimed) {
      // Link to transaction if we have cached data
      await this.linkTransactionToNode(transaction.id, claimedNode.id);

      if (this.hasCompleteData(claimedNode)) {
        return this.parseCachedNode(claimedNode);
      }

      // No cached data
      // This should never happen
      return null;
    }

    const { data } = await this.performRefreshForClaimedNode(claimedNode, transaction.id);
    return data;
  }
```

**File:** back-end/apps/chain/src/cache-management/cache-management.service.ts (L179-183)
```typescript
          const wasRefreshed = await this.accountCacheService.refreshAccount(account);
          if (wasRefreshed) {
            txIds.forEach(txId => transactionsToUpdate.add(txId));
          }
          this.circuitBreaker.recordSuccess(network);
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L38-62)
```typescript
  async computeSignatureKey(
    transaction: Transaction,
    showAll: boolean = false,
  ): Promise<KeyList> {
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    const transactionModel = TransactionFactory.fromTransaction(sdkTransaction);

    // Extract signature requirements from the transaction model
    const requirements = this.extractSignatureRequirements(transactionModel);

    // Build the key list
    const signatureKey = new KeyList();

    await this.addFeePayerKey(signatureKey, transaction, requirements.feePayerAccount);
    await this.addSigningAccountKeys(signatureKey, transaction, requirements.signingAccounts);
    await this.addReceiverAccountKeys(signatureKey, transaction, requirements.receiverAccounts, showAll);

    if (requirements.nodeId) {
      await this.addNodeKeys(signatureKey, transaction, requirements.nodeId);
    }

    signatureKey.push(...requirements.newKeys);

    return signatureKey;
  }
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L140-141)
```typescript
        if (accountInfo?.key && (showAll || accountInfo.receiverSignatureRequired)) {
          signatureKey.push(accountInfo.key);
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L214-217)
```typescript
      const isAccountIdChanging =
        nodeUpdateTx.accountId !== null &&
        nodeInfo.node_account_id !== null &&
        !nodeUpdateTx.accountId.equals(nodeInfo.node_account_id);
```

**File:** back-end/libs/common/src/transaction-signature/cache.types.ts (L1-6)
```typescript
export enum RefreshStatus {
  REFRESHED = 'refreshed',
  NOT_MODIFIED = 'not_modified',
  DATA_UNCHANGED = 'data_unchanged',
  NOT_FOUND = 'not_found',
}
```

**File:** back-end/libs/common/src/transaction-signature/cache.util.ts (L1-8)
```typescript
/**
 * Check if cached data is fresh based on threshold.
 */
export function isFresh(updatedAt: Date | null | undefined, thresholdMs: number): boolean {
  return (
    !!updatedAt && Date.now() - updatedAt.getTime() < thresholdMs
  );
}
```
