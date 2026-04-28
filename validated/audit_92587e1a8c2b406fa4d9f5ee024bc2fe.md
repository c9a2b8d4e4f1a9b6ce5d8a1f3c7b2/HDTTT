Having read all relevant source files, I can verify the exact code paths described in the claim against the actual implementation.

**Verification summary:**

1. **Inconsistent `isFresh` check** — Confirmed. `getAccountInfoForTransaction` checks `isFresh` at line 87, but the `!claimed` branch at lines 99–104 returns `parseCachedAccount(claimedAccount)` with only a `hasCompleteData` guard, no freshness check. Identical pattern in `getNodeInfoForTransaction` lines 98–108.

2. **Ambiguous boolean return** — Confirmed. `refreshAccount` returns `false` for `!claimed` (line 58), and for any status that is not `REFRESHED` (line 62), collapsing `NOT_MODIFIED`, `DATA_UNCHANGED`, and `NOT_FOUND`. The cron caller at lines 179–181 of `cache-management.service.ts` treats all `false` returns identically.

3. **NOT_FOUND suppression is actually worse than described** — When a previously-cached account is deleted from Hedera, `fetchAndSaveAccountInfo` receives `data: null` and calls `saveAccountData` with no payload, which bumps `updatedAt` and clears `refreshToken`. Then `performRefreshForClaimedAccount` sees `!accountData && hasCompleteData(claimedAccount) === true` and returns `NOT_MODIFIED` (not `NOT_FOUND`), so the stale key data persists *and* the timestamp is refreshed, deferring the next refresh attempt by a full TTL.

4. **Downstream impact on `computeSignatureKey`** — Confirmed. Stale `AccountInfoParsed` flows into `addReceiverAccountKeys` (line 140, `receiverSignatureRequired` gate) and stale `NodeInfoParsed` flows into `addNodeKeys` (lines 214–217, `isAccountIdChanging` determination).

All four required checks pass. The finding is valid.

---

# Audit Report

## Title
Inconsistent Staleness Check in Mirror-Node Cache Allows Stale Account/Node Key Data to Drive Signature Requirements

## Summary
`getAccountInfoForTransaction` and `getNodeInfoForTransaction` apply an `isFresh` guard on the fast path but silently bypass it when another process holds the refresh claim, returning known-stale data to `computeSignatureKey`. Additionally, `refreshAccount` and `refreshNode` collapse four semantically distinct outcomes (`!claimed`, `NOT_MODIFIED`, `DATA_UNCHANGED`, `NOT_FOUND`) into a single `false` return, causing the cron-based cache manager to treat a deleted account identically to "no update needed," leaving stale key data in the cache indefinitely while actively deferring the next refresh.

## Finding Description

### Inconsistent `isFresh` check

In `getAccountInfoForTransaction`:

```
// Line 87 — fast path: freshness IS checked
if (this.hasCompleteData(cached) && isFresh(cached.updatedAt, this.cacheTtlMs)) {
  return this.parseCachedAccount(cached);   // fresh, safe
}

// Lines 97–104 — contended-claim path: freshness is NOT checked
const { data: claimedAccount, claimed } = await this.tryClaimAccountRefresh(...);
if (!claimed) {
  if (this.hasCompleteData(claimedAccount)) {
    return this.parseCachedAccount(claimedAccount);  // stale, no isFresh guard
  }
}
```

The caller already established that the data failed `isFresh` at line 87. When `claimed=false` (another pod holds the lock), the function returns the same stale value unconditionally. [1](#0-0) 

The identical pattern exists in `getNodeInfoForTransaction`: [2](#0-1) 

### Ambiguous boolean return from `refreshAccount` / `refreshNode`

`refreshAccount` returns `false` for four distinct conditions: [3](#0-2) 

- `!claimed` — another process holds the lock (line 58)
- `NOT_MODIFIED` — mirror node returned 304 (line 62)
- `DATA_UNCHANGED` — data fetched but identical (line 62)
- `NOT_FOUND` — account deleted from Hedera (line 62)

The cron job treats every `false` as "no update needed": [4](#0-3) 

### NOT_FOUND suppression is worse than a simple miss

When a previously-cached account is deleted from Hedera, `fetchAndSaveAccountInfo` receives `data: null` and calls `saveAccountData` with no payload, which **bumps `updatedAt` and clears `refreshToken`**: [5](#0-4) 

Then `performRefreshForClaimedAccount` evaluates `!accountData && hasCompleteData(claimedAccount) === true` and returns `NOT_MODIFIED` (not `NOT_FOUND`), so the stale key data persists **and** the timestamp is refreshed, deferring the next refresh attempt by a full TTL cycle: [6](#0-5) 

### Stale data reaches the signature engine

The stale `AccountInfoParsed` / `NodeInfoParsed` is consumed directly by `computeSignatureKey`. For receiver accounts, `receiverSignatureRequired` from stale cache gates whether the receiver's key is added: [7](#0-6) 

For node-update transactions, stale `node_account_id` drives the HIP-1299 case selection (Case 1 vs. Case 3), which determines whether a 1-of-2 threshold key is built: [8](#0-7) 

## Impact Explanation

1. **Wrong signature set presented to users.** If an account's key was rotated on-chain and the stale key is returned during the contended-claim window, the multi-sig coordination workflow collects signatures from the wrong key holders. The assembled transaction will be rejected by the Hedera network, permanently blocking execution until the cache refreshes and the workflow is restarted.

2. **Receiver-signature bypass.** If `receiverSignatureRequired` flipped from `false` to `true` on-chain and stale data is served, the receiver's key is omitted from the required set. The transaction is submitted without the receiver's mandatory signature and fails on-chain.

3. **Incorrect HIP-1299 case selection for node-update transactions.** Stale `node_account_id` causes the wrong threshold structure to be built — either omitting the current account key (Case 3 treated as Case 1/2) or unnecessarily requiring it, corrupting the governance signing flow for node management.

4. **Silent NOT_FOUND suppression with active TTL extension.** When an account is deleted from Hedera, `refreshAccount` returns `false`, no transaction update is emitted, and `updatedAt` is bumped — meaning the stale key data persists for at least one additional full TTL cycle before the next refresh attempt. All linked transactions continue to display the deleted account's key as a required signer.

## Likelihood Explanation

The contended-claim window is bounded by `CACHE_CLAIM_TIMEOUT_MS` (default 10 seconds) and the cron fires every 30 seconds. Any request that arrives while the background cron holds the refresh lock for a stale entry hits the vulnerable path. In a multi-instance deployment (multiple Chain Service pods), contention is more frequent. No attacker privilege is required — any user who triggers `computeSignatureKey` for a transaction whose cached account/node data is stale and currently being refreshed by another pod will receive stale data. The NOT_FOUND suppression is self-reinforcing: each refresh cycle bumps `updatedAt`, extending the stale data lifetime by another TTL.

## Recommendation

1. **Enforce `isFresh` on the contended-claim path.** In `getAccountInfoForTransaction` and `getNodeInfoForTransaction`, when `claimed=false`, apply the same `isFresh` check before returning cached data. If the data is stale and the claim is held by another process, either wait/retry or return `null` to signal unavailability rather than serving known-stale data.

2. **Distinguish `NOT_FOUND` from `NOT_MODIFIED` in `performRefreshForClaimedAccount/Node`.** Use the mirror node response's HTTP status code or `etag` presence to differentiate a 304 from a 404, rather than relying solely on `hasCompleteData`. When a 404 is confirmed, do not bump `updatedAt` and do not return `NOT_MODIFIED`.

3. **Return a richer result type from `refreshAccount`/`refreshNode`.** Replace the `boolean` return with a discriminated union (e.g., `RefreshOutcome`) so the cron caller can distinguish `NOT_FOUND` from `NOT_MODIFIED` and take appropriate action (e.g., emit a transaction update or mark the account as deleted).

4. **Emit transaction updates on `NOT_FOUND`.** When an account or node is confirmed deleted on the mirror node, the cron job should emit a transaction update so linked transactions can be re-evaluated and users are notified.

## Proof of Concept

**Contended-claim stale-data path:**

1. Account `0.0.123` has its key rotated on Hedera. Its cache entry becomes stale (`updatedAt` older than `CACHE_STALE_THRESHOLD_MS`).
2. The background cron fires and claims the refresh lock for `0.0.123` (sets `refreshToken`).
3. Concurrently, a user triggers `computeSignatureKey` for a transaction involving `0.0.123`.
4. `getAccountInfoForTransaction` reads the cached entry, finds `isFresh` returns `false` (line 87), and falls through to `tryClaimAccountRefresh`.
5. `tryClaimRefresh` returns `{ claimed: false }` because the cron holds the lock.
6. The function enters the `!claimed` branch (line 99), calls `hasCompleteData` (true, old key present), and returns `parseCachedAccount(claimedAccount)` — the old, rotated-away key — with no freshness check.
7. `computeSignatureKey` adds the old key to the required signer set.
8. The multi-sig workflow collects signatures from the old key holders. The transaction is submitted and rejected by Hedera because the old key is no longer valid.

**NOT_FOUND suppression path:**

1. Account `0.0.456` is deleted from Hedera. Its cache entry has `encodedKey` populated from a prior fetch.
2. The cron fires, claims the refresh lock, and calls `fetchAndSaveAccountInfo`.
3. The mirror node returns 404 (`data: null, etag: null`). `fetchAndSaveAccountInfo` calls `saveAccountData` with no payload, bumping `updatedAt` and clearing `refreshToken`.
4. `performRefreshForClaimedAccount` sees `!accountData && hasCompleteData(claimedAccount) === true` and returns `{ status: NOT_MODIFIED }`.
5. `refreshAccount` returns `false`. The cron does not add linked transactions to `transactionsToUpdate`. No update is emitted.
6. On the next cron cycle, `updatedAt` is fresh (just bumped), so the entry is not selected as stale. The deleted account's key persists in cache for another full TTL.
7. Any subsequent `computeSignatureKey` call for a linked transaction returns the deleted account's old key as a required signer.

### Citations

**File:** back-end/libs/common/src/transaction-signature/account-cache.service.ts (L50-63)
```typescript
  async refreshAccount(cached: CachedAccount): Promise<boolean> {
    const account = cached.account;
    const mirrorNetwork = cached.mirrorNetwork;

    // Try to claim the account for refresh
    const { data: claimedAccount, claimed } = await this.tryClaimAccountRefresh(account, mirrorNetwork);

    if (!claimed) {
      return false; // Didn't refresh (someone else did it)
    }

    const { status } = await this.performRefreshForClaimedAccount(claimedAccount);
    return status === RefreshStatus.REFRESHED;
  }
```

**File:** back-end/libs/common/src/transaction-signature/account-cache.service.ts (L87-110)
```typescript
    if (this.hasCompleteData(cached) && isFresh(cached.updatedAt, this.cacheTtlMs)) {
      // Link to transaction even if using cache
      await this.linkTransactionToAccount(transaction.id, cached.id, isReceiver);
      return this.parseCachedAccount(cached);
    }

    // Cache is stale or doesn't exist - fetch new data
    this.logger.debug(`Fetching account ${account} from mirror node (cache ${cached ? 'stale' : 'missing'})`);

    // Try to claim the account for refresh, create the account row if none exists
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

**File:** back-end/libs/common/src/transaction-signature/account-cache.service.ts (L206-219)
```typescript
    if (!fetchedAccount.data) {
      // Update updatedAt and clear refresh token only
      // Include the isReceiver flag to ensure the transaction
      // link is created with correct role, if applicable
      await this.saveAccountData(
        account,
        mirrorNetwork,
        refreshToken,
        undefined,
        undefined,
        transactionId,
        isReceiver,
      );
      return null; // Indicates no new data (304)
```

**File:** back-end/libs/common/src/transaction-signature/account-cache.service.ts (L259-266)
```typescript
      if (!accountData && this.hasCompleteData(claimedAccount)) {
        return { status: RefreshStatus.NOT_MODIFIED, data: this.parseCachedAccount(claimedAccount) };
      }

      if (!accountData) {
        this.logger.warn(`Account ${account} not found on mirror network ${mirrorNetwork}`);
        return { status: RefreshStatus.NOT_FOUND, data: null };
      }
```

**File:** back-end/libs/common/src/transaction-signature/node-cache.service.ts (L86-109)
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
```

**File:** back-end/apps/chain/src/cache-management/cache-management.service.ts (L179-182)
```typescript
          const wasRefreshed = await this.accountCacheService.refreshAccount(account);
          if (wasRefreshed) {
            txIds.forEach(txId => transactionsToUpdate.add(txId));
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
