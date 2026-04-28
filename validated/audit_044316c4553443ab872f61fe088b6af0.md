Based on my review of the actual code, I can verify all the claims in this report.

**Verified facts:**

1. `getTransactionsToSign` at lines 295–299 issues a `repo.find()` with no `take`/`skip` — confirmed.
2. The loop at lines 301–309 calls `userKeysToSign` per transaction — confirmed.
3. `userKeysToSign` → `userKeysRequiredToSign` → `keysRequiredToSign` → `computeSignatureKey` → `accountCacheService.getAccountInfoForTransaction` per transaction — confirmed (though the cache service may reduce raw DB hits, it still performs per-transaction async work).
4. Pagination is applied post-scan at lines 311–316 — confirmed.
5. Sibling methods `getTransactions` (lines 175–181), `getHistoryTransactions` (lines 227–236), and `getTransactionsToApprove` (lines 342–350) all use `skip`/`take` at the DB level — confirmed.
6. SECURITY.md excludes "Impacts that only require DDoS" — but this is an **authenticated application-level resource exhaustion** bug, not a volumetric DDoS, so it is not excluded.

---

Audit Report

## Title
Unbounded In-Memory Loop with Per-Iteration Async Work in `getTransactionsToSign` Enables Authenticated DoS

## Summary
`getTransactionsToSign` in `back-end/apps/api/src/transactions/transactions.service.ts` fetches every non-terminal transaction from the database with no row limit, then performs per-transaction async work (account cache lookups, key computation) inside a sequential `for` loop. Pagination is applied only after the full scan completes. Any authenticated user can trigger this endpoint; as active transactions accumulate, each call consumes proportionally more server CPU, memory, and I/O, eventually causing timeouts and degraded availability for all users.

## Finding Description

**Root cause — no DB-level limit before the loop:**

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
});
``` [1](#0-0) 

No `take` or `skip` is present. Every non-terminal transaction in the system is loaded into the Node.js heap.

**Per-transaction async work inside the loop:**

```typescript
for (const transaction of transactions) {
  try {
    const keysToSign = await this.userKeysToSign(transaction, user);
    if (keysToSign.length > 0) result.push({ transaction, keysToSign });
  } catch (error) {
    console.log(error);
  }
}
``` [2](#0-1) 

`userKeysToSign` delegates to `userKeysRequiredToSign` → `keysRequiredToSign` → `transactionSignatureService.computeSignatureKey`, which calls `accountCacheService.getAccountInfoForTransaction` for each account involved in each transaction. [3](#0-2) [4](#0-3) 

**Fake pagination applied after full scan:**

```typescript
return {
  totalItems: result.length,
  items: result.slice(offset, offset + limit),
  page,
  size,
};
``` [5](#0-4) 

The caller receives a paginated response, but the server has already paid the full cost of loading every active transaction and processing each one sequentially.

**Contrast with sibling methods** that correctly apply `skip`/`take` at the DB level: [6](#0-5) [7](#0-6) [8](#0-7) 

## Impact Explanation

- **Server memory exhaustion**: all non-terminal transaction rows and their `groupItem` relations are loaded into the Node.js heap per request.
- **CPU/I/O starvation**: sequential `await` inside the loop means each iteration blocks the next; a large transaction set holds the event loop for an extended period, degrading response times for all concurrent users.
- **Account cache pressure**: `computeSignatureKey` issues `getAccountInfoForTransaction` calls for every account referenced in every transaction; cache misses result in external mirror-node or DB lookups, multiplying I/O proportionally.
- **No self-healing**: the problem worsens monotonically as the organization accumulates active transactions; there is no expiry of the load.

## Likelihood Explanation

- **Attacker precondition**: a valid authenticated session only — no admin role required.
- **Trigger**: call the endpoint backed by `getTransactionsToSign`. The cost is borne entirely by the server.
- **Amplification**: organic system growth (many users creating transactions) achieves the same effect without deliberate attack. A malicious user can also create many transactions themselves to inflate the scan set.
- **Repeatability**: the endpoint can be called in a tight loop; no rate-limiting is visible in the service layer.

## Recommendation

1. **Push pagination to the DB layer**: add `take: limit` and `skip: offset` to the initial `repo.find()` call, mirroring the pattern used in `getTransactions`, `getHistoryTransactions`, and `getTransactionsToApprove`.
2. **Pre-filter at the DB level**: add a join/subquery condition so only transactions where the user's keys are actually required signers are returned, eliminating the need to evaluate every transaction in application code.
3. **Batch async work**: if per-transaction key computation must remain in application code, use `Promise.all` with a concurrency limiter rather than sequential `await` inside a `for` loop.
4. **Add rate limiting** at the controller or gateway level for this endpoint.

## Proof of Concept

1. Authenticate as any valid user.
2. Ensure a large number of non-terminal transactions exist in the system (e.g., 10,000 transactions in `WAITING_FOR_SIGNATURES` status).
3. Issue repeated `GET /transactions/sign` requests (with any `page`/`size` parameters).
4. Observe: each request causes the server to load all 10,000 transaction rows into memory and sequentially call `computeSignatureKey` for each, resulting in high CPU usage, elevated memory consumption, and eventually request timeouts — degrading availability for all concurrent users.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L175-181)
```typescript
    const findOptions: FindManyOptions<Transaction> = {
      where: whereForUser,
      order,
      relations: ['creatorKey', 'groupItem', 'groupItem.group'],
      skip: offset,
      take: limit,
    };
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L227-236)
```typescript
    const findOptions: FindManyOptions<Transaction> = {
      where: {
        ...getWhere<Transaction>(filter),
        status: this.getHistoryStatusWhere(filter),
      },
      order,
      relations: ['groupItem', 'groupItem.group'],
      skip: offset,
      take: limit,
    };
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L295-299)
```typescript
    const transactions = await this.repo.find({
      where: whereForUser,
      relations: ['groupItem'],
      order,
    });
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L301-309)
```typescript
    for (const transaction of transactions) {
      /* Check if the user should sign the transaction */
      try {
        const keysToSign = await this.userKeysToSign(transaction, user);
        if (keysToSign.length > 0) result.push({ transaction, keysToSign });
      } catch (error) {
        console.log(error);
      }
    }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L311-316)
```typescript
    return {
      totalItems: result.length,
      items: result.slice(offset, offset + limit),
      page,
      size,
    };
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L342-350)
```typescript
    const findOptions: FindManyOptions<Transaction> = {
      order,
      relations: {
        creatorKey: true,
        groupItem: true,
      },
      skip: offset,
      take: limit,
    };
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L96-114)
```typescript
export const userKeysRequiredToSign = async (
  transaction: Transaction,
  user: User,
  transactionSignatureService: TransactionSignatureService,
  entityManager: EntityManager,
  showAll: boolean = false,
): Promise<number[]> => {
  await attachKeys(user, entityManager);
  if (user.keys.length === 0) return [];

  const userKeysRequiredToSign = await keysRequiredToSign(
    transaction,
    transactionSignatureService,
    entityManager,
    showAll,
    user.keys
  );

  return userKeysRequiredToSign.map(k => k.id);
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
