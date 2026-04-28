### Title
Unbounded Iteration in `getTransactionsToSign` Causes Per-Request O(N) Database Query Amplification Leading to Server Resource Exhaustion

### Summary

`TransactionsService.getTransactionsToSign()` fetches every non-terminal transaction in the database without any row limit, then issues a separate async database call per transaction to compute signing keys. Pagination is applied only after the full iteration completes. As the transaction table grows, a single authenticated API request to `GET /transactions/sign` triggers O(N) database queries, exhausting connection pool slots, CPU, and memory — degrading or crashing the service for all users.

### Finding Description

**Root cause — no `take` limit on the initial fetch:**

In `back-end/apps/api/src/transactions/transactions.service.ts`, `getTransactionsToSign` calls `this.repo.find(...)` with no `take` (SQL `LIMIT`) clause:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no `take` / `skip` applied here
});
``` [1](#0-0) 

**Unbounded per-item async work:**

For every row returned, the code awaits `userKeysToSign`, which itself calls `transactionSignatureService.computeSignatureKey(transaction)` (mirror-node or DB lookup) and `entityManager.find(UserKey, ...)` (another DB query):

```typescript
for (const transaction of transactions) {
  try {
    const keysToSign = await this.userKeysToSign(transaction, user);
    if (keysToSign.length > 0) result.push({ transaction, keysToSign });
  } catch (error) { ... }
}
``` [2](#0-1) 

**Pagination applied post-hoc:**

The `limit`/`offset` from the caller's `Pagination` object is only used to slice the already-computed `result` array — it never constrains the DB fetch or the loop:

```typescript
return {
  totalItems: result.length,
  items: result.slice(offset, offset + limit),
  page,
  size,
};
``` [3](#0-2) 

**`userKeysToSign` issues at least one DB query per transaction:**

`keysRequiredToSign` calls `entityManager.find(UserKey, { where: { publicKey: In(flatPublicKeys) } })` for every transaction that has unsigned keys: [4](#0-3) 

**The endpoint is publicly reachable by any authenticated user:**

```typescript
@Get('/sign')
@Serialize(withPaginatedResponse(TransactionToSignDto))
getTransactionsToSign(
  @GetUser() user: User,
  @PaginationParams() paginationParams: Pagination,
  ...
``` [5](#0-4) 

No rate-limiting, no body-size guard, and no server-side cap on the number of rows processed is present anywhere in the call chain.

### Impact Explanation

For a deployment with N active (non-terminal) transactions:

- **Database connection exhaustion:** N sequential `await entityManager.find(...)` calls hold DB connections for the full duration of the request. Concurrent requests from multiple users multiply this.
- **Memory pressure:** All N transaction rows (including `transactionBytes` blobs and `groupItem` relations) are loaded into the Node.js heap simultaneously.
- **CPU exhaustion:** `SDKTransaction.fromBytes(transaction.transactionBytes)` and `computeSignatureKey` are called N times per request.
- **Cascading denial of service:** A single user repeatedly calling `GET /transactions/sign` can saturate the DB connection pool, causing all other API requests to queue or fail.

The endpoint is marked `/* NO LONGER USED BY FRONT-END */` but remains fully active and accessible to any authenticated user.

### Likelihood Explanation

- **Attacker precondition:** Only a valid JWT (any registered, verified user). No admin role required.
- **Trigger:** A single HTTP GET to `/transactions/sign`. No special payload needed.
- **Natural growth:** Even without a malicious actor, a long-running deployment accumulates thousands of transactions. Legitimate users hitting this endpoint will experience degraded performance that worsens monotonically over time — identical to the Autonomint pattern in the external report.
- **Amplification:** The attacker can issue concurrent requests to multiply the effect.

### Recommendation

1. **Apply the DB limit before the loop.** Pass `take: limit` and `skip: offset` directly into `this.repo.find(...)` and rewrite the query to filter only transactions where the user has keys to sign (push the key-matching logic into SQL or a subquery), eliminating the per-row async loop entirely.

2. **If the loop must remain**, cap it with a hard server-side maximum (e.g., `take: Math.min(limit, 100)`) and document that `totalItems` is an estimate.

3. **Remove or gate the endpoint** if it is truly no longer used by the front-end — dead endpoints that perform unbounded work are unnecessary attack surface.

### Proof of Concept

**Setup:** A deployment with 10,000 non-terminal transactions in the database.

**Steps:**
1. Obtain a valid JWT for any registered user (normal sign-up flow).
2. Send:
   ```
   GET /transactions/sign?page=1&limit=10
   Authorization: Bearer <jwt>
   ```
3. **Observed:** The server fetches all 10,000 transaction rows, then sequentially awaits `userKeysToSign` for each — issuing up to 10,000 additional DB queries — before returning 10 items to the caller.
4. **Repeat concurrently** (e.g., 10 parallel requests) to saturate the DB connection pool.
5. **Expected outcome:** All other API endpoints begin timing out or returning 500 errors due to exhausted DB connections and Node.js event-loop saturation.

### Citations

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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L86-90)
```typescript
      results = await entityManager.find(UserKey, {
        where: { publicKey: In(flatPublicKeys) },
        relations: ['user'],
      });
    }
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L165-178)
```typescript
  @Get('/sign')
  @Serialize(withPaginatedResponse(TransactionToSignDto))
  getTransactionsToSign(
    @GetUser() user: User,
    @PaginationParams() paginationParams: Pagination,
    @SortingParams(transactionProperties) sort?: Sorting[],
    @FilteringParams({
      validProperties: transactionProperties,
      dateProperties: transactionDateProperties,
    })
    filter?: Filtering[],
  ) {
    return this.transactionsService.getTransactionsToSign(user, paginationParams, sort, filter);
  }
```
