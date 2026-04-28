### Title
DoS: `getTransactionsToSign()` Fetches All Non-Terminal Transactions Without DB-Level Pagination, Enabling Unbounded Resource Exhaustion

### Summary

`TransactionsService.getTransactionsToSign()` issues an unbounded `repo.find()` with no `skip`/`take` limit, loading every non-terminal transaction from the database into memory. It then iterates over all of them in a `for` loop, calling `userKeysToSign()` per transaction — which deserializes transaction bytes via the Hedera SDK and issues additional DB queries — before applying pagination in memory via `result.slice()`. Any authenticated user can create transactions that remain in non-terminal status indefinitely, causing each call to `GET /transactions/sign` to consume unbounded memory, CPU, and database connections.

### Finding Description

**Root cause — unbounded DB fetch followed by per-item async work:**

In `back-end/apps/api/src/transactions/transactions.service.ts`, `getTransactionsToSign()` accepts `Pagination` parameters but never passes `skip`/`take` to the database query:

```typescript
// lines 295-299: no skip/take — fetches ALL non-terminal transactions
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
});
```

It then iterates over every result:

```typescript
// lines 301-309: per-transaction async work, unbounded
for (const transaction of transactions) {
  try {
    const keysToSign = await this.userKeysToSign(transaction, user);
    if (keysToSign.length > 0) result.push({ transaction, keysToSign });
  } catch (error) { console.log(error); }
}
```

Pagination is applied only after the full iteration:

```typescript
// line 313: in-memory slice, too late
items: result.slice(offset, offset + limit),
```

**Per-iteration cost of `userKeysToSign()`:**

`userKeysToSign()` calls `userKeysRequiredToSign()` → `keysRequiredToSign()`, which:
1. Deserializes the full transaction bytes via `SDKTransaction.fromBytes(transaction.transactionBytes)` (CPU-intensive)
2. Calls `transactionSignatureService.computeSignatureKey(transaction, showAll)` (potentially involves mirror node or DB lookups)
3. Issues `entityManager.find(UserKey, ...)` for each transaction (DB query per iteration)

**Exposed endpoint:**

`GET /transactions/sign` is registered in the controller with only JWT guards — no rate limiting, no per-user transaction count cap:

```typescript
@Get('/sign')
@Serialize(withPaginatedResponse(TransactionToSignDto))
getTransactionsToSign(
  @GetUser() user: User,
  @PaginationParams() paginationParams: Pagination,
  ...
) {
  return this.transactionsService.getTransactionsToSign(user, paginationParams, sort, filter);
}
```

**The `whereForUser` filter** excludes only `EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `ARCHIVED` — leaving `NEW`, `WAITING_FOR_SIGNATURES`, `WAITING_FOR_EXECUTION`, and `REJECTED` in scope. Transactions created by any user start as `WAITING_FOR_SIGNATURES` and remain there until signed or expired.

**Transaction creation** is open to any authenticated user with a key (`POST /transactions`, no rate limit on creation volume beyond JWT auth).

**Contrast with properly paginated sibling methods:**

`getHistoryTransactions()` and `getTransactionsToApprove()` both pass `skip: offset, take: limit` directly to the DB query — `getTransactionsToSign()` is the sole outlier.

### Impact Explanation

- **Memory exhaustion:** All matching transaction rows (including their `transactionBytes` blobs) are loaded into the Node.js heap simultaneously. With thousands of transactions, this causes OOM or severe GC pressure.
- **CPU exhaustion:** `SDKTransaction.fromBytes()` is called once per transaction per request. Concurrent requests multiply this.
- **Database connection exhaustion:** Each loop iteration issues at least one `entityManager.find(UserKey, ...)` query. With N transactions and C concurrent callers, this is N×C simultaneous DB queries.
- **Service-wide degradation:** The API service is single-process NestJS. A sustained attack degrades or crashes the API for all users, not just the attacker.

### Likelihood Explanation

- **Attacker preconditions:** Only a valid JWT (registered, verified user with at least one key). No admin access required.
- **Attack steps:** Create many transactions via `POST /transactions` (each with a unique `transactionId`), then repeatedly call `GET /transactions/sign`. Transactions remain in `WAITING_FOR_SIGNATURES` until their `validStart` expires.
- **No rate limiting** is applied to either `POST /transactions` or `GET /transactions/sign` at the controller level.
- The endpoint is still live despite the comment "NO LONGER USED BY FRONT-END" — it is registered and reachable.
- The attack is self-amplifying: more transactions → slower responses → easier to sustain.

### Recommendation

Apply DB-level pagination inside `getTransactionsToSign()`, mirroring the pattern used by `getHistoryTransactions()` and `getTransactionsToApprove()`. The key-matching logic (which requires per-transaction deserialization) should be moved to a SQL-side filter or the result set must be bounded before the loop:

```typescript
// Pass skip/take to the DB query
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  skip: offset,
  take: limit,
});
```

Because `userKeysToSign()` is needed to filter which transactions actually require the user's signature, a two-phase approach is preferable: first fetch a bounded page, then filter. Alternatively, push the key-matching logic into a SQL subquery (as done for approvers in `getTransactionsToApprove()`). Additionally, apply a rate limit guard to `GET /transactions/sign` and `POST /transactions`.

### Proof of Concept

1. Register and verify a user account; obtain a JWT.
2. Generate a Hedera key pair and register it as a user key.
3. In a loop, call `POST /transactions` with unique `transactionId` values (e.g., `0.0.X@<timestamp>`), each creating a transaction in `WAITING_FOR_SIGNATURES` status. Repeat until N transactions exist (e.g., N = 10,000).
4. Call `GET /transactions/sign?page=1&size=10` repeatedly (or concurrently from multiple sessions).
5. **Observed:** Each request causes the server to load all N transaction rows into memory, deserialize all N transaction byte blobs via the Hedera SDK, and issue N DB queries for user keys — regardless of the `size=10` pagination parameter. Response latency grows linearly with N; under concurrent load the API process exhausts memory or DB connections and becomes unresponsive.

**Relevant code locations:**

- Unbounded fetch: [1](#0-0) 
- Unbounded per-transaction loop: [2](#0-1) 
- In-memory-only pagination: [3](#0-2) 
- Exposed endpoint (no rate limit): [4](#0-3) 
- Per-iteration SDK deserialization + DB query: [5](#0-4) 
- Correctly paginated sibling for contrast: [6](#0-5)

### Citations

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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L31-43)
```typescript
  const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

  // list of just public keys that have already signed the transaction
  const signerKeys = sdkTransaction._signerPublicKeys;

  const signature = await transactionSignatureService.computeSignatureKey(transaction, showAll);
  // flatten the key list to an array of public keys
  // and filter out any keys that have already signed the transaction
  const flatPublicKeys = flattenKeyList(signature)
    .map(pk => pk.toStringRaw())
    .filter(pk => !signerKeys.has(pk));

  if (flatPublicKeys.length === 0) return [];
```
