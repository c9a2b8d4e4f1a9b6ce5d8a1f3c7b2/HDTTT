### Title
Unbounded Loop with Per-Iteration DB Queries in `getTransactionsToSign` Enables Authenticated Resource Exhaustion

### Summary
`TransactionsService.getTransactionsToSign` fetches **all** non-terminal transactions in the system without any row limit, then iterates over every one of them performing expensive per-transaction operations (transaction byte deserialization, signature key computation, and database queries). Pagination is applied only after the full loop completes. An authenticated user can trigger this endpoint to exhaust server CPU, memory, and database connections, degrading or denying service for all users.

### Finding Description

**Root cause — unbounded fetch + per-item async work:**

In `getTransactionsToSign`, the repository `find()` call has no `take` limit:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,   // all non-terminal statuses, system-wide
  relations: ['groupItem'],
  order,
});                      // ← no .take / .limit
```

The `whereForUser` clause excludes only terminal statuses (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `ARCHIVED`). It is **not** scoped to the requesting user's transactions — it returns every active transaction in the system.

The result set is then iterated in full:

```typescript
for (const transaction of transactions) {
  const keysToSign = await this.userKeysToSign(transaction, user);
  if (keysToSign.length > 0) result.push({ transaction, keysToSign });
}
```

Each call to `userKeysToSign` → `userKeysRequiredToSign` → `keysRequiredToSign` performs:
1. `SDKTransaction.fromBytes(transaction.transactionBytes)` — CPU-intensive deserialization of raw bytes
2. `transactionSignatureService.computeSignatureKey(transaction)` — may involve additional DB lookups for cached accounts/nodes
3. `entityManager.find(UserKey, { where: { publicKey: In(flatPublicKeys) } })` — a database round-trip

Pagination is applied **after** the loop:

```typescript
return {
  totalItems: result.length,
  items: result.slice(offset, offset + limit),  // ← sliced after full scan
  page,
  size,
};
```

There is no cap on how many transactions a user can create (the `importSignatures` function even has an inline comment acknowledging this: `"Added a batch mechanism, probably should limit this on the api side of things"`). A malicious authenticated user can create thousands of transactions, then repeatedly call this endpoint to force the server to process all of them on every request. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation

- **CPU exhaustion**: Each loop iteration deserializes transaction bytes and computes cryptographic signature keys. With thousands of active transactions, a single API call saturates a CPU core.
- **Database connection exhaustion**: Each iteration issues at least one `SELECT` against `user_key`. Thousands of sequential awaited queries hold DB connections for the full duration of the request.
- **Memory pressure**: The entire active transaction set is loaded into memory before any filtering or pagination occurs.
- **Cascading denial of service**: Multiple authenticated users calling this endpoint concurrently multiply the effect. Because the loop is over system-wide transactions (not per-user), every caller pays the full cost regardless of how many transactions they personally own.

**Impact: Service unavailability / severe degradation for all users of the API service.**

### Likelihood Explanation

- **Attacker precondition**: A valid authenticated account — achievable by any registered user.
- **Attack path**: Register → create N transactions via `POST /transactions` (no enforced creation limit) → repeatedly call `GET /transactions/to-sign`.
- **No special privilege required**: The endpoint is accessible to any authenticated user.
- **Amplification**: Because the fetch is system-wide, even a modest number of transactions created by one attacker degrades the experience for all other users.

### Recommendation

1. **Apply a database-level limit before the loop.** Move pagination into the SQL query so only `limit` rows are fetched and processed per request:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  skip: offset,
  take: limit,   // ← enforce at DB level
});
```

2. **Scope the query to the requesting user.** Pre-filter at the SQL level to only transactions where the user's public keys appear in the required signers, rather than loading all active transactions and filtering in application code.

3. **Enforce a maximum transaction creation rate** per user (e.g., via the existing Redis rate-limiter infrastructure) to prevent pre-seeding the system with a large number of transactions.

4. **Batch the per-transaction key lookups** using a single `IN (...)` query across all transaction IDs rather than one query per transaction.

### Proof of Concept

**Setup:**
1. Register as a normal authenticated user (User A).
2. Create 10,000 transactions via `POST /transactions` (each with a unique `transactionId`/`validStart`). No server-side creation limit is enforced.

**Trigger:**
```
GET /transactions/to-sign
Authorization: Bearer <User A token>
```

**Observed behavior:**
- The server executes `repo.find(...)` returning all 10,000 active transactions.
- The server then executes `userKeysToSign(tx, user)` for each — 10,000 sequential async calls, each involving byte deserialization + DB query.
- The request takes tens of seconds or times out; database connection pool is saturated; concurrent requests from other users are queued or rejected.
- Repeating the request (or having multiple attacker sessions call it simultaneously) sustains the degradation. [4](#0-3)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L252-317)
```typescript
  async getTransactionsToSign(
    user: User,
    { page, limit, size, offset }: Pagination,
    sort?: Sorting[],
    filter?: Filtering[],
  ): Promise<
    PaginatedResourceDto<{
      transaction: Transaction;
      keysToSign: number[];
    }>
  > {
    const where = getWhere<Transaction>(filter);
    const order = getOrder(sort);

    const whereForUser: FindOptionsWhere<Transaction> = {
      ...where,
      status: Not(
        In([
          TransactionStatus.EXECUTED,
          TransactionStatus.FAILED,
          TransactionStatus.EXPIRED,
          TransactionStatus.CANCELED,
          TransactionStatus.ARCHIVED,
        ]),
      ),
    };

    const result: {
      transaction: Transaction;
      keysToSign: number[];
    }[] = [];

    /* Ensures the user keys are passed */
    await attachKeys(user, this.entityManager);
    if (user.keys.length === 0) {
      return {
        totalItems: 0,
        items: [],
        page,
        size,
      };
    }

    const transactions = await this.repo.find({
      where: whereForUser,
      relations: ['groupItem'],
      order,
    });

    for (const transaction of transactions) {
      /* Check if the user should sign the transaction */
      try {
        const keysToSign = await this.userKeysToSign(transaction, user);
        if (keysToSign.length > 0) result.push({ transaction, keysToSign });
      } catch (error) {
        console.log(error);
      }
    }

    return {
      totalItems: result.length,
      items: result.slice(offset, offset + limit),
      page,
      size,
    };
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L575-576)
```typescript
    //Added a batch mechanism, probably should limit this on the api side of things
    const BATCH_SIZE = 500;
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L20-93)
```typescript
export const keysRequiredToSign = async (
  transaction: Transaction,
  transactionSignatureService: TransactionSignatureService,
  entityManager: EntityManager,
  showAll: boolean = false,
  userKeys?: UserKey[],
  cache?: Map<string, UserKey>,
): Promise<UserKey[]> => {
  if (!transaction) return [];

  /* Deserialize the transaction */
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

  let results: UserKey[] = [];
  // Now if userKeys is provided, filter out any keys that are not in the flatPublicKeys array
  // this way a user requesting required keys will only see their own keys that are required
  // Otherwise, fetch all UserKeys that are in flatPublicKeys
  if (userKeys) {
    results = userKeys.filter(publicKey =>
        flatPublicKeys.includes(publicKey.publicKey)
    );
  } else {
    if (cache) {
      const cachedKeys: Set<UserKey> = new Set();
      const missingPublicKeys: Set<string> = new Set();

      for (const publicKey of flatPublicKeys) {
        const cached = cache.get(publicKey);
        if (cached) {
          cachedKeys.add(cached);
        } else {
          missingPublicKeys.add(publicKey);
        }
      }

      let fetchedKeys: UserKey[] = [];
      if (missingPublicKeys.size > 0) {
        try {
          fetchedKeys = await entityManager.find(UserKey, {
            where: { publicKey: In([...missingPublicKeys]) },
            relations: ['user'],
          });
          // Store fetched keys in cache
          for (const key of fetchedKeys) {
            cache.set(key.publicKey, key);
          }
        } catch (error) {
          console.error('Error fetching missing user keys:', error);
          throw error;
        }
      }

      results = [...cachedKeys, ...fetchedKeys];
    } else {
      results = await entityManager.find(UserKey, {
        where: { publicKey: In(flatPublicKeys) },
        relations: ['user'],
      });
    }
  }

  return results;
```
