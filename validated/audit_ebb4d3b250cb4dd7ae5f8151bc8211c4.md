### Title
`getTransactionsToSign` Performs Unbounded Per-Transaction DB Queries, Enabling Authenticated DoS

### Summary

The `getTransactionsToSign` function in `TransactionsService` fetches **all** non-terminal transactions system-wide from the database without any row limit, then iterates over every result making at least one additional async database call per transaction (`computeSignatureKey`). Pagination is applied only after the full in-memory scan completes. An authenticated user who creates a large number of transactions can cause this endpoint to exhaust server resources (DB connections, CPU, request timeout) for every subsequent caller.

### Finding Description

**Root cause — unbounded fetch + per-row async DB call:**

In `back-end/apps/api/src/transactions/transactions.service.ts`, `getTransactionsToSign` (lines 252–317):

```typescript
const transactions = await this.repo.find({
  where: whereForUser,   // status filter only — no user scope, no LIMIT
  relations: ['groupItem'],
  order,
});

for (const transaction of transactions) {
  try {
    const keysToSign = await this.userKeysToSign(transaction, user);
    if (keysToSign.length > 0) result.push({ transaction, keysToSign });
  } catch (error) { console.log(error); }
}

return {
  totalItems: result.length,
  items: result.slice(offset, offset + limit),   // pagination applied AFTER full scan
  ...
};
``` [1](#0-0) 

The `whereForUser` filter excludes only terminal statuses (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `ARCHIVED`). It does **not** scope to the requesting user's own transactions, so the query returns every active transaction in the system. [2](#0-1) 

Each iteration calls `userKeysToSign` → `userKeysRequiredToSign` → `keysRequiredToSign`, which:
1. Deserializes `transaction.transactionBytes` (CPU)
2. Calls `transactionSignatureService.computeSignatureKey(transaction)` — an async DB call
3. Queries `entityManager.find(UserKey, ...)` — another DB call [3](#0-2) 

**Attack path:**

1. Attacker registers as a normal user (no privilege required).
2. Attacker calls `POST /transactions` in a loop, creating thousands of transactions. No rate-limiting or per-user transaction cap was found in the codebase.
3. All created transactions remain in a non-terminal status (e.g., `WAITING_FOR_SIGNATURES`).
4. Any user (including the attacker) calls `GET /transactions/sign`. The server now fetches all N attacker-created transactions plus legitimate ones, then makes 2+ DB round-trips per row before returning any response.
5. With enough transactions, the request exceeds the HTTP timeout or exhausts the DB connection pool, returning errors to all callers.

### Impact Explanation

- **Service unavailability**: The `GET /transactions/sign` endpoint becomes unresponsive for all authenticated users, not just the attacker. This is the primary workflow endpoint for collecting signatures on pending transactions.
- **Cascading DB pressure**: Each request spawns O(N) sequential async DB queries. Under concurrent load this saturates the PostgreSQL connection pool, degrading other endpoints.
- **Permanent degradation**: The attacker's transactions persist in `WAITING_FOR_SIGNATURES` indefinitely (they never expire if `validStart` is set far in the future), so the DoS is durable without admin intervention.

### Likelihood Explanation

- Attacker only needs a valid user account — the lowest possible privilege level.
- Transaction creation (`POST /transactions`) is a normal product flow with no observed rate limit or per-user cap.
- The vulnerable endpoint (`GET /transactions/sign`) is the core signing workflow; disrupting it blocks the entire multi-signature use case.
- The attack is cheap: creating thousands of transactions costs only API calls, not on-chain fees.

### Recommendation

Apply the database-level `LIMIT` **before** the per-row processing loop. The correct fix is to push the user-key filtering into the SQL query (or a batch query), rather than fetching all rows and filtering in application memory:

1. Add `take: limit` and `skip: offset` to the `repo.find` call so the DB enforces pagination before any per-row work.
2. Alternatively, batch-fetch all required signature keys in a single query keyed on the transaction IDs returned by the paginated query, eliminating the per-row DB calls inside the loop.
3. Consider adding a per-user transaction creation rate limit or a cap on active (non-terminal) transactions per user.

### Proof of Concept

**Setup**: Two authenticated users — `attacker` and `victim`.

1. `attacker` calls `POST /transactions` in a loop, creating 10,000 transactions with a `validStart` far in the future (so they never expire). Each transaction is valid per the API's schema checks.
2. All 10,000 transactions sit in `WAITING_FOR_SIGNATURES` status.
3. `victim` calls `GET /transactions/sign` (the normal signing workflow).
4. The server executes:
   - `SELECT * FROM transaction WHERE status NOT IN (...)` → returns 10,000+ rows
   - For each row: `computeSignatureKey(tx)` (DB) + `find(UserKey, ...)` (DB) = 20,000+ sequential async DB calls
5. The request either times out at the HTTP gateway or takes tens of seconds, blocking the victim's signing workflow.
6. Every subsequent call to `GET /transactions/sign` by any user reproduces the same delay as long as the attacker's transactions remain active. [4](#0-3) [5](#0-4)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L266-316)
```typescript
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
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L20-94)
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
};
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L96-115)
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
};
```
