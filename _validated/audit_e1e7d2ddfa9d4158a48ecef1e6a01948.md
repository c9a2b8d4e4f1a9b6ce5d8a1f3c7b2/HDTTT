Audit Report

## Title
Unbounded Full-Table Scan with Per-Row Async Processing in `getTransactionsToSign` Causes Server-Side Resource Exhaustion DoS

## Summary
`getTransactionsToSign` in `transactions.service.ts` fetches every active transaction from the database with no row limit, then serially awaits an expensive async cryptographic key-resolution call (`userKeysToSign`) per row before applying pagination in memory. Any authenticated user can trigger this endpoint. As the transaction table grows, each request consumes unbounded CPU, memory, and database connection time, degrading or crashing the API for all users.

## Finding Description

**Root cause — missing `take`/`skip` on the ORM query:**

The function `getTransactionsToSign` (lines 252–317) accepts pagination parameters but never passes them to the database query:

```typescript
// lines 295-299 — no take / skip
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
});
``` [1](#0-0) 

This is in direct contrast to every other paginated query in the same file. For example, `getTransactionsToApprove` (lines 342–350) correctly passes `skip: offset, take: limit`:

```typescript
const findOptions: FindManyOptions<Transaction> = {
  order,
  relations: { creatorKey: true, groupItem: true },
  skip: offset,
  take: limit,
};
``` [2](#0-1) 

Similarly, `getHistoryTransactions` and `getTransactions` both pass `skip: offset, take: limit`. [3](#0-2) 

**Per-row async work:**

After loading the entire table, the function serially awaits `userKeysToSign` for every row:

```typescript
for (const transaction of transactions) {
  try {
    const keysToSign = await this.userKeysToSign(transaction, user);
    if (keysToSign.length > 0) result.push({ transaction, keysToSign });
  } catch (error) { ... }
}
``` [4](#0-3) 

`userKeysToSign` calls `computeSignatureKey`, which deserializes raw transaction bytes, then makes async calls to `AccountCacheService` (and potentially the Hedera Mirror Node) for every account referenced in the transaction: [5](#0-4) 

**Pagination applied only after full processing:**

```typescript
return {
  totalItems: result.length,
  items: result.slice(offset, offset + limit),  // in-memory slice after full scan
  page,
  size,
};
``` [6](#0-5) 

The database and event loop bear the full O(N) cost regardless of the requested page size.

## Impact Explanation

- **Availability**: Node.js is single-threaded. Serially awaiting thousands of async DB/mirror-node calls inside one request handler blocks the event loop for all concurrent requests, causing timeouts and HTTP 503 responses for all users.
- **Memory**: Loading the full `transaction` table (with `groupItem` relations) into a JavaScript array before slicing exhausts heap memory as the table grows.
- **Database**: Each request triggers a full-table scan plus N relation queries, saturating the PostgreSQL connection pool.
- **No recovery path**: There is no circuit-breaker, timeout, or concurrency limit on this loop; a sufficiently large table makes the endpoint permanently unusable.

## Likelihood Explanation

- **Attacker preconditions**: A valid JWT token for any normal user — obtainable by registering an account. The controller applies only `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — no admin or privileged role required.
- **Grows worse over time**: Severity increases monotonically as the organization accumulates active transactions. The k6 load-test configuration explicitly targets 500 transactions (`SIGN_ALL_TRANSACTIONS: 500`) as a realistic scale, confirming the attack surface is expected in production. [7](#0-6) 
- **Single request is sufficient**: One request from one user can cause a multi-second stall; a handful of concurrent requests can take the service down.

## Recommendation

1. **Push pagination into the database query**: Add `skip: offset, take: limit` to the `repo.find()` call in `getTransactionsToSign`, matching the pattern used in `getTransactionsToApprove` and `getHistoryTransactions`.
2. **Pre-filter at the DB level**: Add a join/subquery to filter only transactions where the user has at least one matching key, so the per-row `userKeysToSign` loop operates on a small, already-filtered set.
3. **Parallelize or batch the async work**: Replace the serial `for...await` loop with `Promise.all` (with a concurrency limiter) to reduce wall-clock time.
4. **Add a hard maximum page size**: Enforce a server-side cap (e.g., 100 rows) on all paginated endpoints to prevent unbounded queries even if pagination parameters are omitted.

## Proof of Concept

```
GET /transactions/sign?page=1&size=10
Authorization: Bearer <any valid user JWT>
```

With 500+ active transactions in the database, the server will:
1. Execute `SELECT * FROM transaction WHERE status NOT IN (...)` with no `LIMIT` — returning all rows plus `groupItem` relations.
2. Serially call `computeSignatureKey` (deserialize bytes + async account lookups) for each of the 500 rows.
3. Return only 10 items to the caller, having done 500× the necessary work.

Repeating this request concurrently from multiple sessions (or a single automated client) will exhaust the Node.js event loop and PostgreSQL connection pool, causing service-wide degradation.

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

**File:** automation/k6/src/config/constants.ts (L36-38)
```typescript
export const DATA_VOLUMES = {
  SIGN_ALL_TRANSACTIONS: 500, // Requires 5 pages (500 txns for scaling test)
  READY_TO_SIGN: 200, // Requires 2 pages
```
