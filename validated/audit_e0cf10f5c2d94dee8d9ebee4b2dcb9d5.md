### Title
Unbounded Full-Table Scan with Per-Row Async Processing in `getTransactionsToSign` Causes Server-Side Resource Exhaustion DoS

### Summary
`getTransactionsToSign` in `transactions.service.ts` fetches every active transaction from the database with no row limit, then performs an expensive async cryptographic key-resolution call (`userKeysToSign`) for each row before applying pagination in memory. Any authenticated user can trigger this endpoint. As the transaction table grows, each request consumes unbounded CPU, memory, and database connection time, degrading or crashing the API service for all users.

### Finding Description

**Root cause — no `take` on the query:**

In `back-end/apps/api/src/transactions/transactions.service.ts` the function `getTransactionsToSign` (lines 252–317) accepts pagination parameters but never passes them to the database query:

```typescript
// lines 295-299 — no `take` / `skip`
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
});
```

Compare this with every other paginated query in the same file (e.g. `getTransactions` at line 179, `getTransactionsToApprove` at line 349) which correctly pass `skip: offset, take: limit` to the ORM.

**Per-row async work:**

After loading the full table, the function iterates every row and awaits an expensive operation:

```typescript
// lines 301-308
for (const transaction of transactions) {
  try {
    const keysToSign = await this.userKeysToSign(transaction, user);
    if (keysToSign.length > 0) result.push({ transaction, keysToSign });
  } catch (error) { ... }
}
```

`userKeysToSign` → `computeSignatureKey` (in `back-end/libs/common/src/transaction-signature/transaction-signature.service.ts`, lines 38–62) deserializes raw transaction bytes, then makes async calls to `AccountCacheService` and potentially the Hedera Mirror Node for every account referenced in the transaction. This is O(N × M) work where N is the total number of active transactions and M is the number of accounts per transaction.

**Pagination applied only after full processing:**

```typescript
// lines 311-316
return {
  totalItems: result.length,
  items: result.slice(offset, offset + limit),  // sliced in-memory after full scan
  page,
  size,
};
```

The database and event loop bear the full cost regardless of the requested page size.

**Exploit path:**

1. Attacker registers as a normal user (no privilege required).
2. Attacker (or many users) calls `GET /transactions/sign` (the endpoint wired to `getTransactionsToSign` in `transactions.controller.ts`).
3. The server fetches every row in the `transaction` table with status not in `[EXECUTED, FAILED, EXPIRED, CANCELED, ARCHIVED]`, loads `groupItem` relations, then serially awaits `userKeysToSign` for each row.
4. With a large transaction table (the k6 load tests seed 500 transactions per user — `automation/k6/src/config/constants.ts` line 37), a single request can hold a database connection and Node.js event-loop ticks for seconds to minutes, starving other requests.
5. Concurrent requests from multiple users multiply the effect.

### Impact Explanation

- **Availability**: The Node.js event loop is single-threaded. Awaiting thousands of async DB/mirror-node calls serially inside one request handler blocks the loop for all concurrent requests, causing timeouts and HTTP 503 responses for all users of the API service.
- **Memory**: Loading the full `transaction` table (with relations) into a JavaScript array before slicing exhausts heap memory as the table grows.
- **Database**: Each request opens a full-table scan plus N relation queries, saturating the PostgreSQL connection pool.
- **No recovery path**: The service has no circuit-breaker or timeout on this loop; a sufficiently large table makes the endpoint permanently unusable.

### Likelihood Explanation

- **Attacker preconditions**: A valid JWT token for any normal user — obtainable by registering an account.
- **No special knowledge required**: The endpoint is a standard REST GET call.
- **Grows worse over time**: The severity increases monotonically as the organization accumulates transactions. The load-test configuration explicitly targets 500 transactions per user, confirming realistic scale.
- **Single request is sufficient**: One request from one user can cause a multi-second stall; a handful of concurrent requests can take the service down.

### Recommendation

Apply database-level pagination before the loop, and push the key-eligibility filter into the query rather than filtering in application memory:

```typescript
// Apply take/skip at the DB level
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  take: limit,
  skip: offset,
});
```

Ideally, move the `userKeysToSign` check into a SQL subquery (as already done for `getTransactionsToApprove`) so the database returns only the rows the user can sign, eliminating the per-row async loop entirely.

### Proof of Concept

1. Seed the backend with a large number of active transactions (e.g. using the existing k6 seed script with `SIGN_ALL_TRANSACTIONS: 500`).
2. Authenticate as a normal user and obtain a JWT.
3. Issue a single request:
   ```
   GET /transactions/sign?page=1&limit=10
   ```
4. Observe that response time scales linearly with the total number of active transactions in the database, not with the requested page size of 10.
5. With 500+ active transactions, the request will time out or take tens of seconds, blocking the Node.js event loop and degrading all concurrent API calls.

**Relevant code locations:**

- Unbounded query: [1](#0-0) 
- Per-row async loop: [2](#0-1) 
- In-memory pagination (applied too late): [3](#0-2) 
- Expensive per-row work (`computeSignatureKey`): [4](#0-3) 
- Correct paginated pattern (contrast): [5](#0-4) 
- Load-test scale confirming realistic transaction volumes: [6](#0-5)

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

**File:** automation/k6/src/config/constants.ts (L36-48)
```typescript
export const DATA_VOLUMES = {
  SIGN_ALL_TRANSACTIONS: 500, // Requires 5 pages (500 txns for scaling test)
  READY_TO_SIGN: 200, // Requires 2 pages
  DRAFTS: 100,
  READY_FOR_REVIEW: 100, // Also used for approve transactions
  CONTACTS: 100,
  ACCOUNTS: 100,
  FILES: 100,
  HISTORY: 500, // Requires 5 pages
  GROUP_SIZE: 500, // Transactions per group for Sign All testing (500 txn scaling)
  COMPLEX_KEY_GROUP_SIZE: 100, // Complex key tests use smaller group (17 sigs per txn)
  READY_FOR_EXECUTION: 100, // Transactions ready to submit to Hedera
};
```
