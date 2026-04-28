### Title
Unbounded In-Memory Iteration in `getTransactionsToSign` Causes Escalating DoS

### Summary
`GET /transactions/sign` fetches every non-terminal transaction from the database with no row limit, then performs an expensive per-transaction async operation (`userKeysToSign`) inside a sequential `for` loop before applying pagination in memory. As the transaction table grows, each call to this endpoint consumes proportionally more CPU, memory, and database connections. Any authenticated user can trigger this path, and a malicious user can deliberately inflate the transaction count to degrade or stall the API service.

### Finding Description

**Root cause — no `take` limit on the initial query:**

In `getTransactionsToSign`, the repository `find` call has no `take` parameter:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no `take` / `skip`
});
``` [1](#0-0) 

Every non-terminal transaction in the database is loaded into memory.

**Per-transaction async work inside the loop:**

```typescript
for (const transaction of transactions) {
  const keysToSign = await this.userKeysToSign(transaction, user);
  if (keysToSign.length > 0) result.push({ transaction, keysToSign });
}
``` [2](#0-1) 

`userKeysToSign` → `userKeysRequiredToSign` → `keysRequiredToSign`, which deserializes the transaction bytes, calls `transactionSignatureService.computeSignatureKey` (cryptographic work), and may issue a `UserKey` database query per transaction: [3](#0-2) [4](#0-3) 

**Pagination applied only after full iteration:**

```typescript
return {
  totalItems: result.length,
  items: result.slice(offset, offset + limit),  // ← in-memory slice
  ...
};
``` [5](#0-4) 

The `limit`/`offset` from `@PaginationParams()` never reach the database query; they only slice the already-computed result array.

**Exposed endpoint — any verified user:**

```typescript
@Get('/sign')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
getTransactionsToSign(@GetUser() user, @PaginationParams() paginationParams, ...)
``` [6](#0-5) 

No admin role is required.

### Impact Explanation
With N active transactions in the database, each call to `GET /transactions/sign` performs O(N) deserialization operations, O(N) cryptographic signature-key computations, and up to O(N) database round-trips. At scale this exhausts the Node.js event loop, PostgreSQL connection pool, and heap memory, causing request timeouts and cascading failures across the API service. All users — not just the attacker — lose access to the service.

### Likelihood Explanation
The attacker only needs a valid JWT (any registered, verified user). They can create transactions via `POST /transactions` to inflate N, then repeatedly call `GET /transactions/sign` to amplify resource consumption. No privileged access, leaked credentials, or external dependencies are required. Organic platform growth alone (without any malicious intent) will degrade this endpoint over time.

### Recommendation
1. **Push pagination into the database query** — pass `take: limit` and `skip: offset` to the `repo.find` call so the database returns only the page of rows needed.
2. **Pre-filter in SQL** — add a subquery or join that restricts results to transactions where the user's keys are actually required, eliminating the per-row `userKeysToSign` loop entirely for non-matching rows.
3. **Cap maximum page size** — enforce a hard upper bound (e.g., 100) on `limit` in the `PaginationParams` decorator to prevent a single request from requesting an arbitrarily large slice.

### Proof of Concept

**Setup:**
1. Register and verify a user account (attacker).
2. Create a large number of transactions via `POST /transactions` (e.g., 10 000 transactions with valid `transactionBytes`).

**Trigger:**
```
GET /transactions/sign?page=1&size=10
Authorization: Bearer <attacker_jwt>
```

**Expected (vulnerable) behaviour:**
- The server loads all 10 000 transactions into memory.
- For each transaction, it deserializes bytes and computes the signature key.
- Response time grows linearly with N; at sufficient scale the request times out (HTTP 504) and the Node.js process becomes unresponsive to other requests.
- Legitimate users calling any API endpoint experience degraded or no service.

**Confirmation:** Instrument the service with timing logs around the `for` loop and observe that elapsed time scales linearly with the number of non-terminal transactions in the database.

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
