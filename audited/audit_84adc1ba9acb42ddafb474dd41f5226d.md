### Title
Unbounded In-Memory Load in `getTransactionsToSign` Causes Authenticated DoS via Resource Exhaustion

### Summary
`getTransactionsToSign` in the API service fetches every matching transaction from the database into memory without any row limit, then processes each one with a sequential async call before applying pagination. Any authenticated user who accumulates a large number of pending transactions (or is added as a signer to many) can trigger unbounded memory and CPU consumption on the API server with a single request, degrading or crashing the service for all users.

### Finding Description

**Root cause — missing `take` in the database query:**

`getTransactions` and `getHistoryTransactions` both pass `skip: offset, take: limit` to TypeORM, bounding the result set to the page size. `getTransactionsToSign` does not:

```
back-end/apps/api/src/transactions/transactions.service.ts  lines 295-299
```
```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no `take` here
});
```

The entire table of non-terminal transactions is loaded into the Node.js process heap.

**Compounding factor — sequential async processing of every row:**

After the unbounded load, the service iterates every record and awaits an async key-check per row:

```
back-end/apps/api/src/transactions/transactions.service.ts  lines 301-309
```
```typescript
for (const transaction of transactions) {
  try {
    const keysToSign = await this.userKeysToSign(transaction, user);
    if (keysToSign.length > 0) result.push({ transaction, keysToSign });
  } catch (error) { console.log(error); }
}
```

**Pagination applied only after full load:**

```
back-end/apps/api/src/transactions/transactions.service.ts  line 313
```
```typescript
items: result.slice(offset, offset + limit),
```

Even a request for `page=1&size=1` forces the server to load and process every row.

**Reachable endpoint — still active, no privileged role required:**

```
back-end/apps/api/src/transactions/transactions.controller.ts  lines 156-178
```
```typescript
/* NO LONGER USED BY FRONT-END */
@Get('/sign')
getTransactionsToSign(
  @GetUser() user: User,
  @PaginationParams() paginationParams: Pagination,
  ...
```

The comment confirms the front-end no longer calls this route, but the route is still registered and guarded only by JWT + email-verification — no admin role required.

**Contrast with sibling methods that are correctly bounded:**

```
back-end/apps/api/src/transactions/transactions.service.ts  lines 175-181
```
```typescript
const findOptions: FindManyOptions<Transaction> = {
  ...
  skip: offset,
  take: limit,   // ← bounded
};
```

### Impact Explanation

A single HTTP request to `GET /transactions/sign?page=1&size=1` causes the API process to:
1. Execute an unbounded `SELECT` joining `transaction` and `groupItem` — potentially millions of rows.
2. Deserialize every row into TypeORM entity objects (heap allocation proportional to row count × row size, where each row can be up to 128 KB of `transactionBytes`).
3. Await one async DB/crypto call per row sequentially, holding the event loop.

Repeated requests (or a single request against a large dataset) exhaust Node.js heap memory and/or saturate the event loop, causing the API service to crash or become unresponsive for all users. Because the endpoint is still live and requires only a valid JWT, the impact is full API service unavailability.

### Likelihood Explanation

- **Attacker preconditions:** Valid account + email verification. No admin key, no leaked secret, no physical access.
- **Trigger:** A single `GET /transactions/sign?page=1&size=1` request.
- **Dataset amplification:** The attacker can self-amplify by creating many transactions (each up to 128 KB for privileged payers) or by being added as a signer to existing transactions. The `transactionBytes` column is `bytea` with no application-level cap at query time.
- **Repeatability:** The endpoint is stateless; the attacker can loop requests to sustain pressure.

### Recommendation

Apply the same `take: limit` / `skip: offset` pattern used by `getTransactions` and `getHistoryTransactions` directly in the database query, and move the key-eligibility filter into SQL rather than post-load application code. If the in-memory key-check cannot be pushed to SQL, add a hard cap (e.g., `take: 1000`) before the loop and document the trade-off. Additionally, consider removing or rate-limiting the `/transactions/sign` endpoint entirely since the front-end no longer uses it.

### Proof of Concept

1. Register two accounts (attacker + victim-org-admin) on the API.
2. As attacker, create N transactions (e.g., N = 10 000) each listing the attacker's key as a required signer. Each transaction body can be up to 6 KB (standard payer).
3. As attacker, send:
   ```
   GET /transactions/sign?page=1&size=1
   Authorization: Bearer <attacker_jwt>
   ```
4. Observe: the API process issues a single `SELECT` returning all N rows, allocates N entity objects (≥ 60 MB for N = 10 000 at 6 KB each), and awaits N sequential async calls before returning one item.
5. Repeat the request in a tight loop. Node.js heap grows until OOM or the event loop stalls, making the API unresponsive to all other users. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L301-313)
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

    return {
      totalItems: result.length,
      items: result.slice(offset, offset + limit),
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L156-178)
```typescript
  /* Get all transactions to be signed by the user */
  /* NO LONGER USED BY FRONT-END */
  @ApiOperation({
    summary: 'Get transactions to sign',
    description: 'Get all transactions to be signed by the current user.',
  })
  @ApiResponse({
    status: 200,
  })
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

**File:** back-end/libs/common/src/decorators/pagination-params.decorator.ts (L22-24)
```typescript
  if (size > 100) {
    throw new BadRequestException(ErrorCodes.IPP);
  }
```
