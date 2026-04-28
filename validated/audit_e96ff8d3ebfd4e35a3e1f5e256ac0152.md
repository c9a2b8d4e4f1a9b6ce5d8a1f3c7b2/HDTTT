### Title
Unbounded Full-Table Scan in `getTransactionsToSign` Enables Authenticated DoS

### Summary
`getTransactionsToSign()` in `transactions.service.ts` fetches **every** non-terminal transaction in the database without a `take` limit, then iterates over all of them in-process calling `userKeysToSign()` (which invokes `computeSignatureKey()` and hits the mirror node) for each one. Pagination is applied only after the full scan completes. Any authenticated user can inflate the transaction table by repeatedly creating transactions, causing the endpoint to exhaust server memory, CPU, and mirror-node connections for all callers.

### Finding Description

**Root cause — no `take` limit on the bulk fetch:**

In `back-end/apps/api/src/transactions/transactions.service.ts` lines 295–299, the query has no `take` clause:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
});
```

The `whereForUser` filter only excludes terminal statuses (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `ARCHIVED`). It does **not** filter by the requesting user, so it returns every active transaction in the system.

**Unbounded per-item async work:**

Lines 301–309 then iterate over the full result set, calling `userKeysToSign()` for every row:

```typescript
for (const transaction of transactions) {
  const keysToSign = await this.userKeysToSign(transaction, user);
  if (keysToSign.length > 0) result.push({ transaction, keysToSign });
}
```

`userKeysToSign()` calls `keysRequiredToSign()` → `transactionSignatureService.computeSignatureKey()`, which deserializes the transaction bytes and makes outbound mirror-node HTTP calls per transaction.

**Pagination applied after full scan:**

Line 313 slices the already-computed result:

```typescript
items: result.slice(offset, offset + limit),
```

So even a request for `page=1&size=1` forces the server to process every active transaction.

**Attacker-controlled growth path:**

`POST /transactions` (accessible to any authenticated user) inserts rows that remain in `WAITING_FOR_SIGNATURES` status indefinitely until signed and executed. There is no per-user transaction count cap visible in the codebase.

**Endpoint still active:**

The controller comment says `/* NO LONGER USED BY FRONT-END */`, but `GET /transactions/sign` is still a registered, authenticated route callable by any API client.

### Impact Explanation

- **Memory exhaustion:** TypeORM loads all matching `Transaction` rows (with `groupItem` relation) into the Node.js heap simultaneously.
- **CPU/event-loop exhaustion:** Each row triggers synchronous deserialization of `transactionBytes` and an async mirror-node lookup.
- **Mirror-node connection exhaustion:** N sequential mirror-node calls per request; with thousands of rows this saturates the outbound HTTP pool and causes cascading timeouts.
- **Denial of service for all users:** Because the filter is system-wide (not per-user), a single attacker inflating the table degrades or crashes the endpoint for every caller.

### Likelihood Explanation

- Precondition: valid authenticated account (normal user, no admin privileges required).
- Attack: register an account, call `POST /transactions` in a loop to create thousands of `WAITING_FOR_SIGNATURES` transactions. Each creation requires only valid transaction bytes and a creator key — both are trivially constructable.
- Trigger: call `GET /transactions/sign` (or cause another user to call it). The server will attempt to process every row.
- No rate-limiting or per-user transaction cap was found in the codebase.

### Recommendation

1. **Apply `take` at the database level** — pass `limit` into `this.repo.find({ ..., take: limit, skip: offset })` and filter by the requesting user's keys at the SQL layer (join against `transaction_signer` or `user_key`), mirroring the approach used in `getTransactions()`.
2. **Remove or gate the endpoint** — if `GET /transactions/sign` is no longer used by the front-end, either delete the route or protect it with an admin guard to reduce attack surface.
3. **Add a per-user transaction creation rate limit** to bound the growth rate of the table.

### Proof of Concept

1. Authenticate as a normal user; obtain a JWT.
2. In a loop, `POST /transactions` with valid (but never-to-be-signed) transaction bytes and the user's `creatorKeyId`. Repeat N times (e.g., N = 5,000). Each transaction lands in `WAITING_FOR_SIGNATURES`.
3. Call `GET /transactions/sign?page=1&size=1` with any authenticated token.
4. The server executes `this.repo.find({...})` returning all N rows, then calls `userKeysToSign()` + `computeSignatureKey()` + mirror-node HTTP for each row sequentially.
5. Observed outcome: request timeout / OOM crash / mirror-node connection pool exhaustion, denying service to all concurrent users of the endpoint.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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
