### Title
Unbounded Database Query in `getTransactionsToSign` Enables Authenticated Resource Exhaustion

### Summary
The `GET /transactions/sign` API endpoint in the back-end API service fetches every non-terminal transaction from the database without any row limit before applying in-memory filtering and pagination. Any authenticated user can trigger this endpoint to force the server to load an unbounded number of transaction rows and execute a per-row async database call for each one, exhausting server memory and CPU and causing service degradation or crash.

### Finding Description
In `back-end/apps/api/src/transactions/transactions.service.ts`, the `getTransactionsToSign` method accepts a `Pagination` object (page, limit, size, offset) but never passes `take` or `skip` to the repository query:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no `take`, no `skip`
});
```

After loading the entire result set into memory, it iterates every row and issues an additional async database call per transaction:

```typescript
for (const transaction of transactions) {
  const keysToSign = await this.userKeysToSign(transaction, user);
  ...
}
```

Pagination is applied only after all work is done:

```typescript
items: result.slice(offset, offset + limit),
```

The controller registers this endpoint as `GET /transactions/sign` and it is fully reachable by any authenticated, verified user:

```typescript
/* NO LONGER USED BY FRONT-END */
@Get('/sign')
getTransactionsToSign(
  @GetUser() user: User,
  @PaginationParams() paginationParams: Pagination,
  ...
)
```

The `PaginationParams` decorator enforces `size ≤ 100`, but this only controls the slice returned to the caller — it has no effect on how many rows are fetched from the database.

By contrast, the analogous `getTransactionsToApprove` and `getHistoryTransactions` methods correctly pass `skip: offset, take: limit` to the query, confirming this is an oversight specific to `getTransactionsToSign`.

### Impact Explanation
A single authenticated HTTP request to `GET /transactions/sign?page=1&size=1` causes the server to:
1. Load all non-terminal transactions (potentially thousands) into Node.js heap memory with their `groupItem` relations.
2. Execute one additional async database round-trip per transaction row via `userKeysToSign`.

Repeated calls (within the per-user rate limit of 100/minute) compound memory pressure. On a production instance with a large transaction backlog, a single user can cause OOM crashes or sustained CPU saturation, making the API unavailable to all users.

### Likelihood Explanation
The attacker precondition is only a valid registered account — no admin access, no leaked credentials. The endpoint is publicly documented via Swagger (`@ApiOperation`, `@ApiResponse`) and is reachable over HTTPS. The comment `/* NO LONGER USED BY FRONT-END */` confirms the endpoint was intentionally left registered. The per-user throttle (100 req/min) does not prevent a single large query from consuming unbounded memory.

### Recommendation
Apply database-level pagination in `getTransactionsToSign` identically to how `getTransactionsToApprove` does it — pass `take: limit` and `skip: offset` to the repository query and perform the signer-key check only on the paginated subset. If the full count is needed for `totalItems`, issue a separate `COUNT` query with the same `WHERE` clause. Alternatively, if the endpoint is truly unused, remove it entirely.

### Proof of Concept
1. Register a normal user account and obtain a JWT.
2. As an admin or via seeding, create a large number of transactions (e.g., 10,000) in a non-terminal status.
3. Issue: `GET /transactions/sign?page=1&size=1` with the user's JWT.
4. Observe: the server loads all 10,000 transaction rows into memory and executes 10,000 sequential `userKeysToSign` DB calls before returning a single-item response.
5. Repeat within the 100 req/min rate limit to sustain memory pressure and degrade or crash the API service.

---

**Root cause references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Contrast with correctly paginated sibling methods:** [5](#0-4) 

**Rate-limit context (does not bound per-request DB load):** [6](#0-5) [7](#0-6)

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

**File:** back-end/apps/api/src/throttlers/user-throttler.module.ts (L13-24)
```typescript
        throttlers: [
          {
            name: 'user-minute',
            ttl: seconds(60),
            limit: 100,
          },
          {
            name: 'user-second',
            ttl: seconds(1),
            limit: 10,
          },
        ],
```

**File:** back-end/libs/common/src/decorators/pagination-params.decorator.ts (L18-24)
```typescript
  if (isNaN(page) || page <= 0 || isNaN(size) || size < 0) {
    throw new BadRequestException(ErrorCodes.IPP);
  }

  if (size > 100) {
    throw new BadRequestException(ErrorCodes.IPP);
  }
```
