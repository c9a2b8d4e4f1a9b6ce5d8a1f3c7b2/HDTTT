### Title
Unbounded Full-Table Scan with Per-Row Async DB Queries in `getTransactionsToSign` Enables Authenticated DoS

### Summary
`getTransactionsToSign` in the API service fetches **all** non-terminal transactions from the database without any row limit, then performs one async database call per transaction to evaluate signing requirements, before applying pagination in memory. As the number of active transactions grows, a single authenticated API request can exhaust server memory and database connections, causing service degradation or unavailability for all users.

### Finding Description

**Root cause — no database-level limit on the initial fetch:**

In `back-end/apps/api/src/transactions/transactions.service.ts`, `getTransactionsToSign` calls `this.repo.find()` with no `take` constraint: [1](#0-0) 

The `whereForUser` filter only excludes terminal statuses (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `ARCHIVED`). It does **not** scope the query to the requesting user — it loads every active transaction in the entire system into memory.

**Per-row async DB call inside the loop:**

For each of those transactions, `userKeysToSign` is called — an async operation that itself performs database and potentially mirror-node queries: [2](#0-1) 

**Pagination applied only after the full scan:**

The `take`/`skip` values from `PaginationParams` are never passed to the database query. Pagination is applied in-memory after the entire result set is built: [3](#0-2) 

**The endpoint is still publicly reachable:**

The controller registers `GET /transactions/sign` and the comment "NO LONGER USED BY FRONT-END" does not remove it from the running API: [4](#0-3) 

The `PaginationParams` decorator enforces `size <= 100` on the *response slice*, but places no constraint on how many rows are fetched from the database: [5](#0-4) 

### Impact Explanation

A single authenticated user issuing `GET /transactions/sign?page=1&size=1` causes the server to:
1. Load the entire `transaction` table (all non-terminal rows) into Node.js heap memory.
2. Execute one async DB round-trip per row via `userKeysToSign`.
3. Hold all results in memory before slicing to one item.

With thousands of active transactions (realistic in an organization with many users), this produces unbounded memory growth and a connection-pool storm on every invocation. Repeated calls from one or more authenticated users can exhaust the Node.js heap and the PostgreSQL connection pool, making the API unavailable for all users — including transaction creation, signing, and execution flows.

### Likelihood Explanation

- **Attacker precondition**: Any verified, authenticated user. No admin or privileged role required.
- **Trigger**: A single HTTP GET request to the still-active endpoint `GET /transactions/sign`.
- **Growth vector**: Transactions accumulate naturally over time; an attacker can also create many transactions to accelerate the growth of the active set.
- **No rate-limit bypass needed**: The resource exhaustion occurs within a single request as the active transaction count grows.

### Recommendation

1. **Apply database-level pagination immediately**: Pass `take: limit` and `skip: offset` to `this.repo.find()` so the DB returns at most `limit` rows per request, mirroring the pattern used in `getHistoryTransactions`.
2. **Scope the initial query to the requesting user**: Add a user-scoped `WHERE` clause (e.g., filter by `signers.userId`, `creatorKey.userId`, or approver membership) at the database level before iterating.
3. **Remove or gate the deprecated endpoint**: Since the front-end no longer uses `GET /transactions/sign`, either remove the route or protect it with an admin-only guard to reduce the attack surface.
4. **Replace the per-row loop with a set-based query**: Compute signing eligibility in a single SQL query (as done for `getTransactionsToApprove` with the recursive CTE) rather than N individual async calls.

### Proof of Concept

**Preconditions**: Authenticated user account; organization with ≥ N active (non-terminal) transactions.

**Steps**:
1. Obtain a valid JWT for any verified user.
2. Issue: `GET /transactions/sign?page=1&size=1` with the JWT.
3. The server executes `repo.find({ where: { status: Not(In([...terminalStatuses])) } })` — no `take` — loading all N active transactions.
4. For each of the N transactions, `userKeysToSign` fires an async DB query.
5. With N = 10,000 active transactions, the server allocates memory for 10,000 ORM entities and opens up to 10,000 sequential DB round-trips before returning a single-item page.
6. Repeating the request (or issuing it concurrently from multiple sessions) exhausts the Node.js heap and PostgreSQL connection pool, causing HTTP 500 / connection timeout responses for all API consumers.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L295-309)
```typescript
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
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L311-317)
```typescript
    return {
      totalItems: result.length,
      items: result.slice(offset, offset + limit),
      page,
      size,
    };
  }
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

**File:** back-end/libs/common/src/decorators/pagination-params.decorator.ts (L13-29)
```typescript
export const PaginationParams = createParamDecorator((data, ctx: ExecutionContext): Pagination => {
  const req: Request = ctx.switchToHttp().getRequest();
  const page = parseInt(req.query.page as string);
  const size = parseInt(req.query.size as string);

  if (isNaN(page) || page <= 0 || isNaN(size) || size < 0) {
    throw new BadRequestException(ErrorCodes.IPP);
  }

  if (size > 100) {
    throw new BadRequestException(ErrorCodes.IPP);
  }

  // calculate pagination parameters
  const limit = size;
  const offset = (page - 1) * limit;
  return { page, limit, size, offset };
```
