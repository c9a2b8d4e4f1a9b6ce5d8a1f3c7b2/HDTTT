The code confirms all claims in the report. Here is the audit:

---

Audit Report

## Title
Unbounded Database Query in `getTransactionsToSign` Enables Authenticated Resource Exhaustion

## Summary
The `GET /transactions/sign` endpoint in the back-end API service fetches every non-terminal transaction from the database without any row limit, then issues one additional async database call per row before applying pagination. Any authenticated, verified user can trigger this to exhaust server memory and CPU.

## Finding Description
In `back-end/apps/api/src/transactions/transactions.service.ts`, the `getTransactionsToSign` method receives a `Pagination` object but the `repo.find()` call omits both `take` and `skip`:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no take, no skip
});
``` [1](#0-0) 

After loading the full result set into heap memory, the method iterates every row and issues an async database round-trip per transaction:

```typescript
for (const transaction of transactions) {
  const keysToSign = await this.userKeysToSign(transaction, user);
  ...
}
``` [2](#0-1) 

Pagination is applied only after all work is complete:

```typescript
items: result.slice(offset, offset + limit),
``` [3](#0-2) 

By contrast, both `getHistoryTransactions` and `getTransactionsToApprove` correctly pass `skip: offset, take: limit` to the query, confirming this is an oversight specific to `getTransactionsToSign`: [4](#0-3) [5](#0-4) 

The endpoint is registered and reachable by any authenticated, verified user: [6](#0-5) 

## Impact Explanation
A single HTTP request to `GET /transactions/sign?page=1&size=1` causes the server to:
1. Load **all** non-terminal transactions (potentially thousands) with their `groupItem` relations into Node.js heap memory.
2. Execute **one additional async database round-trip per row** via `userKeysToSign`.

This can exhaust server memory (OOM crash) or saturate CPU/DB connection pool, making the API unavailable to all users. The `PaginationParams` decorator enforces `size ≤ 100`, but this only controls the slice returned to the caller — it has no effect on how many rows are fetched from the database. [7](#0-6) 

## Likelihood Explanation
The attacker precondition is only a valid registered account — no admin access or leaked credentials required. The endpoint is publicly documented via Swagger (`@ApiOperation`, `@ApiResponse`) and is reachable over HTTPS. The comment `/* NO LONGER USED BY FRONT-END */` confirms the endpoint was intentionally left registered. The per-user throttle (100 req/min) does not prevent a single large query from consuming unbounded memory. [8](#0-7) 

## Recommendation
Apply database-level pagination in `getTransactionsToSign` by passing `take` and `skip` to the `repo.find()` call, mirroring the pattern already used in `getHistoryTransactions` and `getTransactionsToApprove`:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  skip: offset,
  take: limit,
});
```

Note that because `userKeysToSign` filters rows post-query, applying DB-level pagination changes the semantics (total count will be approximate). A more complete fix would push the key-matching logic into the database query itself, or accept the semantic trade-off and document it. Additionally, consider removing or disabling the endpoint entirely if it is confirmed to be unused by the front-end. [1](#0-0) 

## Proof of Concept
1. Register and verify a user account on the API.
2. Obtain a valid JWT token.
3. Send a single request:
   ```
   GET /transactions/sign?page=1&size=1
   Authorization: Bearer <token>
   ```
4. The server will execute `SELECT * FROM transaction WHERE status NOT IN (...)` with no `LIMIT`, loading all non-terminal rows and their `groupItem` relations into memory, followed by one `userKeysRequiredToSign` database call per row.
5. On a production instance with a large transaction backlog, this single request will cause measurable memory and CPU spikes. Repeated calls within the 100 req/min rate limit compound the pressure. [9](#0-8)

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

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L157-178)
```typescript
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
