### Title
Unbounded In-Memory Iteration in `getTransactionsToSign` Causes Server-Side Resource Exhaustion

### Summary
`getTransactionsToSign` in `back-end/apps/api/src/transactions/transactions.service.ts` fetches every non-terminal transaction from the database with no row-level cap, then issues an async database call per transaction to evaluate signing eligibility, and only applies pagination in memory after the full scan. An authenticated user who accumulates a large number of transactions can trigger this endpoint to exhaust server memory and database connections, analogous to the unbounded loop in the external `releaseTokens` report.

### Finding Description

**Root cause — no `take` limit on the database query:**

```typescript
// back-end/apps/api/src/transactions/transactions.service.ts  lines 295-309
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no `take` / `skip` here
});

for (const transaction of transactions) {
  const keysToSign = await this.userKeysToSign(transaction, user);   // async DB call per row
  if (keysToSign.length > 0) result.push({ transaction, keysToSign });
}
```

Pagination is applied only after the full scan:

```typescript
items: result.slice(offset, offset + limit),   // line 313
``` [1](#0-0) 

The endpoint is still registered and reachable despite the controller comment "NO LONGER USED BY FRONT-END": [2](#0-1) 

**Exploit path:**
1. Attacker registers as a normal user and obtains a JWT.
2. Attacker creates a large number of transactions via `POST /transactions` (no server-side creation cap was found).
3. Attacker calls `GET /transactions/sign` (authenticated, no privilege required).
4. The service loads every non-terminal transaction into the Node.js heap and fires one `userKeysToSign` DB call per row.
5. With enough rows the process runs out of memory or the DB connection pool is exhausted, degrading or crashing the API service for all users.

**Contrast with other endpoints** — `getTransactions` and `getTransactionsToApprove` both pass `skip`/`take` directly to the database query builder, so they are not affected: [3](#0-2) [4](#0-3) 

### Impact Explanation
A single authenticated user can cause the API process to exhaust heap memory and/or saturate the PostgreSQL connection pool, resulting in service unavailability for all organization users. Because the loop issues one async DB call per transaction row, the cost grows linearly with the number of transactions in the system — not with the number of concurrent attackers.

### Likelihood Explanation
- **Attacker preconditions:** valid JWT only; no admin or privileged role required.
- **Barrier:** transaction creation requires valid Hedera SDK transaction bytes and a registered user key, which is a non-trivial but achievable barrier for a determined attacker or a malicious insider.
- **Amplifier:** the endpoint is a legacy route still registered in the router, unlikely to be rate-limited or monitored.
- **No self-harm:** the attacker's own session is unaffected; only the shared API process degrades.

### Recommendation
Apply the database-level limit before the loop, mirroring the pattern used in `getTransactions`:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  skip: offset,
  take: limit,   // ← push pagination to the DB layer
});
```

If the full count is still needed for `totalItems`, issue a separate `count()` query with the same `where` clause. Alternatively, remove the endpoint entirely since it is already marked as unused by the front-end.

### Proof of Concept

1. Authenticate as a normal user; obtain `TOKEN`.
2. Create `N` transactions (e.g. `N = 50 000`) via `POST /transactions` with valid transaction bytes.
3. Issue:
   ```
   GET /transactions/sign?page=1&size=10
   Authorization: Bearer <TOKEN>
   ```
4. Observe: the API process loads all `N` transaction rows into heap, fires `N` async `userKeysToSign` DB calls, and either times out, returns an OOM error, or crashes the Node.js process — denying service to all concurrent users. [1](#0-0)

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L295-316)
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
