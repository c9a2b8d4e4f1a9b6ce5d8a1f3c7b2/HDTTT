### Title
Unbounded Transaction Fetch in `getTransactionsToSign` Enables Authenticated DoS via Memory and CPU Exhaustion

### Summary
`TransactionsService.getTransactionsToSign` fetches every non-terminal transaction from the database without a `take` (row limit) clause, then iterates over the full result set calling `userKeysToSign` per row before applying in-memory pagination. Any verified user can trigger `GET /transactions/sign` to force the server to load and process an unbounded number of rows, exhausting memory and CPU. A malicious user can amplify the impact by first creating many transactions, then repeatedly calling the endpoint.

### Finding Description

**Root cause — missing DB-level limit in `getTransactionsToSign`**

In `back-end/apps/api/src/transactions/transactions.service.ts` lines 295–309, the query has no `take` parameter:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no `take` / no `skip`
});

for (const transaction of transactions) {
  const keysToSign = await this.userKeysToSign(transaction, user);
  if (keysToSign.length > 0) result.push({ transaction, keysToSign });
}
```

Every other paginated method in the same service correctly passes `skip: offset, take: limit` to the ORM:
- `getTransactions` — `skip: offset, take: limit`
- `getHistoryTransactions` — `skip: offset, take: limit`
- `getTransactionsToApprove` — `skip: offset, take: limit`

Only `getTransactionsToSign` omits these, loading the entire non-terminal transaction table into the Node.js process heap, then calling `userKeysToSign` (a per-row async operation) for each row before slicing the result for the caller.

**Pagination guard does not protect the DB query**

`PaginationParams` caps the output page size at 100:

```typescript
if (size > 100) {
  throw new BadRequestException(ErrorCodes.IPP);
}
```

But this limit is applied only to the final `result.slice(offset, offset + limit)` — it has no effect on how many rows are fetched from the database or how many iterations of the `userKeysToSign` loop execute.

**Attacker-controlled entry point**

The endpoint is live and reachable by any verified user:

```typescript
@Get('/sign')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
getTransactionsToSign(
  @GetUser() user: User,
  @PaginationParams() paginationParams: Pagination,
  ...
)
```

A malicious verified user can:
1. Create a large number of transactions via `POST /transactions` (no documented per-user cap).
2. Repeatedly call `GET /transactions/sign?page=1&size=1` — each call loads all non-terminal rows and iterates over them.

### Impact Explanation

- **Memory exhaustion**: All non-terminal `Transaction` rows (with `groupItem` relation) are loaded into the Node.js heap per request. With thousands of rows, a single request can consume hundreds of MB.
- **CPU exhaustion**: `userKeysToSign` is called once per row in a sequential `for` loop. Each call may involve SDK deserialization and key-matching logic, making the per-request CPU cost proportional to the total transaction count.
- **Service degradation / crash**: Sustained calls cause the NestJS API process to OOM-crash or become unresponsive, denying service to all organization users — including legitimate signers and approvers who depend on the API for multi-sig workflows.

Severity: **High** — authenticated DoS that can permanently degrade or crash the shared API service for all tenants.

### Likelihood Explanation

- **Precondition**: A valid, verified organization account. Registration is a normal product flow; no privileged access is required.
- **Amplification**: The attacker creates transactions (valid product flow) to grow the unbounded list, then polls the endpoint. The cost to the attacker is low (one HTTP request per attack cycle); the cost to the server scales with total transaction count.
- **No rate-limit evidence found** in the codebase that would throttle this endpoint independently.
- The endpoint is marked `/* NO LONGER USED BY FRONT-END */` but remains fully exposed in the API.

### Recommendation

Apply a database-level limit inside `getTransactionsToSign`, mirroring the pattern used by every other paginated method in the same service:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // Add these two lines:
  skip: offset,
  take: limit,
});
```

Because `userKeysToSign` filters rows after the DB query, a DB-level limit will change semantics (pagination will be approximate). The correct fix is to push the signing-key check into the SQL query (as a JOIN or subquery), so the DB can filter and paginate in one pass — matching the approach already used in `getTransactionsToApprove` with its recursive `approverList` CTE.

Alternatively, if the endpoint is truly unused by the front-end, remove it entirely to eliminate the attack surface.

### Proof of Concept

1. Register and verify a user account on the organization back-end.
2. Create N transactions (e.g., N = 5 000) via `POST /transactions` using the verified account's key.
3. Issue a single authenticated request:
   ```
   GET /transactions/sign?page=1&size=1
   Authorization: Bearer <verified_jwt>
   ```
4. Observe: the API process executes `repo.find(...)` returning all N rows, then calls `userKeysToSign` N times in a loop before returning a single-item page.
5. Monitor Node.js heap usage — it grows proportionally to N. Repeat the request in a tight loop to sustain memory pressure and trigger OOM or severe latency for all other API consumers.

**Code references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** back-end/libs/common/src/decorators/pagination-params.decorator.ts (L22-24)
```typescript
  if (size > 100) {
    throw new BadRequestException(ErrorCodes.IPP);
  }
```
