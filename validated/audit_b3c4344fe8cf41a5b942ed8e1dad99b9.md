All four claims check out against the actual code. Here is the audit report.

---

Audit Report

## Title
Unbounded Full-Table Scan with Per-Row Async DB Queries in `getTransactionsToSign` Enables Authenticated DoS

## Summary
`getTransactionsToSign` in `back-end/apps/api/src/transactions/transactions.service.ts` fetches every non-terminal transaction in the database with no row limit, then performs one async database call per row to evaluate signing requirements, before applying pagination in memory. A single authenticated HTTP request to the still-active `GET /transactions/sign` endpoint can exhaust Node.js heap memory and the PostgreSQL connection pool.

## Finding Description

**1. No database-level row limit and no user-scoping in the initial fetch.**

`whereForUser` filters only by terminal status; it does not constrain rows to the requesting user: [1](#0-0) 

The subsequent `repo.find()` call carries no `take` constraint, so every matching row in the entire `transaction` table is loaded into the Node.js heap: [2](#0-1) 

**2. Per-row async DB call inside the loop.**

For every loaded transaction, `userKeysToSign` is awaited individually — a classic N+1 pattern that issues one database (and potentially mirror-node) round-trip per row: [3](#0-2) 

**3. Pagination applied only after the full scan.**

The `limit`/`offset` values from `PaginationParams` are never forwarded to the database query. They are applied in-memory after the entire result set is built: [4](#0-3) 

**4. The endpoint remains active.**

Despite the comment "NO LONGER USED BY FRONT-END", `GET /transactions/sign` is still registered and protected only by standard JWT + verified-user guards — no admin role required: [5](#0-4) 

## Impact Explanation

A single authenticated request to `GET /transactions/sign?page=1&size=1` causes the server to:

1. Load the entire non-terminal portion of the `transaction` table into Node.js heap.
2. Execute one async DB round-trip per row via `userKeysToSign`.
3. Hold all results in memory before slicing to one item.

As the active transaction count grows (naturally over time, or accelerated by an attacker creating transactions), each invocation produces unbounded memory growth and a connection-pool storm. Repeated calls from one or more authenticated users can exhaust the Node.js heap and the PostgreSQL connection pool, making the API unavailable for all users — including transaction creation, signing, and execution flows.

## Likelihood Explanation

- **Attacker precondition**: Any verified, authenticated user. No admin or privileged role required.
- **Trigger**: A single HTTP GET to the still-active `GET /transactions/sign` endpoint.
- **Growth vector**: Transactions accumulate naturally; an attacker can also create many transactions to grow the active set.
- **No rate-limit bypass needed**: Resource exhaustion occurs within a single request as the active transaction count grows.

## Recommendation

1. **Push pagination to the database**: Pass `take` and `skip` to `repo.find()` inside `getTransactionsToSign`, mirroring the pattern used in `getTransactions` and `getHistoryTransactions`.
2. **Add a user-scoping join**: Filter the initial query to transactions where the user's keys are relevant (e.g., join against `transaction_signer` or `user_key`) so the working set is bounded per user, not per system.
3. **Eliminate the N+1 pattern**: Batch-load signing requirements for all candidate transactions in a single query rather than one `await` per row.
4. **Remove or gate the endpoint**: If `GET /transactions/sign` is no longer used by the front-end, remove the route or protect it with an admin guard to reduce the attack surface.

## Proof of Concept

```
# Any authenticated user issues:
GET /transactions/sign?page=1&size=1
Authorization: Bearer <valid_jwt>

# Server behavior:
# 1. Loads ALL non-terminal transactions (no LIMIT in SQL)
# 2. Calls userKeysToSign() once per row (N DB round-trips)
# 3. Slices result[0:1] and returns one item
# Repeated calls (or a large active-transaction table) exhaust
# Node.js heap and the PostgreSQL connection pool.
```

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L266-277)
```typescript
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
