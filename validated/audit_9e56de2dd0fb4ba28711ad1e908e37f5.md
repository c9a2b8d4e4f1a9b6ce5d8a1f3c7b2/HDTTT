All four required checks pass. The code evidence is exact and the SECURITY.md exclusion for "Impacts that only require DDoS" does not cover this — the root cause is a code defect (missing `take` in a TypeORM query), not a volumetric network attack. A single authenticated HTTP request triggers it.

---

Audit Report

## Title
Unbounded In-Memory Load in `getTransactionsToSign` Causes Authenticated DoS via Resource Exhaustion

## Summary
`getTransactionsToSign` in `transactions.service.ts` fetches every non-terminal transaction from the database into memory with no row limit, then sequentially awaits an async key-check per row before slicing the result for pagination. Any authenticated user can trigger unbounded heap allocation and event-loop saturation with a single HTTP request to `GET /transactions/sign`.

## Finding Description

**Missing `take` in the database query (`transactions.service.ts` lines 295–299):**

`getTransactionsToSign` calls `this.repo.find()` without a `take` parameter, loading every non-terminal transaction row into the Node.js heap. [1](#0-0) 

**Sequential async processing of every loaded row (lines 301–309):**

After the unbounded load, the service iterates every record and `await`s `userKeysToSign` per row, holding the event loop for the full duration. [2](#0-1) 

**Pagination applied only after full load (line 313):**

`result.slice(offset, offset + limit)` is called on the already-fully-processed in-memory array. A request for `page=1&size=1` still forces the server to load and process every row. [3](#0-2) 

**Contrast with sibling methods that are correctly bounded:**

`getTransactions` and `getHistoryTransactions` both pass `skip: offset, take: limit` to TypeORM, bounding the result set to the page size. [4](#0-3) [5](#0-4) 

**Endpoint still registered, guarded only by JWT + email verification:**

The controller comment explicitly notes the route is no longer used by the front-end, yet it remains registered. The controller-level guards are `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — no admin role required. [6](#0-5) [7](#0-6) 

## Impact Explanation

A single `GET /transactions/sign?page=1&size=1` request causes the API process to:
1. Execute an unbounded `SELECT` joining `transaction` and `groupItem` — potentially the entire non-terminal transaction table.
2. Deserialize every row into TypeORM entity objects (heap allocation proportional to row count × row size; `transactionBytes` is a `bytea` column with no application-level cap at query time).
3. Await one async DB/crypto call per row sequentially, blocking the Node.js event loop.

Repeated requests (or a single request against a sufficiently large dataset) exhaust Node.js heap memory and/or saturate the event loop, causing the API service to crash or become unresponsive for all users.

## Likelihood Explanation

- **Attacker preconditions:** Valid account + email verification only. No admin key, no leaked secret, no physical access required.
- **Trigger:** A single `GET /transactions/sign?page=1&size=1` HTTP request.
- **Dataset amplification:** The attacker can self-amplify by creating many transactions or by being added as a signer to existing transactions. The `transactionBytes` column is `bytea` with no application-level size cap enforced at query time.
- **Repeatability:** The endpoint is stateless; the attacker can loop requests to sustain pressure.

## Recommendation

1. **Add `take: limit` to the `repo.find()` call in `getTransactionsToSign`** — this is the minimal fix and mirrors the pattern already used in `getTransactions` and `getHistoryTransactions`.
2. **Remove or formally deprecate the `/sign` endpoint** — the code comment already acknowledges the front-end no longer calls it. Removing it eliminates the attack surface entirely.
3. **Consider parallelising `userKeysToSign` calls** (e.g., `Promise.all`) to reduce event-loop hold time once the row limit is in place.

## Proof of Concept

```
# Authenticated request — triggers unbounded SELECT + sequential async processing
curl -H "Authorization: Bearer <valid_jwt>" \
     "https://<api-host>/transactions/sign?page=1&size=1"
```

With a large number of non-terminal transactions in the database, the API process will spike in memory and CPU. Repeating the request sustains the pressure. The server becomes unresponsive for all concurrent users until the Node.js process is restarted or OOM-killed.

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L233-235)
```typescript
      relations: ['groupItem', 'groupItem.group'],
      skip: offset,
      take: limit,
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

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L56-57)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
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
