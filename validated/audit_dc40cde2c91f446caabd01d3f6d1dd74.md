### Title
Unbounded Database Fetch in `getTransactionsToSign` Causes Server-Side Resource Exhaustion (DoS)

### Summary

`TransactionsService.getTransactionsToSign()` fetches every non-terminal transaction from the database with no row limit, then issues one async `userKeysToSign()` database call per row before applying pagination in memory. As the transaction table grows, a single authenticated API call to `GET /transactions/sign` will exhaust server memory, hold open database connections, and time out — degrading or crashing the API service for all users.

### Finding Description

In `back-end/apps/api/src/transactions/transactions.service.ts`, `getTransactionsToSign()` performs an unbounded `repo.find()` with no `take` constraint:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
});
``` [1](#0-0) 

It then iterates the entire result set, issuing one async database round-trip per transaction:

```typescript
for (const transaction of transactions) {
  const keysToSign = await this.userKeysToSign(transaction, user);
  if (keysToSign.length > 0) result.push({ transaction, keysToSign });
}
``` [2](#0-1) 

Pagination is applied only after the full in-memory result is built:

```typescript
items: result.slice(offset, offset + limit),
``` [3](#0-2) 

This is the direct analog of the `GovNFTFactory.govNFTs()` pattern: a getter that returns the entire registry without bounds. Every other paginated endpoint in the service correctly passes `skip: offset, take: limit` to the ORM query. [4](#0-3) 

The HTTP controller exposes this as `GET /transactions/sign`, guarded only by JWT authentication — no admin role required: [5](#0-4) 

The `PaginationParams` decorator enforces `size <= 100` on the HTTP layer, but this limit is never forwarded to the database query, so it provides no protection against the unbounded fetch. [6](#0-5) 

### Impact Explanation

With a large transaction table (thousands of rows, realistic in an active organization deployment):

- The Node.js process allocates memory proportional to the full result set plus all loaded relations.
- Each iteration of the loop holds a database connection open for the duration of the sequential `userKeysToSign()` calls.
- The request will time out at the HTTP layer, but the in-flight database work continues consuming resources.
- Repeated calls (even from a single user) can exhaust the database connection pool and heap memory, causing the API service to become unresponsive for all users.

**Impact category:** Service unavailability / severe degradation under realistic attacker input.

### Likelihood Explanation

- **Precondition:** Any registered, verified user with at least one uploaded key. No privileged role is required.
- **Trigger:** A single `GET /transactions/sign?page=1&size=1` request. The `size` parameter is irrelevant because the DB query is unbounded regardless.
- **Realism:** The endpoint is still active (the "NO LONGER USED BY FRONT-END" comment confirms it is not removed). Any authenticated API client or integrator can reach it. As the platform accumulates transactions over time, the impact worsens automatically without any attacker action.

### Recommendation

Apply the same `skip`/`take` pattern used by every other paginated endpoint. Because `userKeysToSign` requires per-row async logic that cannot be pushed into a single SQL query, the correct fix is to move the eligibility check into the database layer (as a SQL subquery, analogous to `getTransactionsToApprove`) so that pagination can be applied before data is loaded into memory.

Alternatively, as a short-term mitigation, add `take: limit` and `skip: offset` to the `repo.find()` call and accept that `totalItems` will be approximate — or deprecate and remove the endpoint entirely since the front-end no longer uses it.

### Proof of Concept

1. Register a normal user account and upload at least one key via `POST /user-keys`.
2. Ensure the organization has accumulated a large number of non-terminal transactions (e.g., thousands in `WAITING_FOR_SIGNATURES` status).
3. Send: `GET /transactions/sign?page=1&size=1` with a valid JWT.
4. Observe: the server loads all non-terminal transactions into memory, issues N sequential DB calls, and either times out or exhausts the connection pool. Concurrent legitimate requests to other endpoints stall or fail during this window. [7](#0-6)

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L251-317)
```typescript
  /* Get the transactions that a user needs to sign */
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
