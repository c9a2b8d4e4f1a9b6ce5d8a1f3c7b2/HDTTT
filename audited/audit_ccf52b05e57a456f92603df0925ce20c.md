### Title
Unbounded Full-Table Scan and Per-Row Async Iteration in `getTransactionsToSign` Causes Server-Side Resource Exhaustion

### Summary
`getTransactionsToSign` in the API service fetches every active transaction in the database with no row limit, then executes an async `userKeysToSign` call (which itself issues additional database queries) for each row before applying pagination. A single authenticated user can trigger this endpoint to exhaust server memory and database connection pool by accumulating active transactions in the system, causing the API to become unresponsive for all users.

### Finding Description

**Root cause — no `take` limit on the database query:**

In `back-end/apps/api/src/transactions/transactions.service.ts`, `getTransactionsToSign` issues a `repo.find()` with no `take` parameter:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
});
```

The `whereForUser` filter only excludes terminal-status transactions (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `ARCHIVED`). There is **no user-scoped filter** — it loads every active transaction in the entire system. [1](#0-0) 

**Unbounded per-row async iteration:**

After loading the full result set into memory, the function iterates over every row and calls `userKeysToSign` for each one:

```typescript
for (const transaction of transactions) {
  const keysToSign = await this.userKeysToSign(transaction, user);
  if (keysToSign.length > 0) result.push({ transaction, keysToSign });
}
```

`userKeysToSign` delegates to `userKeysRequiredToSign`, which calls `attachKeys` (a DB query) and `keysRequiredToSign` (which calls `transactionSignatureService.computeSignatureKey` — another I/O-bound operation) for every single transaction. [2](#0-1) [3](#0-2) [4](#0-3) 

**Pagination is applied only after the full scan:**

```typescript
return {
  totalItems: result.length,
  items: result.slice(offset, offset + limit),
  ...
};
```

The `limit`/`offset` values from the request are never passed to the database query — they are used only to slice the already-computed in-memory array. [5](#0-4) 

**Contrast with `getTransactionsToApprove`**, which correctly passes `skip`/`take` to the database and never iterates in application code: [6](#0-5) 

### Impact Explanation

For a system with N active transactions:
- **Memory**: the entire active transaction table is loaded into the Node.js heap in a single request.
- **Database connections**: N sequential async calls to `userKeysToSign` each consume a connection from the pool (configured at `POSTGRES_MAX_POOL_SIZE=3` in production).
- **Latency**: response time grows linearly with N; at large N the request times out, holding the connection open and blocking other users.
- **Cascading failure**: because the query is not user-scoped, every authenticated user who calls this endpoint triggers the same full-table scan, compounding the load.

The result is full API unavailability for all users — a complete service denial.

### Likelihood Explanation

- **Attacker precondition**: a valid account on the organization backend (any registered user). No admin role required.
- **Trigger**: call `GET /transactions/sign` (the endpoint backed by `getTransactionsToSign`) once. The rate limiter (100 req/min per user) does not help because the damage is caused by a single request, not request volume.
- **Amplification**: the attacker does not need to create the transactions themselves. Any organic growth of the transaction table (other users' normal activity) increases the cost of each call. The attacker simply waits and then calls the endpoint.
- **Realistic scenario**: an organization running the tool for months will accumulate thousands of active transactions. At that scale, a single call to this endpoint will exhaust the DB pool and stall the server. [7](#0-6) 

### Recommendation

1. **Push pagination into the database query**: pass `take: limit` and `skip: offset` directly to `repo.find()`, mirroring the pattern used in `getTransactionsToApprove`.
2. **Add a user-scoped filter**: the query should only return transactions where the authenticated user is a signer, creator, or observer — not all active transactions in the system.
3. **Avoid per-row async I/O in a loop**: replace the sequential `for` loop with a single SQL query that joins `transaction_signer` against the user's keys, similar to the recursive CTE approach used in `getTransactionsToApprove`.
4. **Enforce a hard maximum page size**: cap `limit` at a reasonable value (e.g., 50) server-side so that even a crafted large-page request cannot bypass the fix.

### Proof of Concept

1. Register two accounts on the backend.
2. With account A, create 10,000 transactions (status `WAITING_FOR_SIGNATURES`).
3. With account B (any authenticated user), send:
   ```
   GET /transactions/sign?page=1&size=10
   ```
4. Observe: the server loads all 10,000 rows into memory, executes 10,000 sequential `userKeysToSign` calls (each hitting the DB), exhausts the connection pool (`POSTGRES_MAX_POOL_SIZE=3`), and the request either times out or causes the Node.js process to OOM-crash.
5. During step 4, all other API requests from all users are blocked or fail with connection-pool errors. [8](#0-7)

### Citations

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L875-877)
```typescript
  async userKeysToSign(transaction: Transaction, user: User, showAll: boolean = false) {
    return userKeysRequiredToSign(transaction, user, this.transactionSignatureService, this.entityManager, showAll);
  }
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L96-115)
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
};
```

**File:** back-end/apps/api/src/throttlers/user-throttler.module.ts (L13-22)
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
```
