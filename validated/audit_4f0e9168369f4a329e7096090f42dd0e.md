### Title
Unbounded In-Memory Iteration in `getTransactionsToSign` Enables Server-Side DoS via Resource Exhaustion

### Summary
The `getTransactionsToSign` function in `transactions.service.ts` fetches **all** matching transactions from the database without any SQL-level `LIMIT`, then iterates over every record in memory — issuing an additional async database call per transaction via `userKeysToSign`. Although the function accepts pagination parameters, they are applied only after the full unbounded scan completes. Any authenticated user can trigger this path, and as the transaction table grows, each call consumes unbounded memory, CPU, and database connections, degrading or crashing the API service.

### Finding Description

**Root cause — no `take` on the initial query:**

In `back-end/apps/api/src/transactions/transactions.service.ts`, `getTransactionsToSign` builds a `FindManyOptions` object that intentionally omits `take`/`skip`:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
});                                          // ← no take/skip
``` [1](#0-0) 

**N+1 async DB call per row:**

After loading every row, the code loops over the full result set and issues an async call for each transaction:

```typescript
for (const transaction of transactions) {
  const keysToSign = await this.userKeysToSign(transaction, user);
  if (keysToSign.length > 0) result.push({ transaction, keysToSign });
}
``` [2](#0-1) 

**Pagination applied only after full scan:**

The `limit`/`offset` values received from the caller are used only to slice the already-built in-memory array:

```typescript
items: result.slice(offset, offset + limit),
``` [3](#0-2) 

**Exploit flow:**

1. Attacker registers as a normal user (no privilege required).
2. Attacker (or colluding accounts) creates or is added as a signer to a large number of transactions — the `whereForUser` filter matches any transaction where the user's keys appear.
3. Attacker repeatedly calls the "ready to sign" endpoint (e.g., `GET /transactions?readyToSign=true`).
4. Each request causes the server to: (a) load all matching transactions into the Node.js heap, (b) issue one async DB round-trip per transaction, (c) hold all results in memory until the slice is returned.
5. With enough transactions, heap memory is exhausted, the event loop stalls, and the API process crashes or becomes unresponsive for all users.

### Impact Explanation

- **Memory exhaustion**: Every matching transaction row (with its `groupItem` relation) is materialised in the Node.js heap simultaneously. A few hundred thousand rows can exhaust a typical container's memory limit.
- **CPU / event-loop starvation**: The sequential `await` inside the `for` loop serialises all N database round-trips, blocking the async event loop for the duration of the request.
- **Database connection pressure**: N concurrent or sequential queries per request can exhaust the TypeORM connection pool, causing all other requests to queue or time out.
- **Denial of service for all users**: Because the API is a shared NestJS process, a single slow request that monopolises the event loop degrades response times for every concurrent user.

**Severity: High** — complete service unavailability is achievable without any privileged access.

### Likelihood Explanation

- Any registered user can reach this code path; no admin role or leaked credential is needed.
- Transactions accumulate naturally over time; in an active organisation the table grows continuously.
- An adversarial user can accelerate growth by bulk-creating transactions (subject only to whatever rate limits exist on the creation endpoint).
- The cost to the attacker is low: creating transactions is a normal product flow, and the attacker only needs to trigger the read endpoint repeatedly.

**Likelihood: Medium** — realistic in any moderately active deployment; trivially achievable by a malicious insider or external attacker with a valid account.

### Recommendation

1. **Push pagination into the database query** — add `take: limit` and `skip: offset` to the `repo.find()` call so the database, not Node.js, enforces the page size.
2. **Eliminate the N+1 pattern** — replace the per-transaction `userKeysToSign` loop with a single bulk query that resolves required keys for all transactions in the page at once.
3. **Enforce a hard maximum page size** — reject requests where `limit` exceeds a configured cap (e.g., 100) at the controller/DTO validation layer.
4. **Add rate limiting** on the endpoint to bound the request rate per user.

### Proof of Concept

**Preconditions:** Attacker has a valid account and can create or be added to transactions.

**Steps:**

1. Register a user account via the normal sign-up flow.
2. Create (or be added as a signer to) `N` transactions (e.g., `N = 50 000`) using the transaction creation API in a loop.
3. Issue a single HTTP request to the "transactions to sign" endpoint:
   ```
   GET /transactions?page=1&size=10&readyToSign=true
   ```
4. **Observed**: The server loads all 50 000 transaction rows into heap memory, then issues 50 000 sequential `userKeysToSign` DB calls before returning 10 items. Memory usage spikes; response time grows linearly with `N`; at sufficient scale the Node.js process OOMs or the event loop stalls, returning 503/timeout to all concurrent users.
5. **Expected**: Only 10 rows should be fetched from the database; the response should return in constant time regardless of total transaction count. [4](#0-3)

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
