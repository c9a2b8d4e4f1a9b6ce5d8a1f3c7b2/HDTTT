All key claims are code-confirmed. The vulnerability is real and accurately described.

---

Audit Report

## Title
Unbounded Full-Table Scan in `getTransactionsToSign()` Enables Authenticated DoS

## Summary
`getTransactionsToSign()` in `transactions.service.ts` fetches every non-terminal transaction system-wide with no database-level `take`/`limit`, then issues a sequential `await userKeysToSign()` DB call per row before applying pagination in memory. Any authenticated user can trigger O(N) database queries per request, where N is the total number of active transactions across all users.

## Finding Description

**Missing `take` on the initial fetch:**

`getTransactionsToSign()` builds a `whereForUser` filter that excludes only terminal statuses. Critically, it contains **no user-scoping clause** — it matches all non-terminal transactions system-wide. It then calls `this.repo.find()` with no `take` parameter: [1](#0-0) 

All N rows are loaded into the Node.js heap, then iterated with a sequential `await` per row: [2](#0-1) 

Pagination is applied only after the full scan completes: [3](#0-2) 

**Contrast with properly paginated endpoints:**

Both `getTransactions()` and `getHistoryTransactions()` pass `skip: offset, take: limit` directly into TypeORM `FindManyOptions`, enforcing page size at the database level: [4](#0-3) [5](#0-4) 

`getTransactionsToSign()` does neither.

## Impact Explanation

- **Availability:** Each request to `GET /transactions/sign` causes O(N) sequential async DB queries where N is the total count of non-terminal transactions across the entire system. With thousands of transactions, each request holds a DB connection pool slot and CPU for an extended period, starving other users.
- **Memory:** All N transaction rows are loaded into the Node.js heap simultaneously before any filtering or pagination.
- **Cascading:** `userKeysToSign()` itself performs additional DB lookups (key resolution, approver tree traversal), so the actual DB query count per request is a multiple of N.
- **No user scoping:** The `whereForUser` filter applies only a status exclusion — it does not filter by the requesting user's ID, meaning a single user's request loads every active transaction in the system.

## Likelihood Explanation

The endpoint `GET /transactions/sign` is protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — any registered, verified user can reach it. Transaction creation (`POST /transactions`) is similarly available to any verified user with a registered key. An attacker needs only one account and the ability to create transactions in bulk. The attack is repeatable and deterministic: more active transactions → longer response time → eventual timeout or OOM.

## Recommendation

Apply DB-level pagination inside `getTransactionsToSign()` by passing `skip: offset, take: limit` into the `this.repo.find()` call, mirroring the pattern used in `getTransactions()` and `getHistoryTransactions()`. Because `userKeysToSign()` filtering must happen in application code (it cannot be expressed as a simple SQL predicate), consider a two-phase approach: pre-filter candidates at the DB level using a join on `transaction_signer` keyed to the user's key IDs, then apply `userKeysToSign()` only to that reduced set.

## Proof of Concept

1. Register and verify an account.
2. Create a large number of transactions via `POST /transactions` (each requires only a valid `creatorKeyId` and `transactionBytes`).
3. Repeatedly call `GET /transactions/sign?page=1&size=10`.
4. Observe that each request loads all active transactions from the DB (not just 10), issues one `userKeysToSign()` DB call per transaction, and response latency grows linearly with the number of active transactions in the system. [6](#0-5)

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
