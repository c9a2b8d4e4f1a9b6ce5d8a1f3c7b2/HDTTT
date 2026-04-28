All key claims are verified against the actual code. Let me now produce the audit report.

---

Audit Report

## Title
DoS: `getTransactionsToSign()` Fetches All Non-Terminal Transactions Without DB-Level Pagination, Enabling Unbounded Resource Exhaustion

## Summary

`TransactionsService.getTransactionsToSign()` issues an unbounded `repo.find()` with no `skip`/`take` limit, loading every non-terminal transaction from the database into memory. It then iterates over all of them, calling `userKeysToSign()` per transaction — which deserializes transaction bytes via the Hedera SDK and invokes `computeSignatureKey()` — before applying pagination in memory via `result.slice()`. Any authenticated user can accumulate non-terminal transactions, causing each call to `GET /transactions/sign` to consume unbounded memory and CPU.

## Finding Description

**Root cause — unbounded DB fetch followed by per-item async work:**

In `back-end/apps/api/src/transactions/transactions.service.ts`, `getTransactionsToSign()` accepts `Pagination` parameters but never passes `skip`/`take` to the database query:

```typescript
// lines 295-299: no skip/take — fetches ALL non-terminal transactions
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
});
``` [1](#0-0) 

It then iterates over every result:

```typescript
// lines 301-309: per-transaction async work, unbounded
for (const transaction of transactions) {
  try {
    const keysToSign = await this.userKeysToSign(transaction, user);
    if (keysToSign.length > 0) result.push({ transaction, keysToSign });
  } catch (error) { console.log(error); }
}
``` [2](#0-1) 

Pagination is applied only after the full iteration:

```typescript
// line 313: in-memory slice, too late
items: result.slice(offset, offset + limit),
``` [3](#0-2) 

**Per-iteration cost of `userKeysToSign()`:**

`userKeysToSign()` delegates to `userKeysRequiredToSign()` → `keysRequiredToSign()`, which per transaction:
1. Deserializes the full transaction bytes via `SDKTransaction.fromBytes(transaction.transactionBytes)` (CPU-intensive)
2. Calls `transactionSignatureService.computeSignatureKey(transaction, showAll)` (potentially involves mirror node or DB lookups) [4](#0-3) 

Note: the `entityManager.find(UserKey, ...)` DB query is only issued when `userKeys` is not provided; in the `userKeysToSign` path, `user.keys` is passed as `userKeys`, so the per-iteration DB query is avoided. However, the CPU cost of `fromBytes` + `computeSignatureKey` per transaction remains significant. [5](#0-4) 

**Exposed endpoint:**

`GET /transactions/sign` is registered in the controller with only JWT guards — no rate limiting, no per-user transaction count cap: [6](#0-5) 

**The `whereForUser` filter** excludes only `EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `ARCHIVED` — leaving `NEW`, `WAITING_FOR_SIGNATURES`, `WAITING_FOR_EXECUTION`, and `REJECTED` in scope. Transactions created by any user start as `WAITING_FOR_SIGNATURES` and remain there until signed or expired. [7](#0-6) 

**Contrast with properly paginated sibling methods:**

`getHistoryTransactions()` passes `skip: offset, take: limit` directly to the DB query: [8](#0-7) 

`getTransactions()` similarly passes `skip: offset, take: limit`: [9](#0-8) 

`getTransactionsToApprove()` also passes `skip: offset, take: limit`: [10](#0-9) 

`getTransactionsToSign()` is the sole outlier.

## Impact Explanation

- **Memory exhaustion:** All matching transaction rows (including their `transactionBytes` blobs) are loaded into the Node.js heap simultaneously. With thousands of transactions, this causes OOM or severe GC pressure.
- **CPU exhaustion:** `SDKTransaction.fromBytes()` and `computeSignatureKey()` are called once per transaction per request. Concurrent requests multiply this.
- **Service-wide degradation:** The API service is single-process NestJS. A sustained attack degrades or crashes the API for all users, not just the attacker.

## Likelihood Explanation

- **Attacker preconditions:** Only a valid JWT (registered, verified user with at least one key). No admin access required.
- **Attack steps:** Create many transactions via `POST /transactions` (each with a unique `transactionId`), then repeatedly call `GET /transactions/sign`. Transactions remain in `WAITING_FOR_SIGNATURES` until their `validStart` expires.
- **No rate limiting** is applied to either `POST /transactions` or `GET /transactions/sign` at the controller level.
- The endpoint is still live and reachable despite the comment `/* NO LONGER USED BY FRONT-END */`.
- The attack is self-amplifying: more transactions → slower responses → easier to sustain.

## Recommendation

1. **Push pagination to the DB layer** in `getTransactionsToSign()`, analogous to the sibling methods. Since the filtering of "keys to sign" requires per-transaction async work, consider a two-phase approach: first fetch a page of candidate transactions with `skip`/`take`, then apply the `userKeysToSign` filter on that bounded set.
2. **Add rate limiting** to `POST /transactions` and `GET /transactions/sign` at the controller or gateway level.
3. **Add a per-user non-terminal transaction cap** to prevent unbounded accumulation.
4. **Consider removing or disabling** `GET /transactions/sign` if it is truly no longer used by the front-end.

## Proof of Concept

```
# Step 1: Authenticate and obtain JWT
POST /auth/login  →  { token: "<JWT>" }

# Step 2: Create N transactions (each with unique transactionId, validStart far in future)
for i in 1..N:
  POST /transactions
  Authorization: Bearer <JWT>
  Body: { transactionId: "0.0.X@<timestamp+i>", transactionBytes: "<bytes>", ... }

# Step 3: Repeatedly call the unbounded endpoint
while true:
  GET /transactions/sign?page=1&size=10
  Authorization: Bearer <JWT>
  # Server fetches ALL N transactions from DB, calls fromBytes() + computeSignatureKey()
  # for each, then slices to 10. Memory and CPU scale with N.
```

With N in the thousands, each request to `GET /transactions/sign` will load all N transaction rows into the Node.js heap and invoke `SDKTransaction.fromBytes()` + `computeSignatureKey()` N times before returning 10 results, causing progressive memory and CPU exhaustion.

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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L31-36)
```typescript
  const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

  // list of just public keys that have already signed the transaction
  const signerKeys = sdkTransaction._signerPublicKeys;

  const signature = await transactionSignatureService.computeSignatureKey(transaction, showAll);
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L96-114)
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
