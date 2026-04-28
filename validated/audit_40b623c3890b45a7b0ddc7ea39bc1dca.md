After verifying all referenced code, here is my assessment:

---

Audit Report

## Title
Unbounded Iteration in `getTransactionsToSign` Causes O(N) `computeSignatureKey` Calls Per Request Leading to Server Resource Exhaustion

## Summary
`TransactionsService.getTransactionsToSign()` fetches every non-terminal transaction in the database with no row limit, then calls `transactionSignatureService.computeSignatureKey()` and `SDKTransaction.fromBytes()` sequentially for every row before applying pagination. A single authenticated `GET /transactions/sign` request scales linearly with the total number of active transactions, exhausting CPU, memory, and potentially mirror-node connections.

## Finding Description

**Unbounded initial fetch — no `take` limit:**

`getTransactionsToSign` issues a `repo.find()` with no `take`/`skip`. The `whereForUser` filter excludes only terminal statuses; it does **not** scope results to the requesting user:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,   // all non-terminal transactions, not filtered by user
  relations: ['groupItem'],
  order,
  // ← no take / skip
});
``` [1](#0-0) 

**O(N) per-transaction CPU work:**

For every row returned, `userKeysToSign` is awaited sequentially. This delegates to `userKeysRequiredToSign`, which calls `keysRequiredToSign`, which in turn calls `SDKTransaction.fromBytes(transaction.transactionBytes)` (CPU-intensive deserialization) and `transactionSignatureService.computeSignatureKey(transaction)` (may involve mirror-node HTTP calls or DB lookups) for every transaction: [2](#0-1) [3](#0-2) 

**Correction to the original report's DB query claim:**

The original report claims `entityManager.find(UserKey, ...)` is issued per transaction. This is **not accurate** for this call path. `userKeysRequiredToSign` passes `user.keys` as the `userKeys` parameter to `keysRequiredToSign`, which causes it to use the in-memory filter branch (lines 49–51) rather than the DB query branch (lines 86–89). No per-transaction `UserKey` DB query is issued. [4](#0-3) [5](#0-4) 

**Pagination applied post-hoc:**

The `limit`/`offset` from the caller's `Pagination` object only slices the already-fully-computed `result` array and never constrains the DB fetch or the loop: [6](#0-5) 

**Endpoint is active and accessible to any authenticated user:**

The endpoint is marked `/* NO LONGER USED BY FRONT-END */` but remains fully registered and protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — no admin role, no rate limit, no server-side row cap: [7](#0-6) [8](#0-7) 

## Impact Explanation

For a deployment with N active (non-terminal) transactions:

- **CPU exhaustion:** `SDKTransaction.fromBytes(transaction.transactionBytes)` and `computeSignatureKey` are called N times per request, blocking the Node.js event loop for the full duration.
- **Memory pressure:** All N transaction rows (including `transactionBytes` blobs and `groupItem` relations) are loaded into the Node.js heap simultaneously.
- **Mirror-node connection exhaustion:** If `computeSignatureKey` issues external HTTP calls, N sequential calls per request can saturate outbound connection limits.
- **Cascading degradation:** Concurrent requests from multiple users multiply the effect. A long-running deployment accumulates thousands of transactions, making this worse over time even without a malicious actor.

## Likelihood Explanation

- **Attacker precondition:** Only a valid JWT for any registered, verified user. No admin role required.
- **Trigger:** A single HTTP `GET /transactions/sign`. No special payload needed.
- **Natural growth:** Even without a malicious actor, a production deployment accumulates non-terminal transactions over time. Legitimate users hitting this endpoint will experience monotonically worsening latency.
- **Amplification:** Concurrent requests multiply the effect linearly.

## Recommendation

1. **Pre-filter by user before fetching:** Join against `transaction_signer` or `user_key` tables in the initial query so only transactions potentially relevant to the requesting user are fetched.
2. **Apply `take`/`skip` at the DB level:** Pass `take: limit` and `skip: offset` to the `repo.find()` call. Because the current design requires post-fetch filtering to determine `keysToSign`, a cursor-based or keyset pagination approach is preferable.
3. **Batch `computeSignatureKey` calls:** Replace the sequential `for...await` loop with `Promise.all` or a bounded concurrency queue to avoid holding the event loop.
4. **Add a hard server-side cap:** Even with pagination, enforce a maximum page size (e.g., 100 rows) to bound worst-case work per request.
5. **Remove or gate the endpoint:** Since the endpoint is explicitly marked `/* NO LONGER USED BY FRONT-END */`, consider removing it or protecting it behind an admin/internal guard.

## Proof of Concept

```
# Precondition: valid JWT for any verified user; N non-terminal transactions exist in DB

GET /transactions/sign?page=1&limit=10
Authorization: Bearer <valid_jwt>

# Server fetches ALL N transactions from DB (no LIMIT),
# then calls SDKTransaction.fromBytes() + computeSignatureKey() N times,
# then slices result[0..10].
# Response time and server CPU scale as O(N).
# Issuing this request concurrently multiplies resource consumption.
```

### Citations

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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L31-36)
```typescript
  const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

  // list of just public keys that have already signed the transaction
  const signerKeys = sdkTransaction._signerPublicKeys;

  const signature = await transactionSignatureService.computeSignatureKey(transaction, showAll);
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L49-51)
```typescript
  if (userKeys) {
    results = userKeys.filter(publicKey =>
        flatPublicKeys.includes(publicKey.publicKey)
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

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L54-57)
```typescript
@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
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
