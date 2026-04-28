### Title
Unbounded In-Memory Load in `getTransactionsToSign` Causes Server Resource Exhaustion

### Summary
`getTransactionsToSign` in the API backend fetches every non-terminal transaction from the database into memory with no row limit, then performs per-transaction SDK deserialization and database queries for each record before applying pagination. As the organization accumulates transactions over time, any authenticated verified user can trigger this endpoint to exhaust server memory and CPU, causing service unavailability.

### Finding Description

The root cause is in `getTransactionsToSign` in `back-end/apps/api/src/transactions/transactions.service.ts`.

The function signature accepts pagination parameters: [1](#0-0) 

But the database query at line 295 passes **no `take` or `skip`**, fetching every non-terminal transaction in the system: [2](#0-1) 

All fetched records are then iterated in memory, and for each transaction `userKeysToSign` is called — which deserializes the Hedera SDK transaction bytes and issues additional database queries: [3](#0-2) 

Pagination is only applied **after** all processing completes, via an in-memory slice: [4](#0-3) 

This is structurally identical to the BtcPoller Bootstrap bug: all records are accumulated in memory and processed before any batching or early exit occurs.

The `userKeysToSign` call chains into `userKeysRequiredToSign` → `computeSignatureKey` (mirror node I/O) + `entityManager.find(UserKey, ...)` (DB query), making the per-transaction cost non-trivial: [5](#0-4) 

The endpoint is exposed at `GET /transactions/sign` and is still active (the comment "NO LONGER USED BY FRONT-END" confirms the route remains reachable): [6](#0-5) 

### Impact Explanation

With N non-terminal transactions in the database, a single request to `GET /transactions/sign`:
- Loads all N transaction rows (including `transactionBytes` blobs) into Node.js heap
- Performs N SDK `fromBytes` deserializations
- Issues up to N additional `entityManager.find(UserKey)` queries

As the organization grows, N grows without bound. A sustained series of requests from a single authenticated user can exhaust server heap memory (OOM kill) or saturate the database connection pool, making the API unavailable for all users. The `transactionBytes` field stores full serialized Hedera transactions, making each row non-trivial in size.

**Severity: Medium** — service-wide availability impact, but requires an authenticated account.

### Likelihood Explanation

The attacker precondition is: a registered, verified user account with at least one registered key (the `user.keys.length === 0` early-exit at line 286 is the only guard). Any legitimate organization member satisfies this. The endpoint requires no special privilege. A malicious insider or a compromised user account can repeatedly call `GET /transactions/sign` to trigger the unbounded load. The rate-limiting guards (`IpThrottlerGuard`, `UserThrottlerGuard`) exist in the codebase but are not applied to this controller: [7](#0-6) 

No `@Throttle` decorator is present on the controller or the `getTransactionsToSign` handler.

**Probability: Medium** — requires a valid account but no elevated privilege; realistic for a malicious insider or compromised credential.

### Recommendation

Apply database-level pagination to the `repo.find()` call by passing `take: limit` and `skip: offset` directly, mirroring the pattern used in `getTransactions` and `getHistoryTransactions`: [8](#0-7) 

Because `userKeysToSign` must be evaluated to determine eligibility (it cannot be pushed into SQL), the correct fix is a two-phase approach: fetch a bounded batch, evaluate eligibility, and repeat until the requested page is filled — analogous to the staking-indexer PR 132 fix of committing in chunks rather than accumulating everything first.

Additionally, apply `@Throttle` to the `getTransactionsToSign` endpoint.

### Proof of Concept

**Preconditions:**
1. Organization has accumulated a large number of non-terminal transactions (e.g., thousands of `WAITING_FOR_SIGNATURES` records).
2. Attacker holds a valid JWT for a verified user account with at least one registered key.

**Steps:**
```
# Repeatedly call the endpoint (no page size limit enforced server-side)
while true; do
  curl -H "Authorization: Bearer <JWT>" \
       "https://<api-host>/transactions/sign?page=1&size=10"
done
```

**Expected outcome:** Each request causes the server to load all non-terminal transaction rows into heap, deserialize each transaction via the Hedera SDK, and issue per-transaction DB queries. Under sustained load, Node.js heap grows until the process is OOM-killed or the database connection pool is exhausted, rendering the API unavailable for all users.

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L252-254)
```typescript
  async getTransactionsToSign(
    user: User,
    { page, limit, size, offset }: Pagination,
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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L31-43)
```typescript
  const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

  // list of just public keys that have already signed the transaction
  const signerKeys = sdkTransaction._signerPublicKeys;

  const signature = await transactionSignatureService.computeSignatureKey(transaction, showAll);
  // flatten the key list to an array of public keys
  // and filter out any keys that have already signed the transaction
  const flatPublicKeys = flattenKeyList(signature)
    .map(pk => pk.toStringRaw())
    .filter(pk => !signerKeys.has(pk));

  if (flatPublicKeys.length === 0) return [];
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L54-58)
```typescript
@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
  constructor(private transactionsService: TransactionsService) {}
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
