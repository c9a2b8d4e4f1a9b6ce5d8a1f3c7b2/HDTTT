### Title
Unbounded In-Memory Load in `getTransactionsToSign` Enables OOM via Authenticated Transaction Accumulation

### Summary
`TransactionsService.getTransactionsToSign` fetches **every** non-terminal transaction in the entire database into the Node.js process heap before applying pagination in-memory. There is no per-user transaction count cap, so an authenticated attacker can accumulate transactions over time and trigger a full table scan into memory with a single HTTP request, crashing the API service.

### Finding Description

**Root cause — missing DB-level `take` in `getTransactionsToSign`:** [1](#0-0) 

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
});
```

The `find` call carries **no `take` clause**. The `limit` / `offset` values that arrive from the `@PaginationParams()` decorator are only applied after the full result set is already in memory: [2](#0-1) 

The `whereForUser` filter excludes only terminal statuses (EXECUTED, FAILED, EXPIRED, CANCELED, ARCHIVED). It does **not** scope the query to the requesting user's transactions — it loads every non-terminal transaction from every user in the organisation. [3](#0-2) 

**Transaction accumulation path:**

Each `POST /transactions` call stores `transactionBytes` (up to 6 144 bytes for normal payers, 131 072 bytes for privileged payers) persistently in the database. [4](#0-3) 

The per-user rate limiter allows 100 requests per minute: [5](#0-4) 

The transaction group endpoint (`POST /transaction-groups`) accepts an unbounded `groupItems` array (no `@ArrayMaxSize` decorator), constrained only by the 2 MB HTTP body limit: [6](#0-5) 

A single group POST therefore creates ~150 transactions (≈ 2 MB / ~13 KB per hex-encoded item) while consuming only **one** rate-limit token.

**Exploit flow:**

1. Attacker registers as a verified organisation user (no privileged role required).
2. Attacker repeatedly calls `POST /transaction-groups` with the maximum-sized `groupItems` array, each item containing a valid signed transaction. At 100 requests/minute this yields ~15 000 new non-terminal transactions per minute.
3. Attacker (or any user) calls `GET /transactions/sign`. The service issues an unbounded `SELECT … FROM transaction` with no `LIMIT`, loading every accumulated row — including `transactionBytes` blobs — into the Node.js heap.
4. Heap exhaustion triggers an OOM crash of the API process.

The endpoint is still reachable despite the comment "NO LONGER USED BY FRONT-END": [7](#0-6) 

### Impact Explanation

A single `GET /transactions/sign` request causes the API service to load the entire non-terminal transaction table into memory. With enough accumulated rows (each carrying up to 6 KB of binary payload), the Node.js process exhausts available heap and crashes, making the entire API unavailable to all users. Because the query is global (not scoped to the requesting user), a single attacker's accumulated transactions affect every concurrent request.

### Likelihood Explanation

The attacker needs only a valid organisation account (no admin or privileged keys). The transaction group endpoint multiplies the creation rate by ~150× per rate-limit token. Transactions that are `isManual` or whose `validStart` is set slightly in the future remain in a non-terminal status until the chain service polls and marks them expired, providing a sustained accumulation window. The vulnerable endpoint is unauthenticated-rate-limit-free beyond the 100 req/min cap and requires no special knowledge beyond the public API schema.

### Recommendation

1. **Add a DB-level `take` to `getTransactorsToSign`** — pass `limit` directly into the `repo.find` call and perform the key-matching loop only on the paginated slice, or rewrite the query to push the user-key join into SQL.
2. **Add `@ArrayMaxSize(N)` to `CreateTransactionGroupDto.groupItems`** — a reasonable cap (e.g. 100) prevents a single request from creating hundreds of transactions.
3. **Add a per-user non-terminal transaction count cap** in `validateAndPrepareTransaction` — reject creation if the creator already has more than a configured maximum of active transactions.
4. **Consider removing or disabling `GET /transactions/sign`** if it is genuinely no longer used by the front-end.

### Proof of Concept

```
# Step 1 – obtain a verified-user JWT
TOKEN=$(curl -s -X POST https://api/auth/login -d '{"email":"attacker@org","password":"..."}' | jq -r .accessToken)

# Step 2 – build a group payload with ~150 valid signed transactions (each ~6 KB transactionBytes)
# (attacker pre-signs 150 AccountCreateTransactions with their own key)
python3 build_group_payload.py > payload.json   # produces ~1.9 MB JSON

# Step 3 – flood at rate limit (100 req/min = ~15 000 new rows/min)
for i in $(seq 1 100); do
  curl -s -X POST https://api/transaction-groups \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d @payload.json &
done
wait

# Step 4 – trigger unbounded heap load with a single request
curl -X GET "https://api/transactions/sign?page=1&size=10" \
  -H "Authorization: Bearer $TOKEN"
# API process OOMs; all subsequent requests return 503
```

The `repo.find` at line 295 issues `SELECT … FROM "transaction" LEFT JOIN "transaction_group_item" …` with no `LIMIT`, loading every accumulated row into the Node.js heap. [1](#0-0) [8](#0-7)

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L311-316)
```typescript
    return {
      totalItems: result.length,
      items: result.slice(offset, offset + limit),
      page,
      size,
    };
```

**File:** back-end/apps/api/src/transactions/dto/create-transaction.dto.ts (L15-17)
```typescript
  @IsNotEmpty()
  @TransformBuffer()
  transactionBytes: Buffer;
```

**File:** back-end/apps/api/src/throttlers/user-throttler.module.ts (L13-24)
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
          },
        ],
```

**File:** back-end/apps/api/src/transactions/dto/create-transaction-group.dto.ts (L24-28)
```typescript
  @IsArray()
  @IsNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionGroupItemDto)
  groupItems: CreateTransactionGroupItemDto[];
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

**File:** back-end/apps/api/src/setup-app.ts (L43-43)
```typescript
  app.use(json({ limit: '2mb' }));
```
