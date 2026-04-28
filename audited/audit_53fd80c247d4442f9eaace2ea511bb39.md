### Title
Unbounded Loop Over All Transactions in `getTransactionsToSign` Enables Authenticated DoS

### Summary
`getTransactionsToSign` in `transactions.service.ts` fetches every transaction in the database without a row limit, then iterates over the full result set performing async cryptographic key-matching work per transaction before applying pagination. Any authenticated user can trigger this endpoint to exhaust server CPU and memory. A second unbounded-input path exists in `importSignatures`, where the developer comment explicitly acknowledges the missing limit.

### Finding Description

**Path 1 — `getTransactionsToSign` (primary)**

`GET /transactions/sign` calls `TransactionsService.getTransactionsToSign`. The database query at line 295 uses `this.repo.find(...)` with no `take` constraint:

```ts
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
});
```

All matching rows are loaded into memory. The service then iterates over every row:

```ts
for (const transaction of transactions) {
  const keysToSign = await this.userKeysToSign(transaction, user);
  if (keysToSign.length > 0) result.push({ transaction, keysToSign });
}
```

`userKeysToSign` delegates to `userKeysRequiredToSign`, which performs signature-related work per transaction. Pagination is applied only after the loop completes:

```ts
items: result.slice(offset, offset + limit),
```

The `{ page, limit, size, offset }` parameters from `PaginationParams` are never passed to the ORM query, so the database always returns the full unbounded set.

**Path 2 — `importSignatures` (secondary)**

`POST /transactions/signatures/import` accepts `UploadSignatureMapDto[] | UploadSignatureMapDto` with no array-size validation. The developer left an explicit acknowledgment of the missing guard at line 575:

```ts
//Added a batch mechanism, probably should limit this on the api side of things
```

Each element in the caller-supplied array triggers transaction lookup, cryptographic signature validation (`publicKey.verify`), and a database write. A large array causes proportional CPU and DB load.

### Impact Explanation
An authenticated user (any registered organization member) can send a single request to `GET /transactions/sign` or `POST /transactions/signatures/import` that causes the API process to load and process an arbitrarily large number of records. As the transaction table grows, response latency increases without bound, eventually starving the Node.js event loop and making the API unresponsive for all users. Because Node.js is single-threaded, a sustained stream of such requests from one user degrades service for the entire organization.

### Likelihood Explanation
Both endpoints require only a valid JWT — no elevated role is needed. The `GET /transactions/sign` endpoint is still reachable despite the controller comment "NO LONGER USED BY FRONT-END"; it remains a live route protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. Any verified user account is sufficient to exploit it. The `importSignatures` endpoint is actively used and accepts an array body with no documented or enforced size cap.

### Recommendation

1. **`getTransactionsToSign`**: Pass the `limit`/`offset` pagination parameters directly to the ORM query (`take: limit, skip: offset`) so the database returns only the requested page. Perform the `userKeysToSign` check only on that page, not on the full table.

2. **`importSignatures` / `uploadSignatureMaps`**: Enforce a hard maximum on the input array length (e.g., 100 items) at the DTO validation layer using a `@ArrayMaxSize` decorator, and document the limit in the API spec.

3. Consider rate-limiting these endpoints per user at the throttler layer.

### Proof of Concept

```
# Authenticated as any verified user:
GET /transactions/sign?page=1&limit=10

# The server fetches ALL transactions from the DB (no LIMIT clause),
# runs userKeysToSign() on every row, then slices to 10.
# With N=50,000 transactions the loop runs 50,000 times before returning.

# For importSignatures:
POST /transactions/signatures/import
Content-Type: application/json

[
  { "id": 1, "signatureMap": { ... } },
  { "id": 2, "signatureMap": { ... } },
  ... (10,000 entries)
]
# No server-side size check rejects this array.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L295-316)
```typescript
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
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L575-582)
```typescript
    //Added a batch mechanism, probably should limit this on the api side of things
    const BATCH_SIZE = 500;

    const updateArray = Array.from(updates.values());

    if (updateArray.length > 0) {
      for (let i = 0; i < updateArray.length; i += BATCH_SIZE) {
        const batch = updateArray.slice(i, i + BATCH_SIZE);
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L93-107)
```typescript
  @Post('/signatures/import')
  @HttpCode(201)
  @Serialize(SignatureImportResultDto)
  async importSignatures(
    @Body() body: UploadSignatureMapDto[] | UploadSignatureMapDto,
    @GetUser() user: User,
  ): Promise<SignatureImportResultDto[]> {
    const transformedSignatureMaps = await transformAndValidateDto(
      UploadSignatureMapDto,
      body
    );

    // Delegate to service to perform the import
    return this.transactionsService.importSignatures(transformedSignatureMaps, user);
  }
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
