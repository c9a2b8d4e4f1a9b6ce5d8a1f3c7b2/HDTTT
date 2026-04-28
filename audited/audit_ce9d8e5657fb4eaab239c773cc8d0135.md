### Title
Denial of Service via Unbounded Full-Table Scan in `getTransactionsToSign`

### Summary
`getTransactionsToSign` in `TransactionsService` fetches **all** non-terminal transactions from the database with no `take` limit, then performs an async `userKeysToSign()` call for every row before applying pagination in memory. Any authenticated user can trigger this endpoint, and as the transaction table grows — either organically or through attacker-created transactions — the server performs an unbounded number of expensive async operations per request, causing memory exhaustion and request timeouts.

### Finding Description

**Root cause — no DB-level pagination in `getTransactionsToSign`:** [1](#0-0) 

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no `take` or `skip`; fetches every non-terminal transaction
});

for (const transaction of transactions) {
  try {
    const keysToSign = await this.userKeysToSign(transaction, user);
    if (keysToSign.length > 0) result.push({ transaction, keysToSign });
  } catch (error) { console.log(error); }
}

return {
  totalItems: result.length,
  items: result.slice(offset, offset + limit), // pagination applied AFTER full scan
  ...
};
```

The `repo.find()` call carries no `take` constraint, so TypeORM issues a `SELECT … FROM transaction` with no `LIMIT`. Every matching row is loaded into Node.js heap memory. Then `userKeysToSign()` — which itself performs async work — is awaited sequentially for each row. Pagination (`result.slice`) is applied only after the entire result set has been processed.

**Exposed endpoint:** [2](#0-1) 

The route `GET /transactions/sign` is still live and guarded only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — any verified user can call it.

**Contrast with `getTransactionsToApprove`, which correctly uses DB-level pagination:** [3](#0-2) 

```typescript
const findOptions: FindManyOptions<Transaction> = {
  order,
  relations: { creatorKey: true, groupItem: true },
  skip: offset,
  take: limit,   // ← DB-level pagination present here
};
```

**Secondary surface — `importSignatures` has no array-size cap (developer-acknowledged):** [4](#0-3) 

```typescript
//Added a batch mechanism, probably should limit this on the api side of things
const BATCH_SIZE = 500;
```

The `POST /transactions/signatures/import` endpoint accepts `UploadSignatureMapDto[] | UploadSignatureMapDto` with no enforced upper bound on array length. [5](#0-4) 

### Impact Explanation

A verified attacker (or organic system growth) causes the server to:
1. Load the entire non-terminal transaction table into heap memory on every `GET /transactions/sign` call.
2. Execute one async `userKeysToSign()` DB round-trip per row.

With N pending transactions, each request costs O(N) memory and O(N) async DB queries. At scale this causes Node.js OOM crashes or request timeouts, making the endpoint — and potentially the entire API process — unavailable to all users. The secondary `importSignatures` surface allows a single authenticated user to submit an arbitrarily large array, triggering O(N) cryptographic verification operations (`SDKTransaction.fromBytes`, `validateSignature`, `addSignature`) in a single request.

### Likelihood Explanation

- **Attacker precondition:** A valid JWT for any verified organization user — no admin role required.
- **Trigger:** A single `GET /transactions/sign` HTTP request. No special tooling needed.
- **Organic trigger:** Even without a malicious actor, a busy organization accumulating thousands of pending transactions will hit this naturally.
- **Transaction creation cost:** Creating transactions requires valid Hedera transaction bytes and a creator key signature, but a determined attacker with a registered key can automate this at low cost.

### Recommendation

1. **Apply DB-level pagination in `getTransactionsToSign`** — add `take: limit` and `skip: offset` to the `repo.find()` call, mirroring the pattern already used in `getTransactionsToApprove`.

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  take: limit,   // ← add this
  skip: offset,  // ← add this
});
```

Note: because `userKeysToSign` filters further in-memory, the `totalItems` count will need a separate `count()` query (again, as `getTransactionsToApprove` already does).

2. **Enforce an array-size cap on `importSignatures`** — add a `@ArrayMaxSize(N)` class-validator decorator to the DTO or a guard check at the controller level, resolving the developer-acknowledged TODO at line 575.

### Proof of Concept

1. Register and verify a user account in the organization.
2. Create a large number of transactions (e.g., 10,000) via `POST /transactions`, each with a unique valid Hedera transaction ID and the user's creator key.
3. Issue repeated `GET /transactions/sign?page=1&size=10` requests.
4. Observe: each request loads all 10,000 transaction rows into memory and calls `userKeysToSign()` 10,000 times before returning 10 results. Server memory and CPU spike; response times grow linearly with N; at sufficient scale the Node.js process OOMs or the request times out, denying service to all other users.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L295-313)
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L575-576)
```typescript
    //Added a batch mechanism, probably should limit this on the api side of things
    const BATCH_SIZE = 500;
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
