### Title
Unbounded Array Processing in Signature Upload Endpoints Enables Authenticated Resource Exhaustion

### Summary
Two authenticated API endpoints — `POST /transactions/signatures/import` and `POST /transactions/:transactionId?/signers` — accept an arbitrarily large array of `UploadSignatureMapDto` objects with no enforced upper bound. For each element, the server performs cryptographic signature verification, SDK transaction deserialization, and database queries. A single authenticated user can submit one crafted request with thousands of entries, exhausting CPU, memory, and database connection resources. A developer comment in the code explicitly acknowledges the missing limit.

### Finding Description

**Root cause:** `transformAndValidateDto()` — the shared validation helper used by both endpoints — performs no array size check before passing the full array to service logic. [1](#0-0) 

Both controllers pass the raw body directly through this helper with no pre-check:

`POST /transactions/signatures/import` → `importSignatures()`: [2](#0-1) 

`POST /transactions/:transactionId?/signers` → `uploadSignatureMap()`: [3](#0-2) 

**Path 1 — `importSignatures` service:** iterates over every element sequentially, performing per-item: a DB access check (`verifyAccess`), `SDKTransaction.fromBytes()` (CPU-intensive protobuf deserialization), `validateSignature()` (cryptographic verification), and `addSignature()`. After the loop, a raw SQL `CASE` string is built by concatenating one clause per item — unboundedly growing the query string and its parameter map. [4](#0-3) [5](#0-4) 

The developer's own comment at line 575 acknowledges the gap:
> `//Added a batch mechanism, probably should limit this on the api side of things`

**Path 2 — `uploadSignatureMaps` service:** uses `Promise.all()` over the entire input array, meaning all items are processed **concurrently**, not sequentially. This amplifies resource pressure compared to Path 1. [6](#0-5) [7](#0-6) 

### Impact Explanation
A single authenticated user can send one HTTP POST request containing thousands of `UploadSignatureMapDto` entries. Each entry triggers cryptographic operations and database queries. The `Promise.all()` path in `uploadSignatureMaps` fires all of these concurrently. This can:
- Saturate the Node.js event loop with CPU-bound crypto work
- Exhaust the PostgreSQL connection pool
- Cause out-of-memory conditions from the unbounded SQL `CASE` string construction
- Render the API service unavailable to all other users

### Likelihood Explanation
Any registered, verified user can reach both endpoints — no admin or operator role is required. The attack requires a single crafted HTTP request. No special tooling is needed beyond a standard HTTP client. The developer comment confirms awareness of the missing limit, indicating it was a known gap left unaddressed.

### Recommendation
1. Enforce a maximum array size in `transformAndValidateDto()` or at the controller level before delegating to service logic (e.g., reject requests with more than 50–100 items).
2. For `uploadSignatureMaps`, replace `Promise.all()` with a bounded concurrency mechanism (e.g., process in batches of N).
3. Add a global NestJS body size limit and consider per-route rate limiting for these endpoints.

### Proof of Concept

```
POST /transactions/signatures/import
Authorization: Bearer <valid_jwt>
Content-Type: application/json

[
  { "id": 1, "signatureMap": { ... } },
  { "id": 1, "signatureMap": { ... } },
  // ... repeated 10,000 times
]
```

Each entry causes `SDKTransaction.fromBytes()` + `validateSignature()` + DB lookup to execute. For the `signers` endpoint, all 10,000 are dispatched concurrently via `Promise.all()`. Server CPU and DB connection pool are exhausted within the single request, blocking all concurrent users until the request completes or the process crashes.

### Citations

**File:** back-end/libs/common/src/dtos/index.ts (L13-21)
```typescript
export async function transformAndValidateDto<T extends object>(
  dtoClass: new (...args: any[]) => T,
  payload: T | T[],
): Promise<T[]> {
  const items = Array.isArray(payload) ? payload : [payload];
  const instances = items.map(item => plainToInstance(dtoClass, item));
  await Promise.all(instances.map(instance => validateOrReject(instance)));
  return instances;
}
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L96-107)
```typescript
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

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L102-119)
```typescript
  async uploadSignatureMap(
    @Body() body: UploadSignatureMapDto | UploadSignatureMapDto[],
    @GetUser() user: User,
    @Query('includeNotifications') includeNotifications?: boolean,
  ): Promise<TransactionSigner[] | UploadSignatureMapResponseDto> {
    const transformedSignatureMaps = await transformAndValidateDto(UploadSignatureMapDto, body);

    const { signers, notificationReceiverIds } = await this.signaturesService.uploadSignatureMaps(
      transformedSignatureMaps,
      user,
    );

    if (includeNotifications) {
      return { signers, notificationReceiverIds };
    }

    return signers;
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L525-553)
```typescript
    for (const { id, signatureMap: map } of dto) {
      const transaction = transactionMap.get(id);

      try {
        /* Verify that the transaction exists and access is verified */
        if (!(await this.verifyAccess(transaction, user))) {
          throw new BadRequestException(ErrorCodes.TNF);
        }

        /* Checks if the transaction is canceled */
        if (
          transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
          transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
        )
          throw new BadRequestException(ErrorCodes.TNRS);

        /* Checks if the transaction is expired */
        const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
        if (isExpired(sdkTransaction)) throw new BadRequestException(ErrorCodes.TE);

        /* Validates the signatures */
        const { data: publicKeys, error } = safe<PublicKey[]>(
          validateSignature.bind(this, sdkTransaction, map),
        );
        if (error) throw new BadRequestException(ErrorCodes.ISNMPN);

        for (const publicKey of publicKeys) {
          sdkTransaction.addSignature(publicKey, map);
        }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L575-601)
```typescript
    //Added a batch mechanism, probably should limit this on the api side of things
    const BATCH_SIZE = 500;

    const updateArray = Array.from(updates.values());

    if (updateArray.length > 0) {
      for (let i = 0; i < updateArray.length; i += BATCH_SIZE) {
        const batch = updateArray.slice(i, i + BATCH_SIZE);

        let caseSQL = 'CASE id ';
        const params: any = {};

        batch.forEach((update, idx) => {
          caseSQL += `WHEN :id${idx} THEN :bytes${idx}::bytea `;
          params[`id${idx}`] = update.id;
          params[`bytes${idx}`] = update.transactionBytes;
        });
        caseSQL += 'END';

        try {
          await this.entityManager
            .createQueryBuilder()
            .update(Transaction)
            .set({ transactionBytes: () => caseSQL })
            .where('id IN (:...ids)', { ids: batch.map(u => u.id) })
            .setParameters(params)
            .execute();
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L99-124)
```typescript
  async uploadSignatureMaps(
    dto: UploadSignatureMapDto[],
    user: User,
  ): Promise<{ signers: TransactionSigner[]; notificationReceiverIds: number[] }> {
    // Load all necessary data
    const { transactionMap, signersByTransaction } = await this.loadTransactionData(dto);

    // Validate and process signatures
    const validationResults = await this.validateAndProcessSignatures(
      dto,
      user,
      transactionMap,
      signersByTransaction
    );

    // Persist changes to database
    const { transactionsToProcess, signers, notificationsToDismiss } = await this.persistSignatureChanges(validationResults, user);

    // Update transaction statuses and emit notifications
    await this.updateStatusesAndNotify(transactionsToProcess);

    return {
      signers: Array.from(signers),
      notificationReceiverIds: notificationsToDismiss,
    };
  }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L155-199)
```typescript
  private async validateAndProcessSignatures(
    dto: UploadSignatureMapDto[],
    user: User,
    transactionMap: Map<number, Transaction>,
    signersByTransaction: Map<number, Set<number>>
  ) {
    // Build user key lookup once
    const userKeyMap = new Map<string, UserKey>();
    for (const key of user.keys) {
      userKeyMap.set(key.publicKey, key);
    }

    return Promise.all(
      dto.map(async ({ id, signatureMap: map }) => {
        try {
          const transaction = transactionMap.get(id);
          if (!transaction) return { id, error: ErrorCodes.TNF };

          // Validate transaction status
          const statusError = this.validateTransactionStatus(transaction);
          if (statusError) return { id, error: statusError };

          // Process signatures
          const { sdkTransaction, userKeys, isSameBytes } = await this.processTransactionSignatures(
            transaction,
            map,
            userKeyMap,
            signersByTransaction.get(id) || new Set()
          );

          return {
            id,
            transaction,
            sdkTransaction,
            userKeys,
            isSameBytes,
            error: null,
          };
        } catch (err) {
          console.error(`[TX ${id}] Error:`, err.message);
          return { id, error: err.message };
        }
      })
    );
  }
```
