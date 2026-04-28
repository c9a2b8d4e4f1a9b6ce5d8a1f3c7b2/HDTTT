### Title
Unbounded Array Processing in Signature Upload Endpoints Enables Authenticated Resource Exhaustion

### Summary
Both `POST /transactions/signatures/import` and `POST /transactions/:transactionId?/signers` accept an array of `UploadSignatureMapDto` objects with no enforced size limit. Each element triggers CPU-intensive cryptographic operations (transaction deserialization, signature validation, signature addition, re-serialization). A single authenticated user can submit a request with an arbitrarily large array, causing the server to exhaust CPU and memory resources. The developer explicitly acknowledged the missing limit in a code comment.

### Finding Description

**Root Cause — `importSignatures` in `transactions.service.ts`:**

The `importSignatures` function accepts `dto: UploadSignatureMapDto[]` with no maximum length check. For every element in the array it performs:

1. `SDKTransaction.fromBytes(transaction.transactionBytes)` — deserializes a Hedera SDK transaction
2. `validateSignature(sdkTransaction, map)` — cryptographic signature validation
3. `sdkTransaction.addSignature(publicKey, map)` — adds signature to the transaction
4. `Buffer.from(sdkTransaction.toBytes())` — re-serializes the transaction [1](#0-0) 

The developer left an explicit acknowledgment of the missing limit at line 575: [2](#0-1) 

The controller exposes this directly to any authenticated user with no throttle or size guard: [3](#0-2) 

**Secondary instance — `uploadSignatureMaps` in `signers.service.ts`:**

The same pattern exists in `uploadSignatureMaps`, which also accepts an unbounded `UploadSignatureMapDto[]` and calls `processTransactionSignatures` (cryptographic work) for every element via `Promise.all`: [4](#0-3) 

The controller endpoint: [5](#0-4) 

**Exploit path:**
An attacker registers as a normal user, obtains a JWT, and sends a single `POST /transactions/signatures/import` request with an array containing thousands of entries (using the same valid transaction ID repeated, or many different IDs). The loop at line 525 iterates over every entry, performing full cryptographic work per iteration, with no early exit or size cap.

### Impact Explanation

A single crafted HTTP request from any authenticated user can saturate the Node.js event loop with synchronous cryptographic work (`fromBytes`, `toBytes`, signature validation), causing:
- Request timeouts for all concurrent users
- Memory exhaustion from accumulating large `transactionBytes` buffers
- Cascading failure of the API service

This is a server-side resource exhaustion vulnerability exploitable by a single authenticated user with no elevated privileges.

### Likelihood Explanation

Any registered, verified user can reach both endpoints. The `UploadSignatureMapDto` array is accepted directly from the request body with no `@ArrayMaxSize()` decorator or middleware size guard. The attacker only needs a valid JWT and one known transaction ID (which can be their own). The developer comment at line 575 confirms the team is aware the limit is missing.

### Recommendation

1. Add `@ArrayMaxSize(N)` (e.g., `N = 100`) to the `UploadSignatureMapDto[]` parameter in both controllers, or enforce it via a NestJS `ValidationPipe` with `transform: true`.
2. Apply `@Throttle` to both signature upload endpoints, as is already done for `remindSigners`. [6](#0-5) 

3. Remove or act on the developer comment at line 575 of `transactions.service.ts`.

### Proof of Concept

```
POST /transactions/signatures/import
Authorization: Bearer <valid_jwt>
Content-Type: application/json

[
  { "id": 1, "signatureMap": { ... } },   // repeated 10,000 times
  { "id": 1, "signatureMap": { ... } },
  ...
]
```

The server enters the loop at `transactions.service.ts:525`, performing `SDKTransaction.fromBytes` + `validateSignature` + `addSignature` + `toBytes` for each of the 10,000 entries. The event loop is blocked for the duration, degrading or denying service to all concurrent users. [7](#0-6) [8](#0-7)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L504-555)
```typescript
    const ids = dto.map(d => d.id);

    // Single batch query for all transactions
    const transactions = await this.entityManager.find(Transaction, {
      where: { id: In(ids) },
      relations: ['creatorKey', 'approvers', 'signers', 'observers'],
    });

    if (transactions.length === 0) {
      return ids.map(id => ({
        id,
        error: new BadRequestException(ErrorCodes.TNF).message,
      }));
    }

    // Create a map for quick lookup
    const transactionMap = new Map(transactions.map(t => [t.id, t]));

    const results = new Map<number, SignatureImportResultDto>();
    const updates = new Map<number, UpdateRecord>();

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

        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L155-198)
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
```

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L100-119)
```typescript
  @Post()
  @HttpCode(201)
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

**File:** back-end/apps/api/src/notification-receiver/notification-receiver.controller.ts (L163-168)
```typescript
  @Throttle({
    'global-minute': {
      limit: 1,
      ttl: seconds(60),
    },
  })
```
