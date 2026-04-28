### Title
Unbounded Array Input in Batch Signature Endpoints Enables Authenticated DoS

### Summary
The `importSignatures` and `uploadSignatureMaps` endpoints accept arrays of `UploadSignatureMapDto` objects with no enforced upper bound on array length. The shared `transformAndValidateDto` utility imposes no size limit, and the service layer performs per-item cryptographic operations, database queries, and a dynamically-growing SQL `CASE` statement proportional to the input size. An authenticated user can submit a single request containing thousands of items to exhaust server CPU, memory, and database connections. The developer explicitly acknowledged this gap in a code comment.

### Finding Description

The `transformAndValidateDto` helper used by both endpoints performs no array-size check:

```typescript
// back-end/libs/common/src/dtos/index.ts
export async function transformAndValidateDto<T extends object>(
  dtoClass: new (...args: any[]) => T,
  payload: T | T[],
): Promise<T[]> {
  const items = Array.isArray(payload) ? payload : [payload];
  const instances = items.map(item => plainToInstance(dtoClass, item));
  await Promise.all(instances.map(instance => validateOrReject(instance)));
  return instances;
}
``` [1](#0-0) 

Both controllers pass the raw body directly through this helper with no pre-check:

- `POST /transactions/signatures/import` — `TransactionsController.importSignatures`
- `POST /transactions/:transactionId?/signers` — `SignersController.uploadSignatureMap` [2](#0-1) [3](#0-2) 

Inside `importSignatures`, for every element in the array the service executes:
1. `verifyAccess` — async DB relation traversal
2. `SDKTransaction.fromBytes` — protobuf deserialization
3. `isExpired` — timestamp check
4. `validateSignature` — cryptographic verification
5. `sdkTransaction.addSignature` — cryptographic operation

Then it builds a single SQL `CASE id WHEN … THEN … END` statement whose size grows linearly with the number of valid items, and executes it against the database:

```typescript
//Added a batch mechanism, probably should limit this on the api side of things
const BATCH_SIZE = 500;
``` [4](#0-3) 

The developer's own comment at line 575 explicitly acknowledges the missing API-side limit. The `BATCH_SIZE = 500` constant only controls how many rows are written per SQL statement — it does **not** cap the total number of items accepted from the caller.

`uploadSignatureMaps` in `SignersService` follows the same pattern: it loads all transaction data, validates and processes signatures per item, then persists in a single database transaction with no input-count guard. [5](#0-4) 

`createTransactions` is a third affected surface: it calls `Promise.all` over all DTOs simultaneously, spawning parallel cryptographic verifications and a bulk DB save with no cap. [6](#0-5) 

None of the three controllers apply a rate-limiting guard; only JWT authentication guards are present. [7](#0-6) 

### Impact Explanation
A single authenticated HTTP request containing, e.g., 10 000 `UploadSignatureMapDto` items forces the server to deserialize 10 000 protobuf blobs, perform 10 000 cryptographic signature verifications, and issue a SQL `CASE` statement with 10 000 branches. This can exhaust CPU, exhaust the PostgreSQL connection pool, and cause out-of-memory conditions, rendering the API unavailable for all other users. Because the processing is synchronous within the request lifecycle, the Node.js event loop is blocked for the duration, amplifying the impact.

### Likelihood Explanation
Any verified (email-confirmed) user account is sufficient to reach these endpoints — no elevated role is required. The attack requires only a single HTTP POST with a large JSON array body, which is trivially scriptable. The developer's own comment ("probably should limit this on the api side of things") confirms awareness that the guard is absent.

### Recommendation

1. **Enforce a hard array-size cap in `transformAndValidateDto`** or add a dedicated guard/pipe:
   ```typescript
   const MAX_BATCH = 100; // tune to operational needs
   if (items.length > MAX_BATCH) {
     throw new BadRequestException(`Batch size exceeds maximum of ${MAX_BATCH}`);
   }
   ```
2. **Apply the cap at the controller layer** for `importSignatures`, `uploadSignatureMap`, and `createTransactions` before delegating to the service.
3. **Add per-user rate limiting** (e.g., via `@nestjs/throttler`) on all batch endpoints.
4. Remove or replace the developer comment at line 575 once the limit is implemented.

### Proof of Concept

```http
POST /transactions/signatures/import HTTP/1.1
Authorization: Bearer <valid_jwt>
Content-Type: application/json

[
  { "id": 1, "signatureMap": { ... } },
  { "id": 1, "signatureMap": { ... } },
  ... // repeated 10,000 times
]
```

The server will attempt to:
- Call `transformAndValidateDto` on all 10 000 items (no size check — `back-end/libs/common/src/dtos/index.ts:17`)
- Execute `SDKTransaction.fromBytes` + `validateSignature` for each item (`back-end/apps/api/src/transactions/transactions.service.ts:542–548`)
- Build and execute a SQL `CASE` statement with up to 10 000 branches (`back-end/apps/api/src/transactions/transactions.service.ts:583–601`)

No server-side guard rejects the request before this work begins.

### Citations

**File:** back-end/libs/common/src/dtos/index.ts (L13-20)
```typescript
export async function transformAndValidateDto<T extends object>(
  dtoClass: new (...args: any[]) => T,
  payload: T | T[],
): Promise<T[]> {
  const items = Array.isArray(payload) ? payload : [payload];
  const instances = items.map(item => plainToInstance(dtoClass, item));
  await Promise.all(instances.map(instance => validateOrReject(instance)));
  return instances;
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L54-57)
```typescript
@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L400-412)
```typescript
  async createTransactions(dtos: CreateTransactionDto[], user: User): Promise<Transaction[]> {
    if (dtos.length === 0) return [];

    await attachKeys(user, this.entityManager);

    const client = await getClientFromNetwork(dtos[0].mirrorNetwork);

    try {
      // Validate all DTOs upfront
      const validatedData = await Promise.all(
        dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)),
      );

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
