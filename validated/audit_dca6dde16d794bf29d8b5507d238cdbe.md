I have verified all code references against the actual repository. Here is my assessment:

---

## Audit Report

## Title
Unbounded Batch Array in `uploadSignatureMap` Enables Authenticated Single-Request Resource Exhaustion

## Summary
The `POST /transactions/:transactionId?/signers` endpoint accepts an array of `UploadSignatureMapDto` objects with no enforced size limit. A single authenticated HTTP request containing thousands of entries causes `validateAndProcessSignatures` to fan out all elements into an unbounded `Promise.all`, spawning concurrent CPU-intensive work units (protobuf deserialization via `SDKTransaction.fromBytes`) that can saturate the Node.js event loop and exhaust server memory.

## Finding Description

**No array size cap at any layer:**

`UploadSignatureMapDto` carries no `@ArrayMaxSize` or equivalent constraint — only `@IsDefined`, `@IsNumber`, `@IsNotEmptyObject`, and `@IsSignatureMap`: [1](#0-0) 

The controller accepts `UploadSignatureMapDto | UploadSignatureMapDto[]` directly: [2](#0-1) 

`transformAndValidateDto` wraps the payload in an array and validates each item individually — no count check: [3](#0-2) 

**Unbounded concurrent processing:**

`validateAndProcessSignatures` fans out every array element into a concurrent `Promise.all` with no concurrency cap: [4](#0-3) 

Each concurrent branch performs two separate `SDKTransaction.fromBytes` calls — one in `validateTransactionStatus` and one in `processTransactionSignatures`: [5](#0-4) [6](#0-5) 

**Duplicate-ID amplification:**

`loadTransactionData` batch-fetches with `In(transactionIds)`, so PostgreSQL deduplicates IDs and returns one row per unique ID. However, `Promise.all` still spawns N concurrent branches for N array entries — each independently deserializing the same transaction bytes: [7](#0-6) 

Sending `[{id:1,...}, {id:1,...}, ...]` 5,000 times results in one DB row but 5,000 concurrent `fromBytes` calls.

**Body size limit provides only partial mitigation:**

The application sets a 2 MB JSON body limit: [8](#0-7) 

Within 2 MB of JSON, an attacker can pack thousands of minimal `{id: N, signatureMap: {}}` entries. The limit constrains payload size but does not prevent the attack.

**No throttling on these endpoints:**

The `SignersController` and `TransactionsController` carry no `@Throttle` decorator or per-endpoint throttler guard. The global user throttler (100 req/min, 10 req/sec) counts HTTP requests, not array elements within a single request: [9](#0-8) 

**Correction on `importSignatures`:** The `importSignatures` service method processes entries sequentially via a `for` loop, not `Promise.all`, so the concurrent amplification does not apply there. The unbounded array acceptance still applies, but the impact is sequential CPU exhaustion rather than concurrent. [10](#0-9) 

## Impact Explanation
A single crafted HTTP POST to `POST /transactions/:id/signers` with thousands of array entries causes the Node.js event loop to be saturated by concurrent CPU-bound protobuf deserialization tasks. Because all work is dispatched simultaneously via `Promise.all` with no concurrency cap, memory pressure grows linearly with array size. This blocks all other requests from being processed, rendering the API unavailable for all users until the request completes or the process OOMs. The 2 MB body cap limits the maximum payload but does not prevent the attack.

## Likelihood Explanation
The only precondition is a valid JWT — any registered, verified user qualifies. No admin role or special account state is required. The affected endpoint is a standard product workflow (signing transactions), reachable in normal operation. The attack is a single HTTP POST with a crafted JSON body.

## Recommendation
1. **Enforce an array size cap** on `UploadSignatureMapDto` using `@ArrayMaxSize(N)` (e.g., N = 50) at the DTO level, and add a guard in `transformAndValidateDto` to reject oversized arrays before processing.
2. **Replace unbounded `Promise.all`** in `validateAndProcessSignatures` with a concurrency-limited alternative (e.g., process in batches of a fixed size).
3. **Apply per-user throttling** specifically to the signature upload endpoints, counting array elements rather than just HTTP requests.

## Proof of Concept
```http
POST /transactions/1/signers HTTP/1.1
Authorization: Bearer <valid_jwt>
Content-Type: application/json

[
  {"id": 1, "signatureMap": {}},
  {"id": 1, "signatureMap": {}},
  ... (repeated ~3000 times, within 2 MB)
]
```
`loadTransactionData` returns one DB row for `id=1`. `validateAndProcessSignatures` spawns ~3000 concurrent async branches via `Promise.all`, each calling `SDKTransaction.fromBytes` twice, saturating the event loop for the duration of the request.

### Citations

**File:** back-end/apps/api/src/transactions/dto/upload-signature.dto.ts (L7-43)
```typescript
export class UploadSignatureMapDto {
  @ApiProperty({
    description: 'The ID of the transaction associated with the signature map.',
    example: 12345,
  })
  @IsDefined()
  @IsNumber()
  id: number;

  @ApiProperty({
    type: 'object',
    additionalProperties: true,
    example: {
      '0.0.3': {
        '0.0.2159149@1730378704.000000000': {
          '302a300506032b657003210061f37fc1bbf3ff4453712ee6a305c5c7255955f7889ec3bf30426f1863158ef4':
            '0xac244c7240650eaa32b60fd4d7d2ef9f49d3bcd1e3ae1df273ede1b4da32f32b25e389d5a8195b6efbc39ac62810348688976c5304fbef33e51cd7505592cd0f',
        },
      },
      '0.0.5': {
        '0.0.2159149@1730378704.000000000': {
          '302a300506032b657003210061f37fc1bbf3ff4453712ee6a305c5c7255955f7889ec3bf30426f1863158ef4':
            '0x053bc5e784dc767095fbdafaaefed3553dd384b86877276951c7eb634d1f0191288a2cc72e6477a1661a483a38935ab51297ec84555c1d0bcb68daf77fb49a0b',
        },
      },
      '0.0.7': {
        '0.0.2159149@1730378704.000000000': {
          '302a300506032b657003210061f37fc1bbf3ff4453712ee6a305c5c7255955f7889ec3bf30426f1863158ef4':
            '0xccad395302df6b0ea31d15d9ab9c58bc5a6dc6ec9a334dbfb09c321e6fba802bf8873ba03e3e81d80e499d56a318f663d897aff78cedeb1b7a3d43bdf4609a08',
        },
      },
    },
  })
  @IsNotEmptyObject()
  @IsSignatureMap()
  signatureMap: SignatureMap;
}
```

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L102-107)
```typescript
  async uploadSignatureMap(
    @Body() body: UploadSignatureMapDto | UploadSignatureMapDto[],
    @GetUser() user: User,
    @Query('includeNotifications') includeNotifications?: boolean,
  ): Promise<TransactionSigner[] | UploadSignatureMapResponseDto> {
    const transformedSignatureMaps = await transformAndValidateDto(UploadSignatureMapDto, body);
```

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L128-135)
```typescript
    const transactionIds = dto.map(item => item.id);

    // Batch load all transactions
    const transactions = await this.dataSource.manager.find(Transaction, {
      where: { id: In(transactionIds) },
    });

    const transactionMap = new Map(transactions.map(t => [t.id, t]));
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L167-198)
```typescript
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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L209-214)
```typescript
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    if (isExpired(sdkTransaction)) {
      return ErrorCodes.TE;
    }

    return null;
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L223-223)
```typescript
    let sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
```

**File:** back-end/apps/api/src/setup-app.ts (L43-43)
```typescript
  app.use(json({ limit: '2mb' }));
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L525-525)
```typescript
    for (const { id, signatureMap: map } of dto) {
```
