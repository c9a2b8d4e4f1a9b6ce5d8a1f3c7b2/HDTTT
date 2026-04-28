I have now verified all the specific claims in the report against the actual codebase. Here is my assessment:

---

Audit Report

## Title
Unbounded Array Input in Signature Upload Endpoints Enables Authenticated DoS via Amplified Cryptographic Work

## Summary
Two authenticated endpoints — `POST /transactions/:transactionId?/signers` and `POST /transactions/signatures/import` — accept an unbounded array of `UploadSignatureMapDto` objects. Each element triggers independent cryptographic operations (deserialization, signature validation, `addSignature`). The only effective cap is the global 2 MB JSON body limit. A single authenticated user can pack thousands of items into one request and force the server to perform thousands of cryptographic operations concurrently, exhausting CPU.

## Finding Description

**Root cause:** No array size cap exists anywhere in the pipeline for these two endpoints.

**`UploadSignatureMapDto`** carries no `@ArrayMaxSize` or equivalent constraint — only field-level validators: [1](#0-0) 

**`transformAndValidateDto`** maps over the array with no size check: [2](#0-1) 

**`SignersController.uploadSignatureMap`** passes the body directly through `transformAndValidateDto` and into `uploadSignatureMaps`: [3](#0-2) 

**`TransactionsController.importSignatures`** does the same: [4](#0-3) 

**Per-item work in `uploadSignatureMaps`:** `validateAndProcessSignatures` uses `Promise.all`, so all items are processed **concurrently**. Each item calls `SDKTransaction.fromBytes` (twice — once in `validateTransactionStatus`, once in `processTransactionSignatures`) and `sdkTransaction.addSignature` per key: [5](#0-4) [6](#0-5) [7](#0-6) 

**`importSignatures`** processes items sequentially (a `for...of` loop, not `Promise.all`), but still performs `SDKTransaction.fromBytes` and `addSignature` per item with no size cap: [8](#0-7) 

**Throttling:** The report's claim that `IpThrottlerGuard` is "only wired to `auth.controller.ts`" is **inaccurate**. `IpThrottlerGuard` is registered as a global `APP_GUARD` and applies to all controllers: [9](#0-8) 

However, this does **not** mitigate the vulnerability. The IP throttler counts HTTP **requests**, not array items within a request. With `GLOBAL_SECOND_LIMIT=1000` and `GLOBAL_MINUTE_LIMIT=10000`, a single request containing thousands of items counts as exactly **one** request against the throttler: [10](#0-9) 

The only hard cap is the 2 MB body limit: [11](#0-10) 

**Duplicate ID amplification:** `loadTransactionData` deduplicates at the DB level via `In(transactionIds)`, but `validateAndProcessSignatures` still iterates over every element of the original `dto` array including duplicates, spawning N concurrent `processTransactionSignatures` calls for the same transaction object: [12](#0-11) 

## Impact Explanation
A single authenticated user can saturate the API server's CPU by sending a continuous stream of requests, each containing thousands of items referencing one valid transaction. Because `Promise.all` is used in `uploadSignatureMaps`, all items in a single request are processed concurrently, multiplying the CPU spike. The IP throttler does not prevent this because it counts requests, not items per request. This can cause severe response-time degradation for all users, complete API unavailability if the Node.js event loop is saturated, and cascading failures in dependent microservices.

## Likelihood Explanation
**Attacker preconditions:**
- A registered, verified account (no admin privileges required).
- One transaction the attacker has access to (any user can create transactions).

Both conditions are reachable by any malicious registered user. The exploit requires no special knowledge beyond the API schema, which is publicly documented via Swagger at `/api-docs`. The attack is trivially scriptable.

## Recommendation
1. **Add an array size cap** at the controller or DTO level. Apply `@ArrayMaxSize(N)` to the outer array (e.g., N=50) before passing to `transformAndValidateDto`, or add a guard that rejects requests where `Array.isArray(body) && body.length > N`.
2. **Deduplicate the DTO array** by `id` before passing to `validateAndProcessSignatures` to eliminate the duplicate-ID amplification vector.
3. **Apply per-user throttling** (`UserThrottlerGuard`) to these endpoints in addition to the existing IP throttler, so that a single authenticated user cannot exhaust the per-IP budget for all users sharing the same IP (e.g., behind NAT).

## Proof of Concept
```http
POST /transactions/signers HTTP/1.1
Authorization: Bearer <valid_jwt>
Content-Type: application/json

[
  { "id": 1, "signatureMap": { "0.0.3": { "0.0.X@T.000000000": { "<DER_KEY>": "<SIG>" } } } },
  { "id": 1, "signatureMap": { "0.0.3": { "0.0.X@T.000000000": { "<DER_KEY>": "<SIG>" } } } },
  ... // repeated ~4000–6000 times within the 2 MB limit
]
```
Each item triggers `SDKTransaction.fromBytes` (×2) and `addSignature` (×1 per key) concurrently via `Promise.all`. The IP throttler records this as a single request. Sending this in a loop exhausts CPU while staying within the throttle budget.

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L127-153)
```typescript
  private async loadTransactionData(dto: UploadSignatureMapDto[]) {
    const transactionIds = dto.map(item => item.id);

    // Batch load all transactions
    const transactions = await this.dataSource.manager.find(Transaction, {
      where: { id: In(transactionIds) },
    });

    const transactionMap = new Map(transactions.map(t => [t.id, t]));

    // Batch load all existing signers
    const existingSigners = await this.dataSource.manager.find(TransactionSigner, {
      where: { transactionId: In(transactionIds) },
      select: ['transactionId', 'userKeyId'],
    });

    // Group by transaction ID
    const signersByTransaction = new Map<number, Set<number>>();
    for (const signer of existingSigners) {
      if (!signersByTransaction.has(signer.transactionId)) {
        signersByTransaction.set(signer.transactionId, new Set());
      }
      signersByTransaction.get(signer.transactionId).add(signer.userKeyId);
    }

    return { transactionMap, signersByTransaction };
  }
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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L201-215)
```typescript
  private validateTransactionStatus(transaction: Transaction): string | null {
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    ) {
      return ErrorCodes.TNRS;
    }

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    if (isExpired(sdkTransaction)) {
      return ErrorCodes.TE;
    }

    return null;
  }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L217-266)
```typescript
  private async processTransactionSignatures(
    transaction: Transaction,
    map: SignatureMap,
    userKeyMap: Map<string, UserKey>,
    existingSignerIds: Set<number>
  ) {
    let sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    const userKeys: UserKey[] = [];
    const processedRawKeys = new Set<string>();

    // To explain what is going on here, we need to understand how sdkTransaction.addSignature works.
    // The addSignature method will go through each inner transaction, then go through the map
    // and pull the signatures for the supplied public key belonging to that inner transaction
    // (denoted by the node and transaction id), add the signatures to the inner transactions.
    // So we need to go through the map and get each unique publicKey and call addSignature one time
    // per key.
    for (const nodeMap of map.values()) {
      for (const txMap of nodeMap.values()) {
        for (const publicKey of txMap.keys()) {
          const raw = publicKey.toStringRaw();

          // Skip duplicates across node/tx maps, and already-processed keys
          if (processedRawKeys.has(raw)) continue;
          processedRawKeys.add(raw);

          // Look up key (raw first, then DER)
          let userKey = userKeyMap.get(raw);
          if (!userKey) {
            userKey = userKeyMap.get(publicKey.toStringDer());
          }
          if (!userKey) throw new Error(ErrorCodes.PNY);

          // Only add the signature once per unique key
          sdkTransaction = sdkTransaction.addSignature(publicKey, map);

          // Only return "new" signers (not already persisted)
          if (!existingSignerIds.has(userKey.id)) {
            userKeys.push(userKey);
          }
        }
      }
    }

    // Finally, compare the resulting transaction bytes to see if any signatures were actually added
    const isSameBytes = Buffer.from(sdkTransaction.toBytes()).equals(
      transaction.transactionBytes
    );

    return { sdkTransaction, userKeys, isSameBytes };
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

**File:** back-end/apps/api/src/api.module.ts (L73-82)
```typescript
  providers: [
    {
      provide: APP_GUARD,
      useClass: IpThrottlerGuard,
    },
    {
      provide: APP_GUARD,
      useClass: FrontendVersionGuard,
    },
    LoggerMiddleware,
```

**File:** back-end/apps/api/example.env (L28-29)
```text
GLOBAL_MINUTE_LIMIT=10000
GLOBAL_SECOND_LIMIT=1000
```

**File:** back-end/apps/api/src/setup-app.ts (L43-43)
```typescript
  app.use(json({ limit: '2mb' }));
```
