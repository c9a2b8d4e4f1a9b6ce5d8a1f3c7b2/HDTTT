### Title
Unbounded Array Iteration in Bulk Signature Endpoints Enables Authenticated Single-Request DoS

### Summary
Two authenticated API endpoints — `POST /transactions/signatures/import` and `POST /transactions/:transactionId/signers` — accept arrays of arbitrary size with no enforced upper bound. Each element triggers CPU-intensive cryptographic deserialization and signature operations. A single crafted request with a large array exhausts server CPU, memory, and database connection pool, causing service unavailability for all users. The developers themselves acknowledged the missing limit in a code comment.

### Finding Description

**Root cause — no array size cap on two bulk endpoints:**

**Endpoint 1: `POST /transactions/signatures/import`**

The controller accepts `UploadSignatureMapDto[] | UploadSignatureMapDto` with no `@ArrayMaxSize` or any size guard: [1](#0-0) 

The service iterates over every element sequentially. Each iteration calls `SDKTransaction.fromBytes()` (protobuf deserialization), `validateSignature()` (cryptographic verification), and `sdkTransaction.addSignature()` / `sdkTransaction.toBytes()` (re-serialization): [2](#0-1) 

The developer explicitly acknowledged the missing limit with a comment directly above the batch loop: [3](#0-2) 

**Endpoint 2: `POST /transactions/:transactionId/signers`**

Same pattern — no array size limit on the body: [4](#0-3) 

The service uses `Promise.all(dto.map(...))` — all items are processed **concurrently**, making resource exhaustion worse than sequential processing: [5](#0-4) 

Each concurrent item calls `SDKTransaction.fromBytes()`, iterates nested `nodeMap → txMap → publicKey` loops, and calls `sdkTransaction.addSignature()`: [6](#0-5) 

**No DTO-level array size constraint exists** on either endpoint's input DTO: [7](#0-6) 

### Impact Explanation

A single authenticated POST request with an array of e.g. 50,000 `UploadSignatureMapDto` entries causes:

- **CPU exhaustion**: protobuf deserialization + ECDSA/ED25519 signature verification × N items, all concurrent on endpoint 2
- **Memory exhaustion**: each `SDKTransaction.fromBytes()` allocates a full in-memory transaction object; N items held simultaneously
- **DB connection pool starvation**: `Promise.all` fires N concurrent DB queries against the pool (default `POSTGRES_MAX_POOL_SIZE: 3`), blocking all other requests
- **Service unavailability**: the NestJS event loop is blocked for the duration, making the API unresponsive to all other users

### Likelihood Explanation

Any registered, verified user can trigger this. The attacker needs only a valid JWT token (obtainable by registering an account) and the ability to POST a crafted JSON array. No admin or privileged role is required. The `JwtAuthGuard` and `VerifiedUserGuard` guards are the only gatekeepers: [8](#0-7) 

The global rate limits (`GLOBAL_MINUTE_LIMIT: 10000`, `GLOBAL_SECOND_LIMIT: 1000`) count individual HTTP requests, not array elements within a single request, so a single oversized request bypasses them entirely: [9](#0-8) 

### Recommendation

1. Add `@ArrayMaxSize(N)` (e.g. `N = 100`) to the `UploadSignatureMapDto[]` body parameter on both endpoints using NestJS class-validator.
2. Enforce a hard cap inside the service before processing begins (e.g. `if (dto.length > MAX_BATCH) throw new BadRequestException(...)`).
3. For `uploadSignatureMaps`, replace `Promise.all` with sequential or chunked processing to prevent concurrent resource exhaustion.
4. Apply a request body size limit at the HTTP layer (NestJS `bodyParser` `limit` option) to cap raw payload size.

### Proof of Concept

```bash
# Attacker registers and obtains a JWT token, then sends:
curl -X POST https://api.example.com/transactions/signatures/import \
  -H "Authorization: Bearer <valid_jwt>" \
  -H "Content-Type: application/json" \
  -d "$(python3 -c "
import json
# 10000 entries, each referencing a valid transaction id
payload = [{'id': 1, 'signatureMap': {}} for _ in range(10000)]
print(json.dumps(payload))
")"
```

Each of the 10,000 entries causes `SDKTransaction.fromBytes()` + cryptographic validation on the server. The server event loop is saturated for the duration of the request, making all concurrent API calls time out. A single request is sufficient; no repeated requests are needed.

### Citations

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L525-573)
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

        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());

        results.set(id, { id });
        updates.set(id, {
          id,
          transactionBytes: transaction.transactionBytes,
          transactionId: transaction.transactionId,
          network: transaction.mirrorNetwork,
        });
      } catch (error) {
        results.set(id, {
          id,
          error:
            (error instanceof BadRequestException)
              ? error.message
              : 'An unexpected error occurred while importing the signatures',
        });
      }
    }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L575-576)
```typescript
    //Added a batch mechanism, probably should limit this on the api side of things
    const BATCH_SIZE = 500;
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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L167-199)
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
  }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L234-267)
```typescript
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
  }
```

**File:** back-end/apps/api/src/transactions/dto/create-transaction.dto.ts (L1-44)
```typescript
import { IsBoolean, IsDate, IsNotEmpty, IsNumber, IsOptional, IsString } from 'class-validator';
import { Type } from 'class-transformer';

import { TransformBuffer } from '@app/common';

//TODO approvers and observers can be added to this dto, validatenested,
// also adding cascade to the transaction relations to enable single saves
export class CreateTransactionDto {
  @IsString()
  name: string;

  @IsString()
  description: string;

  @IsNotEmpty()
  @TransformBuffer()
  transactionBytes: Buffer;

  @IsNumber()
  creatorKeyId: number;

  @IsNotEmpty()
  @TransformBuffer()
  signature: Buffer;

  @IsNotEmpty()
  @IsString()
  mirrorNetwork: string;

  @Type(() => Date)
  @IsDate()
  @IsOptional()
  cutoffAt?: Date;

  @IsOptional()
  @IsBoolean()
  isManual?: boolean;

  @IsOptional()
  @IsNumber()
  reminderMillisecondsBefore?: number;
}


```

**File:** charts/transaction-tool/values.yaml (L151-157)
```yaml
    JWT_EXPIRATION: "365"
    OTP_EXPIRATION: "20"
    ANONYMOUS_MINUTE_LIMIT: "3"
    ANONYMOUS_FIVE_SECOND_LIMIT: "1"
    GLOBAL_MINUTE_LIMIT: "10000"
    GLOBAL_SECOND_LIMIT: "1000"
    NODE_ENV: "production"
```
