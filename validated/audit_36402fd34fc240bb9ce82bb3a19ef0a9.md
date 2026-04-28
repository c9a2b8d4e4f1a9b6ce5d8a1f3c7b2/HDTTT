Based on my code review, the vulnerability claims are substantiated by the actual code. Let me verify the key facts before rendering a verdict.

**Confirmed facts:**

1. `UploadSignatureMapDto` has no `@ArrayMaxSize()` or equivalent constraint — only field-level validators (`@IsDefined`, `@IsNumber`, `@IsSignatureMap`). [1](#0-0) 

2. `POST /transactions/signatures/import` accepts an unbounded array and iterates with `for...of`, calling `SDKTransaction.fromBytes()` + `validateSignature()` + `addSignature()` per element. [2](#0-1) [3](#0-2) 

3. Developer comment at line 575 explicitly acknowledges the missing limit: `//Added a batch mechanism, probably should limit this on the api side of things`. [4](#0-3) 

4. `POST /transactions/:transactionId?/signers` accepts an unbounded array and fans all elements out concurrently via `Promise.all`, each calling `SDKTransaction.fromBytes()` inside `processTransactionSignatures`. [5](#0-4) [6](#0-5) 

5. The global `IpThrottlerGuard` throttles by **request count** (1000/sec, 10000/min per the example config), not by array element count within a single request — a single request with N=10,000 items counts as 1 against the throttler. [7](#0-6) [8](#0-7) 

6. SECURITY.md excludes "Impacts that only require DDoS." This attack requires a **single authenticated HTTP request** with a crafted body — it is not a volumetric DDoS and is therefore in scope. [9](#0-8) 

**One correction to the report:** The DB connection pool exhaustion claim for the `/signers` endpoint is overstated. `loadTransactionData` uses a single batched `IN(...)` query, not N concurrent DB connections. The real resource impact is CPU saturation from concurrent `SDKTransaction.fromBytes()` and cryptographic operations via `Promise.all`. [10](#0-9) 

---

Audit Report

## Title
Unbounded Batch Array in Signature Import/Upload Endpoints Enables Authenticated Resource-Exhaustion DoS

## Summary
Two API endpoints accept an attacker-controlled array of `UploadSignatureMapDto` objects with no upper-bound validation on array length. Each element triggers CPU-intensive SDK deserialization and cryptographic signature validation. A single authenticated HTTP request carrying a large array can saturate the server's CPU and heap memory, denying service to all other users. The developers themselves flagged the missing limit in a code comment.

## Finding Description

**Endpoint 1 — `POST /transactions/signatures/import`**

`TransactionsController.importSignatures` accepts `UploadSignatureMapDto[] | UploadSignatureMapDto` with no array size guard: [2](#0-1) 

Inside `TransactionsService.importSignatures`, a `for...of` loop iterates every element. Per element it calls:
- `SDKTransaction.fromBytes(transaction.transactionBytes)` — protobuf deserialization (line 542)
- `validateSignature(sdkTransaction, map)` — ECDSA/ED25519 cryptographic verification (line 547)
- `sdkTransaction.addSignature(publicKey, map)` — signature attachment (line 552) [3](#0-2) 

The developer explicitly acknowledged the missing guard at line 575:
```
//Added a batch mechanism, probably should limit this on the api side of things
``` [4](#0-3) 

**Endpoint 2 — `POST /transactions/:transactionId?/signers`**

`SignersController.uploadSignatureMap` accepts an unbounded array and passes it directly to `SignersService.uploadSignatureMaps`: [5](#0-4) 

`validateAndProcessSignatures` fans all N items out concurrently via `Promise.all`. Each concurrent task calls `processTransactionSignatures`, which calls `SDKTransaction.fromBytes()` (line 223) and performs cryptographic key verification per element: [6](#0-5) [11](#0-10) 

**No array size constraint on the DTO:**

`UploadSignatureMapDto` contains only field-level validators — no `@ArrayMaxSize()` or equivalent: [12](#0-11) 

**Rate limiting does not mitigate this:**

The global `IpThrottlerGuard` counts HTTP requests (1000/sec, 10000/min in production config). A single request with N=10,000 array elements counts as exactly 1 request against the throttler: [7](#0-6) [8](#0-7) 

## Impact Explanation
A single authenticated HTTP request can exhaust server CPU (N sequential or concurrent cryptographic operations) and heap memory (N deserialized SDK transaction objects held simultaneously). For the `/signers` endpoint, `Promise.all` fans all N operations concurrently, multiplying the CPU impact. This causes complete service unavailability for all organization users — no transactions can be signed, submitted, or monitored — for as long as the attacker repeats the request.

Note: The DB connection pool exhaustion claim in the original report is overstated for the `/signers` endpoint, as `loadTransactionData` uses a single batched `IN(...)` query rather than N concurrent DB connections. The primary resource impact is CPU saturation from concurrent cryptographic operations.

## Likelihood Explanation
Any registered, verified user can reach both endpoints — authentication is the only barrier. No special role, key, or privilege is required. The attack requires a single HTTP request with a crafted JSON body. The developer comment at line 575 (`//Added a batch mechanism, probably should limit this on the api side of things`) confirms the team is aware the limit is missing. Likelihood is **high**.

## Recommendation
1. **Add `@ArrayMaxSize(N)` to the array parameter** in both controllers (e.g., `N = 100` or a configurable value), or wrap the array in a DTO class that carries the decorator.
2. **Enforce the limit at the service layer** as a defense-in-depth measure: reject or truncate arrays exceeding the maximum before processing begins.
3. **For the `/signers` endpoint**, consider replacing unbounded `Promise.all` with a concurrency-limited alternative (e.g., processing in chunks) to prevent CPU saturation even within the allowed limit.
4. **Add a request body size limit** at the HTTP layer (NestJS/Express `bodyParser` `limit` option) to prevent oversized payloads from reaching application code.

## Proof of Concept

```bash
# Generate a large array of UploadSignatureMapDto items
python3 -c "
import json, sys
item = {'id': 1, 'signatureMap': {'0.0.3': {'0.0.1@1234567890.000000000': {'302a300506032b6570...': '0xdeadbeef...'}}}}
payload = [item] * 10000
print(json.dumps(payload))
" > payload.json

# Send as a single authenticated request
curl -X POST https://<server>/transactions/signatures/import \
  -H 'Authorization: Bearer <valid_jwt>' \
  -H 'Content-Type: application/json' \
  -d @payload.json
```

The server will enter the `for...of` loop in `importSignatures` and execute `SDKTransaction.fromBytes()` + `validateSignature()` 10,000 times sequentially, saturating the Node.js event loop. For the `/signers` endpoint, replace the URL with `/transactions/signers` — `Promise.all` will fan all 10,000 operations concurrently, amplifying the CPU impact.

### Citations

**File:** back-end/apps/api/src/transactions/dto/upload-signature.dto.ts (L1-43)
```typescript
import { ApiProperty } from '@nestjs/swagger';

import { IsSignatureMap } from '@app/common';
import { IsDefined, IsNotEmptyObject, IsNumber } from 'class-validator';
import { SignatureMap } from '@hiero-ledger/sdk';

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L575-576)
```typescript
    //Added a batch mechanism, probably should limit this on the api side of things
    const BATCH_SIZE = 500;
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

**File:** back-end/apps/api/src/throttlers/ip-throttler.module.ts (L13-24)
```typescript
        throttlers: [
          {
            name: 'global-minute',
            ttl: seconds(60),
            limit: configService.getOrThrow<number>('GLOBAL_MINUTE_LIMIT'),
          },
          {
            name: 'global-second',
            ttl: seconds(1),
            limit: configService.getOrThrow<number>('GLOBAL_SECOND_LIMIT'),
          },
        ],
```

**File:** back-end/apps/api/example.env (L25-29)
```text
# Throttler limits
ANONYMOUS_MINUTE_LIMIT=3
ANONYMOUS_FIVE_SECOND_LIMIT=1
GLOBAL_MINUTE_LIMIT=10000
GLOBAL_SECOND_LIMIT=1000
```

**File:** SECURITY.md (L44-44)
```markdown
- Impacts that only require DDoS.
```
