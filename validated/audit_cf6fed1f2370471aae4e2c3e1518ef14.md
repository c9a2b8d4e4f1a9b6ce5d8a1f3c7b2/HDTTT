### Title
Unbounded Batch Array in `uploadSignatureMap` and `importSignatures` Endpoints Enables Authenticated Single-Request Resource Exhaustion

### Summary
The `POST /transactions/:transactionId?/signers` and `POST /transactions/signatures/import` endpoints accept an array of `UploadSignatureMapDto` objects with no enforced size limit. An authenticated user can submit a single HTTP request containing thousands of entries. The service processes all entries concurrently via `Promise.all`, spawning unbounded parallel work units that exhaust server CPU and memory, degrading or crashing the API for all users.

### Finding Description

**Root cause — no array size cap at any layer:**

The controller accepts `UploadSignatureMapDto | UploadSignatureMapDto[]` directly from the request body: [1](#0-0) 

The DTO itself carries no `@ArrayMaxSize` or equivalent constraint: [2](#0-1) 

The same pattern is present on the import endpoint: [3](#0-2) 

**Unbounded concurrent processing:**

`validateAndProcessSignatures` fans out every array element into a concurrent `Promise.all`: [4](#0-3) 

Each concurrent branch executes:
1. `SDKTransaction.fromBytes(transaction.transactionBytes)` — CPU-intensive protobuf deserialization.
2. `validateTransactionStatus` — another `fromBytes` call.
3. `processTransactionSignatures` — three nested loops over the attacker-supplied `SignatureMap`, plus `addSignature` per key. [5](#0-4) 

**Duplicate-ID amplification:**

`loadTransactionData` batch-fetches transactions with `In(transactionIds)`. PostgreSQL deduplicates the IDs, so a single valid transaction ID repeated N times in the request body results in one DB row returned — but `Promise.all` still spawns N concurrent processing branches, each deserializing and processing the same transaction bytes independently. [6](#0-5) 

**Second dimension — unbounded `SignatureMap` depth:**

The attacker also controls the `signatureMap` field of each DTO entry. The three nested loops in `processTransactionSignatures` iterate over every node → transaction → public-key entry in the map with no depth or count limit, multiplying CPU cost per array element. [7](#0-6) 

### Impact Explanation
A single crafted HTTP request causes the Node.js event loop to be saturated by thousands of concurrent CPU-bound tasks (protobuf deserialization, ECDSA signature verification). This blocks all other requests from being processed, rendering the API unavailable for every user until the request completes or the process OOMs. Because the work is done inside `Promise.all` without any concurrency cap, memory pressure also grows linearly with array size.

### Likelihood Explanation
The attacker precondition is only a valid JWT — any registered, verified user qualifies. No admin role, no leaked credentials, and no special account state is required. The attack is a single HTTP POST with a crafted JSON body. The two affected endpoints are standard product workflows (signing and importing signatures), so they are reachable in normal operation.

### Recommendation
1. **Enforce an array size limit** at the DTO/controller layer before any processing begins. Add `@ArrayMaxSize(N)` (e.g., 50–100) to the wrapper or validate `Array.isArray(body) && body.length > MAX` in the controller and return `400` immediately.
2. **Cap `SignatureMap` entries** inside `@IsSignatureMap()` validator to reject maps with more than a reasonable number of node/key entries.
3. **Replace `Promise.all` with a concurrency-limited queue** (e.g., `p-limit`) so that even if a large array slips through, the server processes at most K items in parallel.
4. **Deduplicate IDs** before the processing loop so that N copies of the same ID do not produce N parallel work units.

### Proof of Concept

**Preconditions:** Valid JWT for any registered user; one existing transaction in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` status with known ID `TX_ID`.

**Request:**
```
POST /transactions/signers
Authorization: Bearer <valid_jwt>
Content-Type: application/json

[
  { "id": TX_ID, "signatureMap": { "0.0.3": { "0.0.2@1234.0": { "<DER_KEY>": "<SIG>" } } } },
  { "id": TX_ID, "signatureMap": { ... } },
  ... (repeated 10 000 times)
]
```

**Expected outcome:** The server spawns 10 000 concurrent `Promise.all` branches, each calling `SDKTransaction.fromBytes` and iterating the signature map. CPU spikes to 100 %, the event loop stalls, and subsequent requests from other users time out or receive 503 responses until the batch completes or the process is killed by the OS OOM killer.

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L102-107)
```typescript
  async uploadSignatureMap(
    @Body() body: UploadSignatureMapDto | UploadSignatureMapDto[],
    @GetUser() user: User,
    @Query('includeNotifications') includeNotifications?: boolean,
  ): Promise<TransactionSigner[] | UploadSignatureMapResponseDto> {
    const transformedSignatureMaps = await transformAndValidateDto(UploadSignatureMapDto, body);
```

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L217-267)
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
  }
```
