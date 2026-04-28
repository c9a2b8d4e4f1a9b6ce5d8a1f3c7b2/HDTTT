All claims are verified against the actual codebase. Here is the audit report:

---

# Audit Report

## Title
Unbounded Batch Signature Upload Enables Amplified DoS on the API Server

## Summary
The `POST /transactions/:transactionId?/signers` and `POST /transactions/signatures/import` endpoints accept an unbounded array of `UploadSignatureMapDto` objects, each containing an unbounded nested signature map (nodes × transactionIds × public keys). A single authenticated, verified user can craft one HTTP request that forces the server to perform an arbitrarily large number of cryptographic operations and concurrent processing pipelines, exhausting CPU and database resources.

## Finding Description

**1. Controller accepts unbounded array with no size cap**

`uploadSignatureMap` in `signers.controller.ts` declares its body as `UploadSignatureMapDto | UploadSignatureMapDto[]` with no `@ArrayMaxSize` decorator or any other cardinality guard. [1](#0-0) 

The shared helper `transformAndValidateDto` wraps a single item in an array and then processes every element — no upper bound is enforced anywhere in the call chain. [2](#0-1) 

**2. `UploadSignatureMapDto` has no array-size constraint**

The DTO carries only `@IsDefined`, `@IsNumber`, `@IsNotEmptyObject`, and `@IsSignatureMap()` — no `@ArrayMaxSize` on the outer array, and no depth or count limit on the nested map. [3](#0-2) 

**3. `@IsSignatureMap()` iterates O(nodes × txIds × keys) during transformation**

The decorator unconditionally iterates every node account ID, every transaction ID, and every public key in the submitted map, calling `AccountId.fromString`, `TransactionId.fromString`, and `PublicKey.fromString` for each entry. There is no depth or count limit. [4](#0-3) 

**4. Per-entry cryptographic work in `processTransactionSignatures`**

For every unique public key found in the map, the service calls `SDKTransaction.fromBytes` (deserializes the full transaction) and `sdkTransaction.addSignature` (an expensive SDK cryptographic operation). [5](#0-4) 

**5. Batch amplification — all entries processed concurrently via `Promise.all`**

`validateAndProcessSignatures` fans out all DTO items into a `Promise.all`, meaning a 1 000-item array triggers 1 000 parallel cryptographic + deserialization pipelines simultaneously. [6](#0-5) 

**6. Secondary vector — unbounded recursive approver tree**

`CreateTransactionApproversArrayDto` has no `@ArrayMaxSize` on `approversArray`, and the nested `approvers` field in `CreateTransactionApproverDto` also has no max-size constraint. The service processes this with a recursive `createApprover` function that issues multiple DB queries per node. [7](#0-6) [8](#0-7) 

**7. Throttling does not mitigate this**

The user-level throttler limits to 100 requests/minute and 10 requests/second — it counts *requests*, not *work per request*. A single request with a 10 000-entry array exhausts server resources within one throttle window. [9](#0-8) 

## Impact Explanation
A single authenticated user can submit one HTTP request containing thousands of `UploadSignatureMapDto` entries, each with a large signature map. The server performs O(N × M × K) cryptographic operations (N = array length, M = nodes per map, K = keys per node) and a proportional number of concurrent DB queries, exhausting CPU and database connection pools. This can render the API unresponsive for all other users (DoS). The `importSignatures` endpoint (`POST /transactions/signatures/import`) is identically affected, as it uses the same `transformAndValidateDto` helper and processes entries in a loop with per-entry `SDKTransaction.fromBytes` and `addSignature` calls. [10](#0-9) 

## Likelihood Explanation
Any user who has completed email verification (`VerifiedUserGuard`) can reach these endpoints — no admin role or special privilege is required. [11](#0-10) 
The attack requires only a crafted JSON body. The pattern is well-known and trivially reproducible with a single `curl` command.

## Recommendation
1. **Add `@ArrayMaxSize(N)` to the outer array** in `transformAndValidateDto` call sites or directly on the controller body parameter (e.g., `@ArrayMaxSize(50)`).
2. **Add a count limit inside `@IsSignatureMap()`** — reject maps with more than a configurable number of node entries, transaction IDs, or public keys per node.
3. **Add `@ArrayMaxSize` to `CreateTransactionApproversArrayDto.approversArray`** and to `CreateTransactionApproverDto.approvers`.
4. **Enforce a maximum recursion depth** in the `createApprover` recursive function.
5. Consider adding a **payload size limit** at the HTTP layer (e.g., NestJS body size limit) as a defense-in-depth measure.

## Proof of Concept
```http
POST /transactions/signers HTTP/1.1
Authorization: Bearer <valid_verified_user_jwt>
Content-Type: application/json

[
  { "id": 1, "signatureMap": { "0.0.3": { "0.0.1@1700000000.000000000": { "<valid_der_pubkey>": "<valid_sig>" } }, "0.0.4": { ... }, ... /* 100 nodes */ } },
  { "id": 1, "signatureMap": { ... /* same large map */ } },
  ... /* repeat 1000 times */
]
```

The server will invoke `IsSignatureMap` transformation for each of the 1 000 entries (iterating 100 nodes × M txIds × K keys each), then fan all 1 000 entries into `Promise.all`, each calling `SDKTransaction.fromBytes` and `addSignature`. CPU and DB connection pool exhaustion follows within a single request, well within the 100 req/min throttle window. [4](#0-3) [6](#0-5)

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L37-40)
```typescript
@ApiTags('Transaction Signers')
@Controller('transactions/:transactionId?/signers')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class SignersController {
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

**File:** back-end/libs/common/src/decorators/is-signature-map.decorator.ts (L38-63)
```typescript
      for (const nodeAccountId in value) {
        const transactionIds = value[nodeAccountId];

        assertNodeAccountIdValid(nodeAccountId, transactionIds);

        for (const transactionId in transactionIds) {
          const publicKeys = transactionIds[transactionId];
          assertTransactionIdValid(transactionId, publicKeys);

          for (const publicKey in publicKeys) {
            const signature = publicKeys[publicKey];
            const decodedSignature = new Uint8Array(decode(signature));

            if (decodedSignature.length === 0) {
              throw new BadRequestException(ErrorCodes.ISNMP);
            }

            signatureMap.addSignature(
              AccountId.fromString(nodeAccountId),
              TransactionId.fromString(transactionId),
              PublicKey.fromString(publicKey),
              decodedSignature,
            );
          }
        }
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

**File:** back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts (L1-30)
```typescript
import { IsArray, IsNumber, IsOptional, ValidateNested, ArrayMinSize } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateTransactionApproverDto {
  @IsNumber()
  @IsOptional()
  listId?: number;

  @IsNumber()
  @IsOptional()
  threshold?: number;

  @IsNumber()
  @IsOptional()
  userId?: number;

  @IsArray()
  @ArrayMinSize(1)
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionApproverDto)
  approvers?: CreateTransactionApproverDto[];
}

export class CreateTransactionApproversArrayDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionApproverDto)
  approversArray: CreateTransactionApproverDto[];
}
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-332)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);

    const approvers: TransactionApprover[] = [];

    try {
      await this.dataSource.transaction(async transactionalEntityManager => {
        const createApprover = async (dtoApprover: CreateTransactionApproverDto) => {
          /* Validate Approver's DTO */
          this.validateApprover(dtoApprover);

          /* Check if the approver already exists */
          if (await this.isNode(dtoApprover, transactionId, transactionalEntityManager))
            throw new Error(this.APPROVER_ALREADY_EXISTS);

          /* Check if the parent approver exists and has threshold */
          if (typeof dtoApprover.listId === 'number') {
            const parent = await transactionalEntityManager.findOne(TransactionApprover, {
              where: { id: dtoApprover.listId },
            });

            if (!parent) throw new Error(this.PARENT_APPROVER_NOT_FOUND);

            /* Check if the root transaction is the same */
            const root = await this.getRootNodeFromNode(
              dtoApprover.listId,
              transactionalEntityManager,
            );
            if (root?.transactionId !== transactionId)
              throw new Error(this.ROOT_TRANSACTION_NOT_SAME);
          }

          /* Check if the user exists */
          if (typeof dtoApprover.userId === 'number') {
            const userCount = await transactionalEntityManager.count(User, {
              where: { id: dtoApprover.userId },
            });

            if (userCount === 0) throw new Error(this.USER_NOT_FOUND(dtoApprover.userId));
          }

          /* Check if there are sub approvers */
          if (
            typeof dtoApprover.userId === 'number' &&
            dtoApprover.approvers &&
            dtoApprover.approvers.length > 0
          )
            throw new Error(this.ONLY_USER_OR_TREE);

          /* Check if the approver has threshold when there are children */
          if (
            dtoApprover.approvers &&
            dtoApprover.approvers.length > 0 &&
            (dtoApprover.threshold === null || isNaN(dtoApprover.threshold))
          )
            throw new Error(this.THRESHOLD_REQUIRED);

          /* Check if the approver has children when there is threshold */
          if (
            typeof dtoApprover.threshold === 'number' &&
            (!dtoApprover.approvers || dtoApprover.approvers.length === 0)
          )
            throw new Error(this.CHILDREN_REQUIRED);

          /* Check if the approver threshold is less or equal to the number of approvers */
          if (
            dtoApprover.approvers &&
            (dtoApprover.threshold > dtoApprover.approvers.length || dtoApprover.threshold === 0)
          )
            throw new Error(this.THRESHOLD_LESS_OR_EQUAL_APPROVERS(dtoApprover.approvers.length));

          const data: DeepPartial<TransactionApprover> = {
            transactionId:
              dtoApprover.listId === null || isNaN(dtoApprover.listId) ? transactionId : null,
            listId: dtoApprover.listId,
            threshold:
              dtoApprover.threshold && dtoApprover.approvers ? dtoApprover.threshold : null,
            userId: dtoApprover.userId,
          };

          if (typeof dtoApprover.userId === 'number') {
            const userApproverRecords = await this.getApproversByTransactionId(
              transactionId,
              dtoApprover.userId,
              transactionalEntityManager,
            );

            if (userApproverRecords.length > 0) {
              data.signature = userApproverRecords[0].signature;
              data.userKeyId = userApproverRecords[0].userKeyId;
              data.approved = userApproverRecords[0].approved;
            }
          }

          /* Create approver */
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L493-574)
```typescript
  async importSignatures(
    dto: UploadSignatureMapDto[],
    user: User,
  ): Promise<SignatureImportResultDto[]> {
    type UpdateRecord = {
      id: number;
      transactionBytes: Buffer;
      transactionId: string;
      network: string;
    };

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
