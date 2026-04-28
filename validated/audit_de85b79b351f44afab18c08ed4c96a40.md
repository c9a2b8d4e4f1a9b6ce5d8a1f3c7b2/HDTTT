### Title
Unbounded `groupItems` Array and Missing String Length Limits in Transaction API Enable Authenticated DoS

### Summary
The `POST /transaction-groups` endpoint accepts a `CreateTransactionGroupDto` whose `groupItems` array has no `@ArrayMaxSize()` constraint. Any authenticated user can submit a single request containing thousands of transaction items, each with full binary payloads, forcing the server to process all of them in parallel via `Promise.all`. Additionally, the `name` and `description` fields in `CreateTransactionDto` carry no `@MaxLength()` decorator, allowing arbitrarily long strings to reach the service layer before any DB-level rejection. Both gaps are reachable by any registered user with no elevated privileges.

### Finding Description

**Root cause 1 — Unbounded `groupItems` array**

`CreateTransactionGroupDto` declares `groupItems` with only `@IsArray()`, `@IsNotEmpty()`, and `@ValidateNested({ each: true })`. There is no `@ArrayMaxSize()` guard. [1](#0-0) 

The controller passes the DTO directly to `createTransactionGroup`, which immediately fans out to `createTransactions`: [2](#0-1) 

`createTransactions` runs `validateAndPrepareTransaction` for every item concurrently via `Promise.all`: [3](#0-2) 

Each call parses raw protobuf bytes (`SDKTransaction.fromBytes`), verifies a cryptographic signature, and performs DB lookups. With thousands of items in one request, this saturates CPU, memory, and the database connection pool simultaneously.

**Root cause 2 — No `@MaxLength` on `name` and `description` in `CreateTransactionDto`**

Both fields carry only `@IsString()`: [4](#0-3) 

The database entity enforces `length: 50` and `length: 256` at the column level: [5](#0-4) 

But the DTO validation passes before the DB constraint fires, so the full string is deserialized, logged, and processed by the service layer on every request.

**Root cause 3 — Unbounded `UploadSignatureMapDto[]` array on the signers endpoint**

`POST /transactions/:transactionId/signers` and `POST /transactions/signatures/import` both accept `UploadSignatureMapDto | UploadSignatureMapDto[]` with no array-size cap: [6](#0-5) 

**Global body limit is 2 MB — insufficient mitigation**

The only server-wide guard is: [7](#0-6) 

Within 2 MB, a minimal `CreateTransactionGroupItemDto` (small hex-encoded transaction, short strings) occupies roughly 300–500 bytes, allowing 4,000–6,000 items per request. Each item triggers protobuf deserialization, signature verification, and a DB write.

### Impact Explanation

A single authenticated user can submit one crafted `POST /transaction-groups` request that:
- Saturates all available CPU cores with parallel `Promise.all` cryptographic operations.
- Exhausts the PostgreSQL connection pool with a massive batch insert inside a single DB transaction.
- Causes the Node.js process to OOM-crash if enough items are packed into the 2 MB window.
- Degrades or denies service for all other users sharing the same API instance.

The `name`/`description` gap amplifies this: each item in the group can carry a 256-byte description string that is fully deserialized and logged before the DB rejects it, adding memory pressure per item.

### Likelihood Explanation

Any user who has completed registration and email verification (`VerifiedUserGuard`) and has at least one uploaded key (`HasKeyGuard`) can reach this endpoint. No admin role is required. The IP-based throttler (`IpThrottlerModule`) limits request frequency but does not cap payload complexity; a single request within the rate limit is sufficient to trigger the issue. [8](#0-7) 

### Recommendation

1. **Add `@ArrayMaxSize(N)` to `groupItems`** in `CreateTransactionGroupDto` (e.g., `N = 50` to match realistic use cases).
2. **Add `@MaxLength(50)` to `name`** and **`@MaxLength(256)` to `description`** in `CreateTransactionDto` to mirror the DB column constraints and reject oversized strings at the DTO layer.
3. **Add `@ArrayMaxSize(N)` to the `UploadSignatureMapDto[]` body** in both the signers controller and the import endpoint.
4. **Consider reducing the global JSON body limit** from `2mb` to a value that reflects the maximum legitimate payload (e.g., `100kb` for single-transaction endpoints, with a separate higher limit only for the group endpoint).
5. **Apply per-user throttling** (`UserThrottlerGuard`, which already exists but is not applied to transaction-creation endpoints) to the `POST /transaction-groups` and `POST /transactions` routes.

### Proof of Concept

```bash
# Authenticated as any verified user with at least one key
TOKEN="<jwt>"
SERVER="https://api.example.com"

# Build a payload with 5000 minimal group items
python3 -c "
import json, sys
item = {
  'seq': 0,
  'transaction': {
    'name': 'x' * 50,
    'description': 'y' * 256,
    'transactionBytes': 'deadbeef' * 100,   # 400 hex chars = 200 bytes
    'signature': 'cafebabe' * 16,
    'creatorKeyId': 1,
    'mirrorNetwork': 'testnet'
  }
}
payload = {
  'description': 'dos',
  'atomic': False,
  'groupItems': [dict(item, seq=i) for i in range(5000)]
}
json.dump(payload, sys.stdout)
" > payload.json

curl -s -o /dev/null -w "%{time_total}\n" \
  -X POST "$SERVER/transaction-groups" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @payload.json
```

**Expected outcome:** The server accepts the request (body is under 2 MB), spawns 5,000 parallel `validateAndPrepareTransaction` calls, exhausts the DB connection pool, and either returns after a multi-second delay or crashes the process — denying service to concurrent users.

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction-group.dto.ts (L24-28)
```typescript
  @IsArray()
  @IsNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionGroupItemDto)
  groupItems: CreateTransactionGroupItemDto[];
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L46-53)
```typescript
    // Extract all transaction DTOs
    const transactionDtos = dto.groupItems.map(item => item.transaction);

    // Batch create all transactions
    const transactions = await this.transactionsService.createTransactions(
      transactionDtos,
      user,
    );
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L408-412)
```typescript
      // Validate all DTOs upfront
      const validatedData = await Promise.all(
        dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)),
      );

```

**File:** back-end/apps/api/src/transactions/dto/create-transaction.dto.ts (L9-13)
```typescript
  @IsString()
  name: string;

  @IsString()
  description: string;
```

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L74-81)
```typescript
  @Column({ length: 50 })
  name: string;

  @Column()
  type: TransactionType;

  @Column({ length: 256 })
  description: string;
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

**File:** back-end/apps/api/src/setup-app.ts (L43-43)
```typescript
  app.use(json({ limit: '2mb' }));
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L43-50)
```typescript
  @Post()
  @Serialize(TransactionGroupDto)
  createTransactionGroup(
    @GetUser() user: User,
    @Body() dto: CreateTransactionGroupDto,
  ): Promise<TransactionGroup> {
    return this.transactionGroupsService.createTransactionGroup(user, dto);
  }
```
