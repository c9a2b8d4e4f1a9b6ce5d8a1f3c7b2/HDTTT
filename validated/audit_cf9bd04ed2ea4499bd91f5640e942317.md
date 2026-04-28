All technical claims verified against the codebase. Here is the audit result:

---

Audit Report

## Title
Unbounded `groupItems` Array in `CreateTransactionGroupDto` Allows Single-Request Resource Exhaustion

## Summary
The `POST /transaction-groups` endpoint accepts a `groupItems` array with no upper-bound constraint. A single authenticated request with an arbitrarily large array triggers `Promise.all()` of N parallel cryptographic verifications, SDK transaction parsings, and async hash computations, followed by a bulk DB insert — all within one HTTP request. This exhausts server CPU, memory, and database connections, bypassing all per-request rate limits.

## Finding Description

**Root cause:** `CreateTransactionGroupDto.groupItems` carries no `@ArrayMaxSize()` decorator. [1](#0-0) 

The only decorators present are `@IsArray()`, `@IsNotEmpty()`, and `@ValidateNested({ each: true })` — none of which bound the array length.

**Exploit path:**

1. Attacker authenticates as any verified organization user (no privileged role required).
2. Attacker sends a single `POST /transaction-groups` with `groupItems` containing N (e.g., 10,000) entries, each with a valid signed transaction body.
3. `TransactionGroupsController.createTransactionGroup` delegates to `TransactionGroupsService.createTransactionGroup` with no additional guards beyond `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. [2](#0-1) 

4. The service extracts all N transaction DTOs and calls `TransactionsService.createTransactions(transactionDtos, user)`. [3](#0-2) 

5. `createTransactions` fires `Promise.all()` of N parallel `validateAndPrepareTransaction` calls simultaneously. [4](#0-3) 

6. Each `validateAndPrepareTransaction` call performs:
   - `publicKey.verify()` — CPU-intensive ECDSA/ED25519 verification
   - `SDKTransaction.fromBytes()` — full deserialization
   - `sdkTransaction.getTransactionHash()` — async SHA-384 [5](#0-4) 

7. After validation, all N `Transaction` entities are saved in a single DB transaction, followed by N `TransactionGroupItem` entities. [6](#0-5) 

**Why rate limiting does not mitigate this:** The user throttler allows 100 requests/minute and 10 requests/second. [7](#0-6) 

A single request with 10,000 items consumes the same rate-limit token as a request with 1 item, but causes orders-of-magnitude more server work. The throttler counts requests, not work units.

## Impact Explanation
A single crafted request can:
- Saturate all available Node.js event-loop threads with parallel crypto operations (`Promise.all` of N concurrent `publicKey.verify` + `fromBytes` + `getTransactionHash`), making the API unresponsive to all other users.
- Exhaust the PostgreSQL connection pool (configured at `POSTGRES_MAX_POOL_SIZE=2` or `3` in all deployment configs) with a massive bulk insert inside a single DB transaction. [8](#0-7) 

- Cause OOM conditions from holding N deserialized SDK transaction objects in memory simultaneously.

This constitutes **service unavailability** for all organization users, achievable by any single verified member.

## Likelihood Explanation
- **Attacker precondition:** Any verified organization account — the lowest privilege level in the system.
- **Attack complexity:** Trivial. Craft one HTTP POST with a large JSON array. No special tooling required.
- **Detection difficulty:** The request is structurally valid and passes all existing validators. No anomaly is flagged before the damage is done.

## Recommendation
1. Add `@ArrayMaxSize(N)` (e.g., `N = 50` or a configurable env value) to `groupItems` in `CreateTransactionGroupDto`:

```typescript
// back-end/apps/api/src/transactions/dto/create-transaction-group.dto.ts
import { ArrayMaxSize, IsArray, IsNotEmpty, IsOptional, IsBoolean, IsString, ValidateNested } from 'class-validator';

@IsArray()
@IsNotEmpty()
@ArrayMaxSize(50)
@ValidateNested({ each: true })
@Type(() => CreateTransactionGroupItemDto)
groupItems: CreateTransactionGroupItemDto[];
```

2. Replace the unbounded `Promise.all()` in `createTransactions` with a concurrency-limited batch (e.g., process in chunks of 10) to prevent CPU/memory spikes even within the allowed maximum.
3. Add a request body size limit at the HTTP layer (NestJS `bodyParser` `limit` option) as a defense-in-depth measure.

## Proof of Concept

```bash
# 1. Authenticate and obtain JWT
TOKEN=$(curl -s -X POST http://localhost:3000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@org.com","password":"password"}' | jq -r '.accessToken')

# 2. Generate a large groupItems array (Python helper)
python3 -c "
import json, sys
item = {
  'seq': 1,
  'transaction': {
    'name': 'Tx',
    'description': 'desc',
    'transactionBytes': '<valid_signed_bytes_hex>',
    'creatorKeyId': 1,
    'signature': '<valid_sig_hex>',
    'mirrorNetwork': 'testnet'
  }
}
payload = {'description': 'dos', 'atomic': False, 'sequential': False, 'groupItems': [item]*5000}
print(json.dumps(payload))
" > payload.json

# 3. Send single request — server CPU/memory spikes, API becomes unresponsive
curl -X POST http://localhost:3000/transaction-groups \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d @payload.json
```

**Expected outcome:** The server attempts 5,000 parallel `publicKey.verify` + `SDKTransaction.fromBytes` + `getTransactionHash` operations simultaneously. Node.js event loop saturates, PostgreSQL connection pool exhausts, and concurrent legitimate requests time out or receive 503 errors.

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction-group.dto.ts (L24-28)
```typescript
  @IsArray()
  @IsNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionGroupItemDto)
  groupItems: CreateTransactionGroupItemDto[];
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L27-50)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionGroupsController {
  constructor(private readonly transactionGroupsService: TransactionGroupsService) {}

  /* Submit a transaction group */
  @ApiOperation({
    summary: 'Create a transaction group',
    description:
      'Create a transaction group for the organization. ' +
      'The group contains group items that each point to a transaction ' +
      'that the organization is to approve, sign, and execute.',
  })
  @ApiResponse({
    status: 201,
    type: TransactionGroupDto,
  })
  @Post()
  @Serialize(TransactionGroupDto)
  createTransactionGroup(
    @GetUser() user: User,
    @Body() dto: CreateTransactionGroupDto,
  ): Promise<TransactionGroup> {
    return this.transactionGroupsService.createTransactionGroup(user, dto);
  }
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

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L55-67)
```typescript
    await this.dataSource.transaction(async manager => {
      // Create group items with corresponding transactions
      const groupItems = transactions.map((transaction, index) => {
        const groupItemDto = dto.groupItems[index];
        const groupItem = manager.create(TransactionGroupItem, groupItemDto);
        groupItem.transaction = transaction;
        groupItem.group = group;
        return groupItem;
      });

      // Save everything
      await manager.save(TransactionGroup, group);
      await manager.save(TransactionGroupItem, groupItems);
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L409-411)
```typescript
      const validatedData = await Promise.all(
        dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)),
      );
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L910-939)
```typescript
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
```

**File:** back-end/apps/api/src/throttlers/user-throttler.module.ts (L14-23)
```typescript
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
```

**File:** back-end/apps/api/example.env (L38-38)
```text
POSTGRES_MAX_POOL_SIZE=2
```
