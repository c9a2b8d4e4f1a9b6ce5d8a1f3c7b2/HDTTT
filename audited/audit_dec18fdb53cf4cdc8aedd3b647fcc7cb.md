### Title
Oversized HTTP JSON Body Limit Enables Memory Exhaustion DoS via Transaction Submission Endpoints

### Summary

The NestJS API service configures a 2 MB HTTP JSON body limit, which is ~333× larger than the actual maximum transaction size (6 KB for normal payers, 128 KB for privileged payers). The `POST /transactions` and `POST /transaction-groups` endpoints accept a `transactionBytes` field with no DTO-level size constraint. The application-level size check (`isTransactionBodyOverMaxSize`) only executes in the service layer after the full 2 MB body has already been parsed and allocated in memory. An authenticated attacker can send repeated near-2 MB requests to exhaust server memory and cause a denial of service.

### Finding Description

**Root cause — oversized body limit:**

In `back-end/apps/api/src/setup-app.ts` line 43, the Express JSON middleware is configured with a 2 MB limit:

```typescript
app.use(json({ limit: '2mb' }));
``` [1](#0-0) 

The actual maximum transaction size enforced by the application is 6 KB for normal payers and 128 KB for privileged payers: [2](#0-1) 

**Root cause — no DTO-level size constraint on `transactionBytes`:**

`CreateTransactionDto` accepts `transactionBytes` as a raw `Buffer` with no `@MaxLength()` or byte-size decorator: [3](#0-2) 

**Root cause — size check is post-parse:**

The `isTransactionBodyOverMaxSize` guard runs inside `validateAndPrepareTransaction`, which is called only after the full 2 MB body has been deserialized into memory by the middleware: [4](#0-3) 

**Amplification via unbounded `groupItems` array:**

`CreateTransactionGroupDto` has no `@ArrayMaxSize()` on `groupItems`. A single 2 MB request to `POST /transaction-groups` can carry dozens of group items, each with a large `transactionBytes` value, causing the server to parse, validate, and call `SDKTransaction.fromBytes()` on each one before any item is rejected: [5](#0-4) 

The `createTransactions` service method processes all DTOs with `Promise.all`, meaning all items in a single request are deserialized and validated concurrently: [6](#0-5) 

**Attack path:**

1. Attacker registers a user account (standard self-service registration).
2. Attacker obtains a JWT token via `POST /auth/login`.
3. Attacker sends concurrent `POST /transaction-groups` requests, each ~2 MB, containing many group items with large `transactionBytes` hex strings.
4. The server allocates ~2 MB per request in the JSON parser before any application-level check fires.
5. Concurrent requests exhaust available heap memory, causing the Node.js process to crash or become unresponsive.

### Impact Explanation

A single authenticated user can cause the API service to exhaust memory and become unavailable to all other users. Because the body is fully buffered before any validation, even a modest number of concurrent requests (e.g., 50 × 2 MB = 100 MB of simultaneous allocations) can destabilize the process. This results in complete service unavailability for all organization users who depend on the API for transaction coordination, signing, and execution.

### Likelihood Explanation

Any registered user — including a malicious organization member or an attacker who self-registers — can reach `POST /transactions` and `POST /transaction-groups`. The IP-based throttler (`IpThrottlerModule`) applies rate limits configured via `GLOBAL_MINUTE_LIMIT` and `GLOBAL_SECOND_LIMIT` environment variables: [7](#0-6) 

However, the throttler counts requests, not bytes. A single request at the rate limit can still carry a full 2 MB payload. If the per-second limit is, for example, 10 requests/second, an attacker can sustain 20 MB/s of body allocations from a single IP, which is sufficient to exhaust typical Node.js heap limits within seconds. The attack requires only a valid JWT and a script to send large POST bodies.

### Recommendation

1. **Reduce the global JSON body limit** to a value that reflects the actual maximum legitimate payload. Given the largest valid transaction is 128 KB (privileged payer) plus JSON envelope overhead, a limit of `256kb` is sufficient:
   ```typescript
   app.use(json({ limit: '256kb' }));
   ``` [1](#0-0) 

2. **Add a DTO-level byte-size constraint** on `transactionBytes` in `CreateTransactionDto` using a custom `@MaxByteLength(131072)` decorator or a `@Transform` + `@IsLength` combination, so oversized payloads are rejected before service logic runs. [3](#0-2) 

3. **Add `@ArrayMaxSize()`** to `groupItems` in `CreateTransactionGroupDto` to cap the number of transactions per group request: [5](#0-4) 

4. **Make the throttler byte-aware** or add a separate per-user rate limit on write endpoints to limit the total bytes processed per time window.

### Proof of Concept

```bash
# 1. Register and obtain a JWT token
TOKEN=$(curl -s -X POST https://api.example.com/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@example.com","password":"password"}' \
  | jq -r '.accessToken')

# 2. Build a ~2 MB transactionBytes hex string (padding with valid-looking hex)
LARGE_HEX=$(python3 -c "print('aa' * 1_000_000)")  # 2 MB hex = 1 MB bytes

# 3. Send concurrent requests to exhaust memory
for i in $(seq 1 50); do
  curl -s -X POST https://api.example.com/transactions \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"x\",\"description\":\"x\",\"transactionBytes\":\"$LARGE_HEX\",
         \"creatorKeyId\":1,\"signature\":\"aa\",\"mirrorNetwork\":\"testnet\"}" &
done
wait
```

Each request causes the server to allocate ~2 MB in the JSON parser before `isTransactionBodyOverMaxSize` rejects it. Fifty concurrent requests allocate ~100 MB simultaneously. The `POST /transaction-groups` variant with many `groupItems` per request amplifies this further by triggering concurrent `SDKTransaction.fromBytes()` calls on each oversized item.

### Citations

**File:** back-end/apps/api/src/setup-app.ts (L43-43)
```typescript
  app.use(json({ limit: '2mb' }));
```

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L58-61)
```typescript
export const MAX_TRANSACTION_BYTE_SIZE = 6_144;
// HIP-1300: privileged governance fee payers (0.0.2 and 0.0.42-0.0.799) get an
// increased transaction size limit of 128 KB to accommodate council signatures.
export const MAX_PRIVILEGED_TRANSACTION_BYTE_SIZE = 131_072;
```

**File:** back-end/apps/api/src/transactions/dto/create-transaction.dto.ts (L15-17)
```typescript
  @IsNotEmpty()
  @TransformBuffer()
  transactionBytes: Buffer;
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L409-411)
```typescript
      const validatedData = await Promise.all(
        dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)),
      );
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L928-931)
```typescript
    // Check size
    if (isTransactionBodyOverMaxSize(sdkTransaction)) {
      throw new BadRequestException(ErrorCodes.TOS);
    }
```

**File:** back-end/apps/api/src/transactions/dto/create-transaction-group.dto.ts (L24-28)
```typescript
  @IsArray()
  @IsNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionGroupItemDto)
  groupItems: CreateTransactionGroupItemDto[];
```

**File:** back-end/apps/api/src/throttlers/ip-throttler.module.ts (L13-27)
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
      }),
    }),
  ],
```
