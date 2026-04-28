### Title
Unbounded Array Input in `uploadSignatureMaps` Enables Single-Request Resource Exhaustion by Any Authenticated User

### Summary
The `POST /transactions/:transactionId?/signers` endpoint accepts a `UploadSignatureMapDto | UploadSignatureMapDto[]` body with no enforced upper bound on array length. The service processes all items concurrently via `Promise.all(dto.map(...))`, and each item executes nested loops over an attacker-controlled `SignatureMap`. A single authenticated user can craft one HTTP request that spawns an unbounded number of concurrent async operations and nested cryptographic iterations, exhausting server CPU and memory and degrading service for all other users.

### Finding Description

**Entry point** — `POST /transactions/:transactionId?/signers` in `SignersController.uploadSignatureMap`:

```
back-end/apps/api/src/transactions/signers/signers.controller.ts, lines 100–119
```

The controller accepts `body: UploadSignatureMapDto | UploadSignatureMapDto[]` and passes it directly to `transformAndValidateDto`, which validates individual DTO fields but imposes **no limit on the array length**. [1](#0-0) 

**Unbounded concurrent processing** — `validateAndProcessSignatures` in `SignersService`:

```
back-end/apps/api/src/transactions/signers/signers.service.ts, lines 167–198
```

The entire `dto` array is fanned out with `Promise.all(dto.map(...))`. Every element spawns a concurrent async task that performs DB lookups, status validation, and cryptographic signature processing. There is no concurrency cap, no chunk size, and no request-level size guard. [2](#0-1) 

**Nested loops over attacker-controlled `SignatureMap`** — `processTransactionSignatures`:

```
back-end/apps/api/src/transactions/signers/signers.service.ts, lines 234–259
```

For each DTO item, three nested `for...of` loops iterate over `map.values()` (node map) → `nodeMap.values()` (tx map) → `txMap.keys()` (public keys). The attacker controls both the number of DTO items **and** the depth/width of each `SignatureMap`, giving two independent axes of amplification. [3](#0-2) 

**Secondary unbounded loop** — `getTransactionsToSign` in `TransactionsService`:

```
back-end/apps/api/src/transactions/transactions.service.ts, lines 295–309
```

`this.repo.find({ where: whereForUser, ... })` fetches **all** non-terminal transactions with no `take` limit, then iterates over every result calling `userKeysToSign` per transaction. As the transaction table grows, this single GET call performs O(N) async operations with no pagination guard at the query level. [4](#0-3) 

### Impact Explanation

A single crafted POST request with an array of N `UploadSignatureMapDto` items, each carrying a large `SignatureMap`, causes:
- `Promise.all` to spawn N concurrent async tasks simultaneously, saturating the Node.js event loop and the database connection pool.
- Each task executes nested loops over the signature map, consuming CPU proportional to `N × nodes × txIds × publicKeys`.
- The database receives N concurrent `IN(...)` queries in `loadTransactionData`, exhausting connection pool slots.

Result: the API service becomes unresponsive for all other users until the request completes or the process OOMs. Because NestJS runs in a single-process event loop, one such request can block or severely degrade the entire API service.

### Likelihood Explanation

Any registered, verified user (no admin role required) can reach this endpoint — the only guards are `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. [5](#0-4)  Account registration is a normal product workflow. The attacker needs only a valid JWT token and the ability to craft a JSON array body — no special knowledge, no privileged keys.

### Recommendation

1. **Enforce an array size cap at the controller level** using a class-validator `@ArrayMaxSize(N)` decorator on the DTO or an explicit guard before calling `uploadSignatureMaps`. A reasonable limit (e.g., 50–100 items per request) matches realistic multi-signature batch workflows.
2. **Process items in bounded chunks** rather than a single `Promise.all` over the entire array (e.g., `p-limit` or sequential batching).
3. **Validate `SignatureMap` dimensions** (max nodes, max tx IDs, max public keys per map) before entering the nested loops in `processTransactionSignatures`.
4. **Add a `take` limit** to the `repo.find` call in `getTransactionsToSign` so the query is bounded regardless of table size. [6](#0-5) 

### Proof of Concept

**Preconditions:** Attacker has a valid JWT for any registered, verified user account.

**Request:**
```http
POST /transactions/signers HTTP/1.1
Authorization: Bearer <valid_jwt>
Content-Type: application/json

[
  { "id": 1, "signatureMap": { /* large map with many nodes/txIds/keys */ } },
  { "id": 2, "signatureMap": { /* large map */ } },
  ... (repeat 10,000 times with arbitrary transaction IDs)
]
```

**Expected outcome:**
- `validateAndProcessSignatures` calls `Promise.all` over 10,000 concurrent tasks.
- Each task enters the three-level nested loop in `processTransactionSignatures` over the supplied `SignatureMap`.
- The Node.js event loop is saturated; the database connection pool is exhausted.
- All concurrent legitimate API requests time out or receive 503 errors until the server recovers.

No privileged access, no leaked credentials, and no external infrastructure are required — only a single HTTP request from a registered user account.

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L39-41)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class SignersController {
  constructor(private signaturesService: SignersService) {}
```

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L102-112)
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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L234-259)
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
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L295-309)
```typescript
    const transactions = await this.repo.find({
      where: whereForUser,
      relations: ['groupItem'],
      order,
    });

    for (const transaction of transactions) {
      /* Check if the user should sign the transaction */
      try {
        const keysToSign = await this.userKeysToSign(transaction, user);
        if (keysToSign.length > 0) result.push({ transaction, keysToSign });
      } catch (error) {
        console.log(error);
      }
    }
```
