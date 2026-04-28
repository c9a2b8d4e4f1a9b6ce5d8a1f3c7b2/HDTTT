Let me explore the repository structure and relevant files to assess this.

### Title
Unbounded Array Input in Signature Import Endpoints Enables Authenticated DoS via Resource Exhaustion

### Summary
Two authenticated API endpoints accept an array of `UploadSignatureMapDto` objects with no enforced upper bound on array length. Each element triggers cryptographic signature validation, SDK transaction deserialization, and database operations. A malicious authenticated user can submit a single crafted request with thousands of entries, causing excessive CPU, memory, and database resource consumption — a direct analog to the CometBFT `LastCommit round` DoS where an attacker-controlled numeric value drives unbounded allocation.

### Finding Description

**Affected endpoints:**

1. `POST /transactions/signatures/import` — `TransactionsController.importSignatures`
2. `POST /transactions/:transactionId?/signers` — `SignersController.uploadSignatureMap`

Both accept `UploadSignatureMapDto | UploadSignatureMapDto[]` with no array-length cap.

**Root cause — endpoint 1:** [1](#0-0) 

The body is passed directly to `importSignatures` after per-element DTO validation. No count limit is applied before or after `transformAndValidateDto`.

Inside `importSignatures`, for every element in the array the service:
1. Loads all referenced transactions from the DB in one `IN` query (unbounded `ids` list)
2. Deserializes each transaction with `SDKTransaction.fromBytes` (memory + CPU)
3. Runs `validateSignature` (cryptographic ECDSA/ED25519 verification)
4. Calls `sdkTransaction.addSignature` and `sdkTransaction.toBytes` (memory)
5. Builds a SQL `CASE` expression proportional to the batch size [2](#0-1) 

The developer explicitly acknowledged the missing limit with the comment on line 575: [3](#0-2) 

**Root cause — endpoint 2:** [4](#0-3) 

Same pattern: `body` is an unbounded array, `transformAndValidateDto` validates each element's schema but does not limit count, and the full array is forwarded to `uploadSignatureMaps`.

**Contrast with pagination (which IS bounded):** [5](#0-4) 

Pagination enforces `size ≤ 100`. The signature import endpoints have no equivalent guard.

### Impact Explanation

A single HTTP POST with N entries causes O(N) cryptographic verifications, O(N) SDK deserializations, and an `IN (id1, id2, ..., idN)` database query. At N = 10,000 entries (each entry is small — an integer ID plus a compact signature map — easily fitting within a multi-MB body), the API worker process exhausts CPU and heap memory. Because NestJS runs in a single Node.js event loop per worker, one such request blocks all other requests on that worker until completion or OOM crash. Repeated requests across workers can take the entire API service offline, preventing all organization users from signing or submitting transactions.

### Likelihood Explanation

Any registered, verified user can reach these endpoints — no admin or privileged role is required. The attacker profile is "malicious normal user abusing valid product flows," which is explicitly in scope per `RESEARCHER.md`. The exploit requires only a crafted HTTP POST body, achievable with `curl` or any HTTP client. No leaked credentials, no physical access, and no external oracle manipulation are needed.

### Recommendation

Enforce a hard upper bound on the accepted array length at the controller layer, before any processing occurs. For example:

```typescript
// In both controllers, immediately after receiving body:
const items = Array.isArray(body) ? body : [body];
if (items.length > 50) {
  throw new BadRequestException('Too many items in a single request');
}
```

The limit value (e.g., 50–100) should be chosen based on expected legitimate batch sizes. Additionally, consider adding per-user rate limiting on these endpoints using the existing throttler infrastructure already present in the project.



### Proof of Concept

```bash
# Generate a payload with 5000 entries (each referencing transaction id=1)
python3 -c "
import json
entry = {'id': 1, 'signatureMap': {'0.0.3': {'0.0.1@1700000000.000000000': {'302a300506032b6570032100' + 'aa'*32: '00'*64}}}}
print(json.dumps([entry] * 5000))
" > payload.json

# Send as authenticated user (replace TOKEN and HOST)
curl -X POST https://<HOST>/transactions/signatures/import \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d @payload.json
```

**Expected outcome:** The API worker spends seconds-to-minutes deserializing 5,000 SDK transactions and running 5,000 cryptographic verifications. During this time, the event loop is saturated and all other requests on that worker are stalled. Repeating across concurrent connections exhausts all workers, rendering the API unavailable to legitimate users.

### Citations

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L504-576)
```typescript
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

    //Added a batch mechanism, probably should limit this on the api side of things
    const BATCH_SIZE = 500;
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

**File:** back-end/libs/common/src/decorators/pagination-params.decorator.ts (L22-24)
```typescript
  if (size > 100) {
    throw new BadRequestException(ErrorCodes.IPP);
  }
```
