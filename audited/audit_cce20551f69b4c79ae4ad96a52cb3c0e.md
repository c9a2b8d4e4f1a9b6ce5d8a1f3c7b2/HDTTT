### Title
Duplicate `TransactionSigner` Records Inserted via Repeated Transaction ID in Batch `uploadSignatureMaps` Request

### Summary
The `uploadSignatureMaps` function in `signers.service.ts` processes a caller-supplied batch of `UploadSignatureMapDto` items using `Promise.all` without first deduplicating transaction IDs. When the same transaction ID appears more than once in the request body, the in-memory `existingSignerIds` set (loaded once before processing begins) does not reflect in-flight insertions, so both parallel tasks independently conclude the user key is "new" and both push identical rows to `signersToInsert`. Because the `transaction_signer` table carries no unique constraint on `(transactionId, userKeyId)`, the subsequent bulk insert succeeds and persists duplicate signer records, corrupting the signing-state accounting.

### Finding Description

**Root cause — no deduplication before parallel processing**

`loadTransactionData` builds `signersByTransaction` from a single pre-flight DB read: [1](#0-0) 

`validateAndProcessSignatures` then fans out over every element of `dto` concurrently: [2](#0-1) 

If `dto` is `[{id: 1, signatureMap: …}, {id: 1, signatureMap: …}]`, both tasks receive the **same** `transaction` object and the **same** `existingSignerIds` set (which does not yet contain the user's key). Both therefore pass the guard: [3](#0-2) 

Both return identical `userKeys` arrays.

**Duplicate rows accumulate in `signersToInsert`**

`persistSignatureChanges` iterates over all results without deduplication: [4](#0-3) 

**No unique constraint prevents the insert**

`bulkInsertSigners` performs a plain bulk insert with no `ON CONFLICT` clause: [5](#0-4) 

The `TransactionSigner` entity declares only a non-unique index on `(transactionId, userKeyId)`: [6](#0-5) 

The migration confirms no `UNIQUE` constraint exists on the table: [7](#0-6) 

**Entry point is publicly reachable**

The controller accepts an array body from any authenticated user: [8](#0-7) 

### Impact Explanation
Duplicate `TransactionSigner` rows corrupt the signer-accounting state for the affected transaction. `getSignaturesByTransactionId` and `getSignaturesByUser` return inflated, duplicate entries. The `signersByTransaction` snapshot used in subsequent `uploadSignatureMaps` calls will contain the `userKeyId` (preventing further duplicates), but the already-inserted duplicates are permanent — there is no cleanup path. This constitutes an unauthorized, persistent corruption of the project's signing-state records.

### Likelihood Explanation
Any authenticated user who holds a valid key for a transaction can trigger this with a single crafted POST request. No elevated privileges, leaked credentials, or race conditions are required. The batch endpoint is a documented, normal product flow (`UploadSignatureMapDto[]`), and no server-side validation rejects repeated IDs in the array.

### Recommendation
1. **Deduplicate `dto` by `id` before processing** in `loadTransactionData` or at the top of `uploadSignatureMaps`.
2. **Add a unique constraint** on `(transactionId, userKeyId)` in the `transaction_signer` table.
3. **Use conflict-safe insertion** in `bulkInsertSigners` (e.g., `.orIgnore()` or `ON CONFLICT DO NOTHING`) as a defence-in-depth measure.

### Proof of Concept

```
POST /transactions/signers
Authorization: Bearer <valid_jwt>
Content-Type: application/json

[
  { "id": 42, "signatureMap": { <valid_sig_map_for_tx_42> } },
  { "id": 42, "signatureMap": { <valid_sig_map_for_tx_42> } }
]
```

**Expected (correct) result**: one `TransactionSigner` row for `(userId, transactionId=42, userKeyId)`.

**Actual result**: two identical `TransactionSigner` rows are inserted for `(userId, transactionId=42, userKeyId)`, permanently inflating the signer count and corrupting the signing-state accounting for transaction 42.

### Citations

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L253-256)
```typescript
          // Only return "new" signers (not already persisted)
          if (!existingSignerIds.has(userKey.id)) {
            userKeys.push(userKey);
          }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L302-309)
```typescript
      if (userKeys.length > 0) {
        const newSigners = userKeys.map(userKey => ({
          userId: user.id,
          transactionId: id,
          userKeyId: userKey.id,
        }));
        signersToInsert.push(...newSigners);
      }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L406-419)
```typescript
  private async bulkInsertSigners(
    manager: any,
    signersToInsert: any[],
  ) {
    const result = await manager
      .createQueryBuilder()
      .insert()
      .into(TransactionSigner)
      .values(signersToInsert)
      .returning('*')
      .execute();

    return result.raw;
  }
```

**File:** back-end/libs/common/src/database/entities/transaction-signer.entity.ts (L14-16)
```typescript
@Entity()
@Index(['transactionId', 'userKeyId'])
export class TransactionSigner {
```

**File:** back-end/typeorm/migrations/1764999592722-InitialSchema.ts (L12-12)
```typescript
        await queryRunner.query(`CREATE TABLE IF NOT EXISTS "transaction_signer" ("id" SERIAL NOT NULL, "transactionId" integer NOT NULL, "userKeyId" integer NOT NULL, "userId" integer NOT NULL, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_e7d778a4903a0946bda00650cf5" PRIMARY KEY ("id"))`);
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
