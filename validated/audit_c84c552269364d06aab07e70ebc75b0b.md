### Title
Concurrent Signature Uploads Overwrite Each Other's Transaction Bytes, Causing Signature Loss

### Summary

The `uploadSignatureMaps` function in `SignersService` reads transaction bytes, merges new signatures in memory, then writes the result back with a blind `UPDATE` — no optimistic locking or row-level locking. When two authenticated signers submit signatures for the same transaction concurrently, the second writer's bytes overwrite the first writer's, silently discarding the first signer's signatures. In a multi-signer organization workflow this can prevent a transaction from ever accumulating enough signatures before its valid-start window expires, causing permanent transaction failure.

### Finding Description

**Root cause — no optimistic locking in `bulkUpdateTransactions`**

`loadTransactionData` reads the current `transactionBytes` for a set of transaction IDs: [1](#0-0) 

`processTransactionSignatures` then calls `sdkTransaction.addSignature(publicKey, map)` on the in-memory copy of those bytes: [2](#0-1) 

Finally, `bulkUpdateTransactions` writes the result back with a plain `UPDATE` — no `WHERE "transactionBytes" = :expected` guard, no `SELECT FOR UPDATE`, no version column: [3](#0-2) 

The same pattern exists in `importSignatures` in `transactions.service.ts`: [4](#0-3) 

**Race window**

```
Signer A                          Signer B
─────────────────────────────────────────────────────
loadTransactionData → bytes = B0
                                  loadTransactionData → bytes = B0
addSignature(SA) → B1 = B0+SA
                                  addSignature(SB) → B2 = B0+SB
UPDATE bytes = B1  ✓
                                  UPDATE bytes = B2  ← overwrites B1
                                                        SA is gone
```

The `signersByTransaction` deduplication only prevents inserting a duplicate `TransactionSigner` row; it does **not** prevent the bytes overwrite. [5](#0-4) 

The public endpoint that triggers this path has no rate-limiting or serialization: [6](#0-5) 

### Impact Explanation

- **Signature loss**: Signer A's signatures are silently dropped from `transactionBytes`. The `TransactionSigner` row for A is still inserted (it is written in a separate `INSERT`), so the UI shows A as having signed, but the actual bytes no longer carry A's cryptographic signature.
- **Permanent transaction failure**: Hedera transactions have a fixed valid-start window (default 120 s, configurable). If the lost signatures were the ones needed to reach the required threshold, and the window closes before the victim re-signs, the transaction expires and cannot be re-executed with the same transaction ID. The organization must create a brand-new transaction.
- **Silent integrity break**: The `TransactionSigner` table and `transactionBytes` become inconsistent — the DB says N signers have signed, but the bytes only contain a subset of their signatures.

### Likelihood Explanation

- Any two verified organization users who are both signers of the same transaction can trigger this by submitting signatures within the same ~100 ms window (typical DB round-trip).
- No special privileges are required — only a valid JWT and membership as a signer.
- In organizations with many required signers (e.g., a 5-of-10 threshold key), concurrent signing is the normal workflow, making accidental collisions likely.
- A malicious insider signer can deliberately loop `POST /transactions/:id/signers` with their own valid signature map to continuously overwrite the bytes and prevent the transaction from accumulating enough signatures before expiry.

### Recommendation

Apply optimistic locking on the `transactionBytes` column. The simplest approach is to add a `version` integer column to `Transaction` and include it in the `WHERE` clause of every bytes update:

```sql
UPDATE transaction
SET "transactionBytes" = :newBytes,
    "version"          = "version" + 1,
    "updatedAt"        = NOW()
WHERE id      = :id
  AND "version" = :expectedVersion
```

If `affected = 0`, re-read the row, re-apply the signature to the fresh bytes, and retry (up to N times). Alternatively, use `SELECT ... FOR UPDATE` inside the existing `dataSource.transaction()` block

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L354-372)
```typescript
  private async bulkUpdateTransactions(
    manager: any,
    transactionsToUpdate: { id: number; transactionBytes: Buffer }[]
  ) {
    const whenClauses = transactionsToUpdate
      .map((t, index) => `WHEN ${t.id} THEN $${index + 1}::bytea`)
      .join(' ');

    const ids = transactionsToUpdate.map(t => t.id);
    const bytes = transactionsToUpdate.map(t => t.transactionBytes);

    await manager.query(
      `UPDATE transaction
     SET "transactionBytes" = CASE id ${whenClauses} END,
         "updatedAt" = NOW()
     WHERE id = ANY($${bytes.length + 1})`,
      [...bytes, ids]
    );
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L594-601)
```typescript
        try {
          await this.entityManager
            .createQueryBuilder()
            .update(Transaction)
            .set({ transactionBytes: () => caseSQL })
            .where('id IN (:...ids)', { ids: batch.map(u => u.id) })
            .setParameters(params)
            .execute();
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
