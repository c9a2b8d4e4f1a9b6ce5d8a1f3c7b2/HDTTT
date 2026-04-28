Audit Report

## Title
Concurrent Signature Uploads Overwrite Each Other's Transaction Bytes, Causing Signature Loss

## Summary
`uploadSignatureMaps` in `SignersService` reads `transactionBytes` outside any database transaction, merges new signatures in memory, then writes the result back with a plain `UPDATE` — no optimistic locking, no `SELECT FOR UPDATE`, no version column. When two signers submit signatures for the same transaction concurrently, the second writer's bytes overwrite the first writer's, silently discarding the first signer's cryptographic signatures. The same pattern exists in `importSignatures` in `TransactionsService`.

## Finding Description

**Root cause — read outside DB transaction, blind write**

`loadTransactionData` reads `transactionBytes` using `this.dataSource.manager.find()` — a plain, unguarded read completely outside any database transaction: [1](#0-0) 

`processTransactionSignatures` then deserializes those stale bytes and merges new signatures in memory: [2](#0-1) 

`bulkUpdateTransactions` writes the result back with a plain `UPDATE … WHERE id = ANY(…)` — no `WHERE "transactionBytes" = :expected` guard, no `SELECT FOR UPDATE`, no version column: [3](#0-2) 

The DB-level `this.dataSource.transaction()` wrapping in `persistSignatureChanges` only makes the *write* atomic; the *read* that produced the in-memory bytes already happened outside it, so the transaction provides no protection against the race: [4](#0-3) 

The identical pattern exists in `importSignatures` — read outside any transaction, then a plain `UPDATE` with a `CASE id` expression and no concurrency guard: [5](#0-4) [6](#0-5) 

**Why the `isSameBytes` check does not prevent the overwrite**

`isSameBytes` compares the post-signature bytes to the *stale* bytes that were read at the start of the request: [7](#0-6) 

In the race scenario, Signer B's bytes `B2 = B0 + SB` differ from `B0`, so `isSameBytes` is `false` and the write proceeds — overwriting `B1 = B0 + SA` that Signer A already committed.

**Why `signersByTransaction` deduplication does not prevent the overwrite**

`signersByTransaction` is used only to avoid inserting a duplicate `TransactionSigner` row: [8](#0-7) 

It has no effect on whether `bulkUpdateTransactions` overwrites the bytes column.

**No rate-limiting or serialization on the endpoint**

The `POST` handler carries only JWT and verified-user guards — no throttle, no mutex, no serialization: [9](#0-8) 

## Impact Explanation

- **Silent signature loss**: Signer A's cryptographic signature is dropped from `transactionBytes`. The `TransactionSigner` row for A is still inserted (separate `INSERT`), so the UI shows A as having signed, but the actual bytes no longer carry A's signature — the DB and the bytes are inconsistent.
- **Permanent transaction failure**: Hedera transactions have a fixed valid-start window (default 120 s). If the lost signatures were needed to reach the required threshold and the window closes before the victim re-signs, the transaction expires and cannot be re-executed with the same transaction ID.
- **Deliberate denial-of-signing**: A malicious insider signer can loop `POST /transactions/:id/signers` with their own valid signature map to continuously overwrite the bytes and prevent the transaction from ever accumulating enough signatures before expiry.

## Likelihood Explanation

- Any two verified organization users who are both signers of the same transaction can trigger this by submitting signatures within the same ~100 ms window (typical DB round-trip).
- No special privileges are required — only a valid JWT and membership as a signer.
- In organizations with many required signers (e.g., a 5-of-10 threshold key), concurrent signing is the normal workflow, making accidental collisions likely.
- A malicious insider can deliberately loop the endpoint to prevent threshold accumulation.

## Recommendation

**Option 1 — Optimistic locking (preferred):** Add a `version` column to the `Transaction` entity and use TypeORM's `@VersionColumn`. The `UPDATE` will automatically include `WHERE version = :expected` and fail if another writer has already committed. Retry on conflict.

**Option 2 — Pessimistic locking:** Move the read inside the DB transaction and use `SELECT … FOR UPDATE` (TypeORM `LockModeStyleEnum.PESSIMISTIC_WRITE`) so concurrent requests are serialized at the row level.

**Option 3 — Conditional UPDATE:** Change `bulkUpdateTransactions` to `UPDATE transaction SET "transactionBytes" = $new WHERE id = $id AND "transactionBytes" = $expected`. Detect zero-affected-rows as a conflict and retry by re-reading and re-merging.

Apply the same fix to `importSignatures` in `transactions.service.ts`.

## Proof of Concept

```
1. Create a transaction T requiring signatures from keys KA and KB.
2. Signer A (key KA) and Signer B (key KB) both call
   POST /transactions/T/signers simultaneously.

Timeline:
  A: loadTransactionData  → bytes = B0
  B: loadTransactionData  → bytes = B0   (same stale read)
  A: addSignature(KA)     → B1 = B0 + SA
  B: addSignature(KB)     → B2 = B0 + SB
  A: UPDATE bytes = B1    ✓ committed
  B: UPDATE bytes = B2    ← overwrites B1; SA is gone

3. DB now shows two TransactionSigner rows (A and B both "signed"),
   but transactionBytes only contains SB.
4. If T requires both KA and KB, it can never be submitted to Hedera
   unless A re-signs before the valid-start window expires.
5. A malicious B can loop step 2 to continuously reset the bytes,
   preventing T from ever accumulating enough signatures.
```

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L127-133)
```typescript
  private async loadTransactionData(dto: UploadSignatureMapDto[]) {
    const transactionIds = dto.map(item => item.id);

    // Batch load all transactions
    const transactions = await this.dataSource.manager.find(Transaction, {
      where: { id: In(transactionIds) },
    });
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L223-251)
```typescript
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
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L253-256)
```typescript
          // Only return "new" signers (not already persisted)
          if (!existingSignerIds.has(userKey.id)) {
            userKeys.push(userKey);
          }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L261-264)
```typescript
    // Finally, compare the resulting transaction bytes to see if any signatures were actually added
    const isSameBytes = Buffer.from(sdkTransaction.toBytes()).equals(
      transaction.transactionBytes
    );
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L315-321)
```typescript
    // Execute in single transaction
    try {
      await this.dataSource.transaction(async manager => {
        // Bulk update transactions
        if (transactionsToUpdate.length > 0) {
          await this.bulkUpdateTransactions(manager, transactionsToUpdate);
        }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L365-371)
```typescript
    await manager.query(
      `UPDATE transaction
     SET "transactionBytes" = CASE id ${whenClauses} END,
         "updatedAt" = NOW()
     WHERE id = ANY($${bytes.length + 1})`,
      [...bytes, ids]
    );
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L507-510)
```typescript
    const transactions = await this.entityManager.find(Transaction, {
      where: { id: In(ids) },
      relations: ['creatorKey', 'approvers', 'signers', 'observers'],
    });
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
