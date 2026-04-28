### Title
Lost-Update Race Condition in `uploadSignatureMaps` Allows Concurrent Signature Uploads to Silently Overwrite Each Other's `transactionBytes`

### Summary
`uploadSignatureMaps` in `signers.service.ts` follows a read-modify-write pattern with no optimistic locking or status guard on the final write. Two concurrent signature uploads for the same transaction both read the same base `transactionBytes` snapshot, independently add their own signatures, and the second write unconditionally overwrites the first. The first signer's signatures are silently lost from the database, mirroring the external report's race condition where one actor's action causes another's to fail.

### Finding Description

The flow in `uploadSignatureMaps` is split across three private methods with no atomic protection spanning them:

**Step 1 — Snapshot load** (`loadTransactionData`, lines 131–133): All transactions are fetched into an in-memory `Map` once. [1](#0-0) 

**Step 2 — Status check on stale snapshot** (`validateTransactionStatus`, lines 201–215): The status check is performed against the in-memory object loaded in Step 1, not a fresh DB read. [2](#0-1) 

**Step 3 — Signature merge** (`processTransactionSignatures`, lines 223–266): New signatures are added to the in-memory `sdkTransaction` built from the snapshot bytes. [3](#0-2) 

**Step 4 — Unconditional overwrite** (`bulkUpdateTransactions`, lines 354–372): The merged bytes are written back with a raw SQL `UPDATE` that has **no status guard and no version/timestamp condition**:

```sql
UPDATE transaction
SET "transactionBytes" = CASE id WHEN {id} THEN $1::bytea END,
    "updatedAt" = NOW()
WHERE id = ANY($N)
``` [4](#0-3) 

**Race window**: Between Step 1 and Step 4, any concurrent call that completes Step 4 first will have its bytes silently overwritten. Because both callers start from the same snapshot, the winner's bytes do not include the loser's signatures.

The identical TOCTOU exists in `importSignatures` in `transactions.service.ts` (lines 507–601), where the status check is on a stale snapshot and the final `UPDATE` has no status or version guard: [5](#0-4) 

### Impact Explanation

In a multi-signer organization, Signer A and Signer B both upload signatures for the same transaction concurrently. Both load identical base bytes. Both add their own signature to the in-memory copy. The second write wins; the first signer's signature is gone from `transactionBytes`. The `TransactionSigner` row is inserted for both (separate INSERT path), so the system believes both have signed, but the actual bytes only carry one signature. `processTransactionStatus` evaluates the bytes and may never promote the transaction to `WAITING_FOR_EXECUTION`, permanently stalling it. [6](#0-5) 

A malicious signer who is a legitimate participant can deliberately trigger this by submitting rapid concurrent `POST /transactions/:id/signers` requests timed to race with another signer's upload, causing the victim's signatures to be silently dropped and the transaction to stall indefinitely.

### Likelihood Explanation

- **Attacker preconditions**: Must be a registered signer on the target transaction — no privileged access required.
- **Trigger**: Two concurrent HTTP requests to `POST /transactions/:transactionId/signers`. This is trivially achievable from a script.
- **Detection difficulty**: The API returns HTTP 201 with a signer record for both callers. Neither caller receives an error. The signature loss is invisible at the API layer.
- **Natural occurrence**: Even without a malicious actor, high-concurrency environments (multiple signers in different time zones clicking "Sign" simultaneously) can trigger this organically.

### Recommendation

Add optimistic locking to `bulkUpdateTransactions`. The simplest fix is to include an `updatedAt` guard in the WHERE clause and reject the update if the row was modified since the snapshot was taken:

```sql
UPDATE transaction
SET "transactionBytes" = CASE id ... END,
    "updatedAt" = NOW()
WHERE id = ANY($N)
  AND "updatedAt" = $snapshot_updated_at   -- optimistic lock
  AND status IN ('WAITING FOR SIGNATURES', 'WAITING FOR EXECUTION')
```

If the update affects 0 rows, retry by re-reading the latest bytes, re-merging signatures, and re-attempting the write. Apply the same fix to `importSignatures` in `transactions.service.ts`.

Alternatively, use `SELECT ... FOR UPDATE` inside the existing `dataSource.transaction(...)` block to serialize concurrent writes at the DB level. [7](#0-6) 

### Proof of Concept

1. Create a transaction `T` requiring signatures from Signer A and Signer B (e.g., a 2-of-2 threshold key).
2. Both signers sign the SDK transaction bytes locally.
3. Signer A and Signer B simultaneously send `POST /transactions/T/signers` with their respective `signatureMap` payloads.
4. Both requests pass `validateTransactionStatus` (status is `WAITING_FOR_SIGNATURES` in both snapshots).
5. Both build new bytes: Signer A's copy has only A's signature; Signer B's copy has only B's signature.
6. Both execute `bulkUpdateTransactions`. The second write wins.
7. Inspect `transactionBytes` in the DB: only one signer's signature is present.
8. `processTransactionStatus` evaluates the bytes, finds the threshold is not met, and the transaction remains in `WAITING_FOR_SIGNATURES` indefinitely — it can never be promoted to `WAITING_FOR_EXECUTION`.
9. Both `TransactionSigner` rows exist in the DB, so the UI shows both signers as having signed, masking the corruption. [8](#0-7)

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L99-124)
```typescript
  async uploadSignatureMaps(
    dto: UploadSignatureMapDto[],
    user: User,
  ): Promise<{ signers: TransactionSigner[]; notificationReceiverIds: number[] }> {
    // Load all necessary data
    const { transactionMap, signersByTransaction } = await this.loadTransactionData(dto);

    // Validate and process signatures
    const validationResults = await this.validateAndProcessSignatures(
      dto,
      user,
      transactionMap,
      signersByTransaction
    );

    // Persist changes to database
    const { transactionsToProcess, signers, notificationsToDismiss } = await this.persistSignatureChanges(validationResults, user);

    // Update transaction statuses and emit notifications
    await this.updateStatusesAndNotify(transactionsToProcess);

    return {
      signers: Array.from(signers),
      notificationReceiverIds: notificationsToDismiss,
    };
  }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L131-133)
```typescript
    const transactions = await this.dataSource.manager.find(Transaction, {
      where: { id: In(transactionIds) },
    });
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L201-215)
```typescript
  private validateTransactionStatus(transaction: Transaction): string | null {
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    ) {
      return ErrorCodes.TNRS;
    }

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    if (isExpired(sdkTransaction)) {
      return ErrorCodes.TE;
    }

    return null;
  }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L223-266)
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
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L315-341)
```typescript
    // Execute in single transaction
    try {
      await this.dataSource.transaction(async manager => {
        // Bulk update transactions
        if (transactionsToUpdate.length > 0) {
          await this.bulkUpdateTransactions(manager, transactionsToUpdate);
        }

        // Bulk update notifications
        if (notificationsToUpdate.length > 0) {
          const updatedNotificationReceivers = await this.bulkUpdateNotificationReceivers(manager, notificationsToUpdate);

          // To maintain backwards compatibility and multi-machine support, we send off a dismiss event.
          emitDismissedNotifications(
            this.notificationsPublisher,
            updatedNotificationReceivers,
          );

          notificationsToDismiss = updatedNotificationReceivers.map(nr => nr.id);
        }

        // Bulk insert signers
        if (signersToInsert.length > 0) {
          const results = await this.bulkInsertSigners(manager, signersToInsert);
          results.forEach(signer => signers.add(signer));
        }
      });
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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L118-175)
```typescript
export async function processTransactionStatus(
  transactionRepo: Repository<Transaction>,
  transactionSignatureService: TransactionSignatureService,
  transactions: Transaction[],
): Promise<Map<number, TransactionStatus>> {
  const statusChanges = new Map<number, TransactionStatus>();

  // Group intended updates by [newStatus, oldStatus] so we can bulk update
  // only rows that still have the expected current status
  const updatesByStatus = new Map<string, { newStatus: TransactionStatus, oldStatus: TransactionStatus, ids: number[] }>();

  for (const transaction of transactions) {
    if (!transaction) continue;

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    const signatureKey = await transactionSignatureService.computeSignatureKey(transaction);
    const isAbleToSign = hasValidSignatureKey(
      [...sdkTransaction._signerPublicKeys],
      signatureKey
    );

    let newStatus = TransactionStatus.WAITING_FOR_SIGNATURES;

    if (isAbleToSign) {
      const collatedTx = await smartCollate(transaction, signatureKey);
      if (collatedTx !== null) {
        newStatus = TransactionStatus.WAITING_FOR_EXECUTION;
      }
    }

    if (transaction.status !== newStatus) {
      const key = `${transaction.status}->${newStatus}`;
      if (!updatesByStatus.has(key)) {
        updatesByStatus.set(key, { newStatus, oldStatus: transaction.status, ids: [] });
      }
      updatesByStatus.get(key)!.ids.push(transaction.id);
    }
  }

  if (updatesByStatus.size > 0) {
    await Promise.all(
      Array.from(updatesByStatus.values()).map(async ({ newStatus, oldStatus, ids }) => {
        const result = await transactionRepo
          .createQueryBuilder()
          .update(Transaction)
          .set({ status: newStatus })
          .where('id IN (:...ids) AND status = :oldStatus', { ids, oldStatus })
          .returning('id')
          .execute();

        for (const row of result.raw) {
          statusChanges.set(row.id, newStatus);
        }
      })
    );
  }

  return statusChanges;
```
