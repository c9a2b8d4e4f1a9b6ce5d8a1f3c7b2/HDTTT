### Title
Concurrent Signature Uploads Cause Silent Signature Loss via Blind `transactionBytes` Overwrite (TOCTOU Race Condition)

### Summary
`SignersService.uploadSignatureMaps` reads `transactionBytes` from the database, adds signatures in memory, then writes the result back with an unconditional `UPDATE` that has no optimistic-locking guard on `transactionBytes`. When two signers upload concurrently, the last writer silently overwrites the first writer's signature, leaving the stored bytes in a state that does not match the `TransactionSigner` records and can permanently prevent the transaction from advancing to `WAITING_FOR_EXECUTION`.

### Finding Description

The flow in `uploadSignatureMaps` is:

**Step 1 — Read** (`loadTransactionData`): both concurrent requests load the same snapshot of `transactionBytes` from the database. [1](#0-0) 

**Step 2 — Mutate in memory** (`processTransactionSignatures`): each request independently deserialises the bytes and calls `addSignature`, producing a new byte blob that contains only its own signer's key. [2](#0-1) 

**Step 3 — Blind overwrite** (`bulkUpdateTransactions`): the resulting bytes are written back with a plain `UPDATE … SET "transactionBytes" = CASE id WHEN … END WHERE id = ANY(…)`. There is no `WHERE "transactionBytes" = <expected_value>` guard and no distributed lock. [3](#0-2) 

Race window:

```
T0  Request-A reads bytes_0
T0  Request-B reads bytes_0
T1  Request-A adds sig_A  → bytes_A  (sig_A only)
T1  Request-B adds sig_B  → bytes_B  (sig_B only)
T2  Request-A writes bytes_A to DB
T3  Request-B writes bytes_B to DB   ← overwrites sig_A silently
```

Final DB state: `transactionBytes` contains only `sig_B`. The `TransactionSigner` row for User A exists (inserted inside the DB transaction), but User A's cryptographic signature is absent from the stored bytes.

Contrast this with the status-update path, which correctly uses an optimistic-lock `WHERE status = :oldStatus` guard: [4](#0-3) 

And the execution path, which uses `WHERE id = :id AND status = :currentStatus`: [5](#0-4) 

No equivalent guard exists for `transactionBytes`.

### Impact Explanation

`processTransactionStatus` determines whether a transaction can advance by calling `hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey)`, which inspects the actual bytes stored in the database, not the `TransactionSigner` table. [6](#0-5) 

After the overwrite, the bytes no longer contain the lost signer's key. Even though the `TransactionSigner` record shows the user signed, the scheduler will never promote the transaction to `WAITING_FOR_EXECUTION` because the cryptographic threshold is not met in the bytes. The transaction is permanently stuck unless the affected signer re-uploads — and even then, the same race can recur.

A malicious co-signer can deliberately time their upload to race with a target signer, repeatedly nullifying that signer's contribution and blocking execution indefinitely.

### Likelihood Explanation

Multi-user concurrent signing is the primary design goal of the organization workflow. The system explicitly supports multiple signers and the API accepts batch signature maps. Two users signing the same transaction at nearly the same time is a routine, expected event — not an edge case. No distributed lock (such as the `@MurLock` used in `executeTransactionGroup`) protects this path. [7](#0-6) 

### Recommendation

Replace the blind `UPDATE` with an optimistic-locking update that appends signatures rather than replacing bytes, or use a row-level advisory lock / `SELECT … FOR UPDATE` inside the database transaction so that concurrent requests serialise on the same row. A minimal fix is to re-read `transactionBytes` inside the database transaction with `SELECT … FOR UPDATE`, merge the new signatures onto the freshly-locked bytes, and then write the merged result.

### Proof of Concept

1. Create a transaction requiring two signers (User A and User B).
2. Both users call `POST /transactions/:id/signers` simultaneously with their respective signature maps.
3. Observe that only one signer's signature appears in the stored `transactionBytes` (query the `transaction` table directly).
4. Observe that both `TransactionSigner` rows exist, creating a permanent inconsistency.
5. Confirm the scheduler's `processTransactionStatus` never advances the transaction to `WAITING_FOR_EXECUTION` because `hasValidSignatureKey` fails on the incomplete bytes. [8](#0-7)

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L127-133)
```typescript
  private async loadTransactionData(dto: UploadSignatureMapDto[]) {
    const transactionIds = dto.map(item => item.id);

    // Batch load all transactions
    const transactions = await this.dataSource.manager.find(Transaction, {
      where: { id: In(transactionIds) },
    });
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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L132-146)
```typescript
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
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L159-166)
```typescript
      Array.from(updatesByStatus.values()).map(async ({ newStatus, oldStatus, ids }) => {
        const result = await transactionRepo
          .createQueryBuilder()
          .update(Transaction)
          .set({ status: newStatus })
          .where('id IN (:...ids) AND status = :oldStatus', { ids, oldStatus })
          .returning('id')
          .execute();
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L62-63)
```typescript
  @MurLock(15000, 'transactionGroup.id + "_group"')
  async executeTransactionGroup(transactionGroup: TransactionGroup) {
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L187-198)
```typescript
    const updateResult = await this.transactionsRepo
      .createQueryBuilder()
      .update(Transaction)
      .set({ status: transactionStatus, executedAt, statusCode: transactionStatusCode })
      .where('id = :id AND status = :currentStatus', {
        id: transaction.id,
        currentStatus: TransactionStatus.WAITING_FOR_EXECUTION,
      })
      .returning('id')
      .execute();

    if (updateResult.raw.length === 0) return null;
```
