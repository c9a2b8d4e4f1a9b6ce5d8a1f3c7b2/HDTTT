### Title
Lost-Update Race Condition in `uploadSignatureMaps` Allows Silent Signature Erasure from Transaction Bytes

### Summary
`SignersService.uploadSignatureMaps` reads transaction bytes from the database, merges new signatures in memory, then writes the result back with an unconditional SQL `UPDATE` — no optimistic locking and no row-level lock held across the read-modify-write cycle. Two concurrent calls for the same transaction ID will each read the same original bytes, independently merge their signatures, and the last writer silently overwrites the first writer's merged bytes. The `transaction_signer` insert records for the first writer still succeed, creating a permanent inconsistency: the signer table claims a key signed, but the stored `transactionBytes` blob does not contain that key's signature. When the chain service later attempts execution it checks `sdkTransaction._signerPublicKeys` against the required key list and throws `Transaction has invalid signature`, permanently blocking execution of a time-bounded transaction.

### Finding Description

**Root cause — read outside the write transaction, unconditional overwrite:**

`loadTransactionData` fetches `transactionBytes` and existing signers with a plain `find` call, outside any database transaction and without a pessimistic lock. [1](#0-0) 

`validateAndProcessSignatures` then merges the caller's signatures into the in-memory `sdkTransaction` object derived from those bytes. [2](#0-1) 

`persistSignatureChanges` wraps only the write operations in a DB transaction, but the read already happened outside it. The final SQL update is unconditional — it overwrites whatever bytes are currently in the row: [3](#0-2) 

There is no `WHERE "updatedAt" = :previousUpdatedAt` or equivalent optimistic-locking guard, and no `SELECT ... FOR UPDATE` held from the read through the write.

**Exploit flow:**

1. Transaction T exists with `transactionBytes = B0` (no signatures). Two signers, User A and User B, are both valid signers.
2. User A calls `POST /transactions/T/signers` → `loadTransactionData` reads `B0`.
3. User B calls `POST /transactions/T/signers` concurrently → `loadTransactionData` also reads `B0`.
4. User A merges signature_A into `B0` → `B1 = B0 + sig_A`. User A's DB transaction commits, writing `B1`.
5. User B merges signature_B into `B0` → `B2 = B0 + sig_B` (User B never saw `B1`). User B's DB transaction commits, writing `B2` — **overwriting `B1`**.
6. `transaction_signer` now has rows for both User A and User B (the INSERT is a separate operation that does not conflict).
7. `transactionBytes` in the DB is `B2`, which contains only `sig_B`. `sig_A` is permanently gone.
8. `processTransactionStatus` may advance the transaction to `WAITING_FOR_EXECUTION` based on signer-record counts.
9. `ExecuteService.getValidatedSDKTransaction` reconstructs the SDK transaction from `transactionBytes` (`B2`) and calls `hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey)`. Because `sig_A` is absent, the check fails and throws `Transaction has invalid signature`. [4](#0-3) 

The transaction has a fixed `validStart` and will expire, making the loss permanent.

The same pattern exists in `importSignatures` in `transactions.service.ts`, which also reads bytes, merges signatures in memory, and writes back with an unconditional `UPDATE ... WHERE id IN (...)` — no status guard in the WHERE clause and no optimistic lock. [5](#0-4) 

### Impact Explanation
A malicious co-signer (or a network-level attacker who can replay/delay HTTP responses) can permanently erase another signer's signature bytes from a transaction while leaving a false `transaction_signer` record. The transaction will be marked as having sufficient signers but will fail at execution time with an invalid-signature error. Because Hedera transactions are time-bounded by `validStart`, the window to re-upload the lost signature may close before the inconsistency is detected, permanently blocking execution of the transaction. In an organizational multi-sig workflow this constitutes a targeted denial-of-execution attack against any transaction the attacker is a valid signer for.

### Likelihood Explanation
Any authenticated user who holds a registered key for a transaction can reach `POST /transactions/:id/signers` without elevated privilege. In a realistic multi-user organization, multiple signers uploading signatures in close succession (e.g., triggered by the same notification) will naturally race. A deliberate attacker needs only to send their own signature upload request timed to land after a victim's request has been read but before it has been written — a window that spans the entire async signature-processing phase, which includes CPU-bound signature verification and multiple awaited DB queries.

### Recommendation
Apply a pessimistic row-level lock (`SELECT ... FOR UPDATE`) on the `transaction` row at the start of `loadTransactionData`, held inside a single encompassing database transaction that also contains the write. Alternatively, use optimistic locking: record `updatedAt` at read time and add `AND "updatedAt" = :readAt` to the UPDATE WHERE clause, retrying on conflict. The same fix must be applied to `importSignatures` in `transactions.service.ts`. The pattern used correctly in `ExecuteService._executeTransaction` — `WHERE id = :id AND status = :currentStatus` with a check on `updateResult.raw.length === 0` — is the right model to follow. [6](#0-5) 

### Proof of Concept

**Setup:** Transaction T in status `WAITING_FOR_SIGNATURES`, requiring signatures from key_A and key_B. Both users are authenticated and have their keys registered.

**Steps:**

1. User A sends `POST /transactions/T/signers` with `signatureMap` containing `sig_A`.
2. Before User A's request completes its async processing (after `loadTransactionData` returns but before `persistSignatureChanges` commits), User B sends `POST /transactions/T/signers` with `signatureMap` containing `sig_B`.
3. Both requests complete with HTTP 201.
4. Query `SELECT "transactionBytes" FROM transaction WHERE id = T` — deserialize with `SDKTransaction.fromBytes()` and inspect `_signerPublicKeys`. Only one key is present (whichever user's write landed last).
5. Query `SELECT * FROM transaction_signer WHERE "transactionId" = T` — two rows exist, one for each user.
6. Observe the inconsistency: signer table has two entries; bytes have only one signature.
7. When the chain service attempts execution, `hasValidSignatureKey` fails and the transaction is never submitted to Hedera. [7](#0-6)

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L217-266)
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

**File:** back-end/libs/common/src/execute/execute.service.ts (L204-223)
```typescript
  private async getValidatedSDKTransaction(
    transaction: Transaction,
  ): Promise<SDKTransaction> {
    /* Throws an error if the transaction is not found or in incorrect state */
    if (!transaction) throw new Error('Transaction not found');

    await this.validateTransactionStatus(transaction);

    /* Gets the SDK transaction from the transaction body */
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    /* Gets the signature key */
    const signatureKey = await this.transactionSignatureService.computeSignatureKey(transaction);

    /* Checks if the transaction has valid signatureKey */
    if (!hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey))
      throw new Error('Transaction has invalid signature.');

    return sdkTransaction;
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L580-601)
```typescript
    if (updateArray.length > 0) {
      for (let i = 0; i < updateArray.length; i += BATCH_SIZE) {
        const batch = updateArray.slice(i, i + BATCH_SIZE);

        let caseSQL = 'CASE id ';
        const params: any = {};

        batch.forEach((update, idx) => {
          caseSQL += `WHEN :id${idx} THEN :bytes${idx}::bytea `;
          params[`id${idx}`] = update.id;
          params[`bytes${idx}`] = update.transactionBytes;
        });
        caseSQL += 'END';

        try {
          await this.entityManager
            .createQueryBuilder()
            .update(Transaction)
            .set({ transactionBytes: () => caseSQL })
            .where('id IN (:...ids)', { ids: batch.map(u => u.id) })
            .setParameters(params)
            .execute();
```
