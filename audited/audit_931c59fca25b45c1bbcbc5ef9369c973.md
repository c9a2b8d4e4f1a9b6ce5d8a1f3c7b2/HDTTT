### Title
Concurrent Signature Upload Race Condition Causes Silent Signature Loss in `uploadSignatureMaps`

### Summary

The `uploadSignatureMaps` function in `SignersService` performs a read-modify-write on `transaction.transactionBytes` without any row-level lock or optimistic concurrency control. When two or more organization members submit signatures for the same transaction concurrently, each request reads the same stale bytes, independently adds its own signatures in memory, then blindly overwrites the database row. The last writer wins and silently discards all signatures written by earlier concurrent requests.

This is the direct analog of the IN3-server race condition: multiple actors independently perform an expensive state-mutating action on the same object without first checking whether the action has already been applied, causing earlier work to be lost.

---

### Finding Description

**Vulnerability class**: Race condition / TOCTOU (Time-of-Check-Time-of-Use) on a shared mutable blob.

The flow inside `uploadSignatureMaps` is:

**Step 1 — Read** (`loadTransactionData`): both concurrent requests fetch the same `transactionBytes` snapshot from the database. [1](#0-0) 

**Step 2 — Mutate in memory** (`processTransactionSignatures`): each request independently deserializes the bytes and calls `sdkTransaction.addSignature(publicKey, map)` on its own in-memory copy. [2](#0-1) 

**Step 3 — Blind overwrite** (`bulkUpdateTransactions`): each request writes its own mutated bytes back with an unconditional `UPDATE … SET "transactionBytes" = … WHERE id = ANY(…)`. There is no `WHERE "transactionBytes" = <expected_old_value>` guard and no optimistic version column. [3](#0-2) 

The SQL issued is:

```sql
UPDATE transaction
SET "transactionBytes" = CASE id WHEN {id} THEN $1::bytea END,
    "updatedAt" = NOW()
WHERE id = ANY($N)
```

No condition on the current value of `transactionBytes` is present. Whichever request commits last overwrites all signatures written by earlier concurrent requests.

The same pattern exists in `importSignatures` inside `transactions.service.ts`, which also reads bytes, mutates them in memory, and writes back with an unconditional `UPDATE`: [4](#0-3) 

**No distributed lock protects `uploadSignatureMaps`.** Compare with `executeTransaction` and `executeTransactionGroup`, which are both decorated with `@MurLock` to prevent concurrent execution: [5](#0-4) 

`uploadSignatureMaps` has no equivalent protection. [6](#0-5) 

---

### Impact Explanation

When two organization members (e.g., Alice and Bob) sign the same transaction at nearly the same time:

1. Both requests read `transactionBytes` = `B₀` (unsigned).
2. Alice's request produces `B_A` = `B₀ + Alice's signature`.
3. Bob's request produces `B_B` = `B₀ + Bob's signature`.
4. Alice's request writes `B_A` to the database.
5. Bob's request writes `B_B` to the database, overwriting `B_A`.

The persisted bytes now contain only Bob's signature. Alice's signature is silently lost. The `TransactionSigner` row for Alice is still inserted (the signer insert is separate from the bytes update), creating a false record that Alice signed, while the actual cryptographic signature is absent from `transactionBytes`.

Downstream, `processTransactionStatus` evaluates `hasValidSignatureKey` against the stored bytes. Because Alice's signature is missing from the bytes, a transaction that should have reached `WAITING_FOR_EXECUTION` may remain stuck in `WAITING_FOR_SIGNATURES` indefinitely, or be submitted to Hedera without the required threshold of signatures and fail on-chain. [7](#0-6) 

---

### Likelihood Explanation

Organization mode is explicitly designed for multi-user collaborative signing. Multiple approvers signing the same transaction within a short window is the normal, expected workflow — not an edge case. The front-end calls `POST /transactions/:id/signers` for each signer independently: [8](#0-7) 

With any realistic number of concurrent signers (≥ 2) and no locking, the race window is open on every multi-party signing event. No special attacker capability is required; normal concurrent use triggers the bug.

---

### Recommendation

Apply one of the following mitigations:

1. **Optimistic locking**: Add a `version` integer column to the `transaction` table and include `WHERE id = :id AND version = :expectedVersion` in the update. Retry on conflict.

2. **Pessimistic row lock**: Wrap the read-modify-write inside a database transaction using `SELECT … FOR UPDATE` to serialize concurrent writers at the database level.

3. **Distributed lock (MurLock)**: Apply `@MurLock(15000, 'transaction.id')` to `uploadSignatureMaps`, consistent with how `executeTransaction` is already protected.

4. **Atomic merge in SQL**: Instead of overwriting bytes, store signatures as separate rows and merge them into `transactionBytes` only at execution time, eliminating the shared-mutable-blob pattern entirely.

---

### Proof of Concept

```
T=0ms  Alice  → GET transaction #42 → transactionBytes = B₀
T=0ms  Bob    → GET transaction #42 → transactionBytes = B₀

T=5ms  Alice  → addSignature(aliceKey, map) → B_A = B₀ + sig_alice
T=5ms  Bob    → addSignature(bobKey,   map) → B_B = B₀ + sig_bob

T=10ms Alice  → UPDATE transaction SET transactionBytes = B_A WHERE id = 42
T=11ms Bob    → UPDATE transaction SET transactionBytes = B_B WHERE id = 42
               ↑ unconditional overwrite — B_A (Alice's sig) is gone

DB now holds B_B only.
TransactionSigner table: rows for both Alice AND Bob exist (false record).
hasValidSignatureKey(B_B, requiredKeyList) → false if threshold requires both.
Transaction stays WAITING_FOR_SIGNATURES forever.
```

The race window is the entire async gap between `loadTransactionData` and `bulkUpdateTransactions`, which spans multiple `await` points and is easily hit under normal concurrent load. [9](#0-8)

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L98-124)
```typescript
  /* Upload signatures for the given transaction ids */
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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L269-345)
```typescript
  private async persistSignatureChanges(
    validationResults: any[],
    user: User,
  ) {
    const signers = new Set<TransactionSigner>();
    let notificationsToDismiss: number[] = [];

    // Prepare batched operations
    const transactionsToUpdate: { id: number; transactionBytes: Buffer }[] = [];
    const notificationsToUpdate: { userId: number; transactionId: number }[] = [];
    const signersToInsert: { userId: number; transactionId: number; userKeyId: number }[] = [];
    const transactionsToProcess: { id: number; transaction: Transaction }[] = [];

    for (const result of validationResults) {
      if (result.error) {
        console.error(`[TX ${result.id}] Validation failed: ${result.error}`);
        continue;
      }

      const { id, transaction, sdkTransaction, userKeys, isSameBytes } = result;

      // Skip if nothing to do - no signatures were added to the transaction
      // AND no new signers were inserted (the signature can be present on the transaction
      // if collated by an outside or 'offline' method)
      if (isSameBytes && userKeys.length === 0) continue;

      // Collect updates
      if (!isSameBytes) {
        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
        transactionsToUpdate.push({ id, transactionBytes: transaction.transactionBytes });
      }

      // Collect inserts
      if (userKeys.length > 0) {
        const newSigners = userKeys.map(userKey => ({
          userId: user.id,
          transactionId: id,
          userKeyId: userKey.id,
        }));
        signersToInsert.push(...newSigners);
      }

      transactionsToProcess.push({ id, transaction });
      notificationsToUpdate.push({ userId: user.id, transactionId: transaction.id });
    }

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
    } catch (err) {
      console.error('Database transaction failed:', err);
      throw new BadRequestException(ErrorCodes.FST);
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L507-601)
```typescript
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

    const updateArray = Array.from(updates.values());

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

**File:** back-end/libs/common/src/execute/execute.service.ts (L41-62)
```typescript
  @MurLock(15000, 'transaction.id')
  async executeTransaction(transaction: Transaction) {
    /* Gets the SDK transaction */
    const sdkTransaction = await this.getValidatedSDKTransaction(transaction);
    const result = await this._executeTransaction(transaction, sdkTransaction);
    if (result) {
      emitTransactionStatusUpdate(
        this.notificationsPublisher,
        [{
          entityId: transaction.id,
          additionalData: {
            network: transaction.mirrorNetwork,
            transactionId: sdkTransaction.transactionId,
            status: result.status,
          }
        }],
      );
    }
    return result;
  }

  @MurLock(15000, 'transactionGroup.id + "_group"')
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L118-155)
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
```

**File:** front-end/src/renderer/services/organization/transaction.ts (L119-124)
```typescript
  return await commonRequestHandler(async () => {
    return await axiosWithCredentials.post(
      `${organization.serverUrl}/${controller}/signers?includeNotifications=true`,
      formattedMaps,
    );
  }, 'Failed upload signatures');
```
