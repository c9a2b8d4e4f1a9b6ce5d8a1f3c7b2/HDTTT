The code is confirmed. All three phases of the race condition are present in the actual source. Here is the audit report:

---

Audit Report

## Title
TOCTOU Race Condition in `uploadSignatureMaps` Allows Concurrent Signature Writes to Overwrite Each Other, Causing Lost Signatures in `transactionBytes`

## Summary
`SignersService.uploadSignatureMaps` performs a three-phase read-modify-write on `transactionBytes` with no locking or optimistic-concurrency guard at any phase. When two authenticated users upload signatures to the same transaction concurrently, the last writer's `UPDATE` silently overwrites the first writer's signature bytes. The `TransactionSigner` rows for both users are inserted correctly, so the system believes the transaction is fully signed, but the actual `transactionBytes` in the database is missing one or more cryptographic signatures, causing Hedera submission to fail.

## Finding Description

**Phase 1 — Unlocked read outside any DB transaction (`loadTransactionData`):**

`loadTransactionData` fetches `transactionBytes` with a plain `find` call — no `SELECT FOR UPDATE`, no enclosing DB transaction, no snapshot isolation guarantee relevant to the subsequent write. [1](#0-0) 

**Phase 2 — In-memory modification (`processTransactionSignatures`):**

`processTransactionSignatures` deserialises the stale in-memory snapshot and calls `sdkTransaction.addSignature`. It has no awareness of concurrent writers and operates entirely on the snapshot captured in Phase 1. [2](#0-1) 

**Phase 3 — Unconditional UPDATE with no concurrency guard (`bulkUpdateTransactions`):**

The write-back issues a bare `UPDATE ... SET "transactionBytes" = CASE id WHEN X THEN $1::bytea END WHERE id = ANY(...)`. There is no `WHERE "transactionBytes" = <expected_old_value>`, no version column, and no row-level lock. The last `UPDATE` to arrive wins unconditionally. [3](#0-2) 

**Status check also uses the stale snapshot (`validateTransactionStatus`):**

`validateTransactionStatus` inspects `transaction.status` from the in-memory object loaded in Phase 1, not a freshly locked DB row. The check and the write are therefore not atomic. [4](#0-3) 

**`bulkInsertSigners` correctly inserts both users' rows:**

Both `TransactionSigner` rows are inserted inside the DB transaction with different `userKeyId` values and no conflict, so the system's own threshold check concludes the transaction is fully signed. [5](#0-4) 

**Exploit timeline (two concurrent users, same transaction):**

```
T=0  User A: loadTransactionData → reads transactionBytes (no sigs)
T=0  User B: loadTransactionData → reads transactionBytes (no sigs)
T=1  User A: processTransactionSignatures → adds sig_A → newBytesA
T=1  User B: processTransactionSignatures → adds sig_B → newBytesB
T=2  User A: bulkUpdateTransactions → writes newBytesA to DB  ✓
T=3  User B: bulkUpdateTransactions → writes newBytesB to DB  ← overwrites A; sig_A gone
T=4  TransactionSigner rows: both A and B present             ← system thinks fully signed
T=5  Hedera submission fails: sig_A missing from transactionBytes
```

## Impact Explanation

- **Integrity failure**: `transactionBytes` in the database diverges from the set of `TransactionSigner` records. The system's own invariant — "if enough `TransactionSigner` rows exist, the transaction can be executed" — is silently violated.
- **Transaction execution failure**: The Hedera network rejects the submission because a required signature is absent from the bytes, even though the backend reports the transaction as `WAITING_FOR_EXECUTION` or `EXECUTED`.
- **Unrecoverable state**: Once the transaction's `validStart` window expires, the transaction cannot be re-signed or re-submitted. The funds or account-update intent are permanently lost for that transaction window.
- **No privileged access required**: Any two authenticated organisation members who are both required signers can trigger this by uploading signatures within the same request window.

## Likelihood Explanation

In an organisation with multiple required signers, it is normal and expected for several users to upload their signatures in a short time window (e.g., after receiving an email or WebSocket notification). The race window spans the entire async processing time of `processTransactionSignatures` — SDK deserialisation plus signature addition — which is on the order of tens to hundreds of milliseconds. This window is wide enough to be hit in normal production use without any deliberate attack. A malicious insider can trivially widen the window by submitting a large signature map to slow Phase 2.

## Recommendation

Move the `transactionBytes` read inside the DB transaction and acquire a row-level lock before processing, so that the read, modify, and write are atomic:

```sql
-- Replace the plain find with:
SELECT * FROM transaction WHERE id = ANY($1) FOR UPDATE;
```

Alternatively, apply optimistic concurrency control by adding a `WHERE "transactionBytes" = $expected` clause to the `UPDATE` and retrying on conflict. Either approach eliminates the window between Phase 1 and Phase 3.

The `loadTransactionData` call at line 104 and the `persistSignatureChanges` DB transaction at line 317 must be merged into a single `dataSource.transaction` block so that the `SELECT FOR UPDATE` and the `UPDATE` share the same connection and lock scope. [6](#0-5) 

## Proof of Concept

1. Create a Hedera transaction requiring two signers (User A key + User B key).
2. Both User A and User B call `POST /transactions/:id/signers` simultaneously (e.g., via two concurrent HTTP requests timed to overlap during `processTransactionSignatures`).
3. Observe that both `TransactionSigner` rows are inserted (DB query confirms `userKeyId` for both A and B).
4. Inspect `transactionBytes` in the `transaction` table: it contains only one user's signature (whichever request completed last).
5. Attempt to submit the transaction to the Hedera network: the node rejects it with a `INVALID_SIGNATURE` error because the required key from the overwritten signer is absent from the bytes.

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
