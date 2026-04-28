### Title
Race Condition (Lost Update) in `importSignatures` Allows Silent Signature Drops, Potentially Expiring Transactions

### Summary
The `importSignatures` method in `TransactionsService` performs a non-atomic read-modify-write on `transactionBytes` with no concurrency control. Two concurrent calls for the same transaction ID both read the same base bytes, independently append their signatures in memory, then race to write back — the second write silently overwrites the first, discarding valid signatures. A malicious authenticated organization member can exploit this to continuously race legitimate signers, preventing a transaction from ever accumulating the required signatures before its `validStart` deadline expires.

### Finding Description

**Root cause — non-atomic read-modify-write without any lock:**

`importSignatures` reads the current `transactionBytes` from the database, appends signatures in the Node.js process memory, then writes the result back via a raw SQL `UPDATE`: [1](#0-0) 

```
READ  → entityManager.find(Transaction, { where: { id: In(ids) } })
CHECK → status must be WAITING_FOR_SIGNATURES or WAITING_FOR_EXECUTION
MODIFY→ sdkTransaction.addSignature(publicKey, map)
        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes())
WRITE → UPDATE transaction SET transactionBytes = CASE id WHEN … END
``` [2](#0-1) 

The write-back is a plain `UPDATE … WHERE id IN (…)` with no optimistic-lock version column and no `SELECT … FOR UPDATE` row lock: [3](#0-2) 

**Exploit flow:**

| Time | Request A (legitimate signer) | Request B (attacker) |
|------|-------------------------------|----------------------|
| T0 | `find` → reads `bytes_0` | `find` → reads `bytes_0` |
| T1 | adds `sig_A` → `bytes_A` | adds `sig_B` (dummy/own) → `bytes_B` |
| T2 | writes `bytes_A` | writes `bytes_B` (overwrites A) |
| T3 | — | `sig_A` is silently gone |

The attacker only needs to fire their own `POST /transactions/signatures/import` for the same transaction ID at the same time as a legitimate signer. Because Node.js is single-threaded but `await` yields between the `find` and the `UPDATE`, both requests interleave freely.

**No guard exists.** There is no mutex, no Redis lock, no `SELECT … FOR UPDATE`, and no optimistic-lock (`@VersionColumn`) on the `Transaction` entity for this field.

### Impact Explanation

A malicious authenticated organization member can:

1. **Silently drop valid signatures** — each racing write discards the previous signer's work. The legitimate signer receives a `200 OK` with `{ id }` (success), unaware their signature was lost.
2. **Expire a transaction** — Hedera transactions have a fixed `validStart` window. By repeatedly racing every legitimate import attempt, the attacker can prevent the required signature threshold from ever being reached before the deadline, permanently killing the transaction (expired transactions cannot be re-submitted with the same ID).
3. **Corrupt accumulated signature state** — the final `transactionBytes` stored in the DB may contain an inconsistent or incomplete signature set, causing downstream execution failures.

### Likelihood Explanation

- **Attacker precondition:** must be a registered, verified organization member with `importSignatures` access to the target transaction — a realistic insider-threat profile explicitly listed in `RESEARCHER.md` ("Malicious normal user abusing valid product/protocol flows").
- **Trigger:** two concurrent HTTP `POST /transactions/signatures/import` requests for the same transaction ID. Trivially achievable with any HTTP client (e.g., `Promise.all([fetch(…), fetch(…)])`).
- **No rate-limit protection** on this endpoint prevents sustained racing.
- **Silent success response** means the victim signer has no indication their signature was dropped.

### Recommendation

Replace the in-memory read-modify-write with a database-level atomic operation:

1. **Preferred — `SELECT … FOR UPDATE` inside a transaction:**
   ```typescript
   await this.entityManager.transaction(async em => {
     const tx = await em
       .createQueryBuilder(Transaction, 't')
       .setLock('pessimistic_write')
       .where('t.id = :id', { id })
       .getOne();
     // mutate tx.transactionBytes, then em.save(tx)
   });
   ```
2. **Alternative — optimistic locking:** add a `@VersionColumn() version: number` to the `Transaction` entity and let TypeORM throw `OptimisticLockVersionMismatchError` on conflict, then retry.
3. **Alternative — application-level mutex:** use a per-transaction-ID Redis lock (e.g., `redlock`) acquired before the read and released after the write.

### Proof of Concept

```typescript
// Attacker and legitimate signer both call simultaneously:
const url = 'https://api.example.com/transactions/signatures/import';
const headers = { Authorization: 'Bearer <valid_jwt>', 'Content-Type': 'application/json' };

const legitimatePayload = [{ id: 42, signatureMap: legitimateSignatureMap }];
const attackerPayload   = [{ id: 42, signatureMap: attackerOwnSignatureMap }];

// Fire both concurrently
const [legitResult, attackResult] = await Promise.all([
  fetch(url, { method: 'POST', headers, body: JSON.stringify(legitimatePayload) }),
  fetch(url, { method: 'POST', headers, body: JSON.stringify(attackerPayload) }),
]);

// Both return HTTP 201 { id: 42 } — success
// But the DB now contains only one set of signatures (whichever wrote last)
// The legitimate signer's signature is silently gone
```

Expected outcome: the transaction's `transactionBytes` in the database contains only the attacker's signature. The legitimate signer's signature is lost with no error surfaced. Repeating this pattern across every signing attempt causes the transaction to expire unsigned. [4](#0-3)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L493-626)
```typescript
  async importSignatures(
    dto: UploadSignatureMapDto[],
    user: User,
  ): Promise<SignatureImportResultDto[]> {
    type UpdateRecord = {
      id: number;
      transactionBytes: Buffer;
      transactionId: string;
      network: string;
    };

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

          // mark each update in the batch as succeeded
          batch.forEach(u => results.set(u.id, { id: u.id }));
        } catch (err) {
          const SAVE_ERROR_PREFIX = 'An unexpected error occurred while saving the signatures';
          const message =
            err instanceof Error && err.message
              ? `${SAVE_ERROR_PREFIX}: ${err.message}`
              : SAVE_ERROR_PREFIX;

          batch.forEach(u => results.set(u.id, { id: u.id, error: message }));
        }
      }

      emitTransactionStatusUpdate(
        this.notificationsPublisher,
        updateArray.map(r => ({
          entityId: r.id,
          additionalData: { transactionId: r.transactionId, network: r.network },
        })),
      );
    }

    return Array.from(results.values());
  }
```
