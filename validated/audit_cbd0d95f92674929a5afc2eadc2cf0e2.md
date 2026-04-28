### Title
TOCTOU Race Condition in `createTransactions` Allows Duplicate Transaction Records to Bypass Duplicate-Submission Guard

---

### Summary

The duplicate-submission check in `createTransactions` is executed **outside** the database transaction and there is **no database-level unique constraint** on `transactionId`. Two concurrent authenticated POST requests carrying the same Hedera `transactionId` can both pass the guard simultaneously and both be persisted, creating duplicate records. This is the direct analog of the external report's nonce-induced uniqueness bypass: instead of a nonce making every hash unique, the absence of an atomic check-and-insert makes the guard non-atomic, achieving the same result — the duplicate detection is silently bypassed.

---

### Finding Description

**Root cause — check/save split across two separate database operations:**

In `back-end/apps/api/src/transactions/transactions.service.ts`, `createTransactions` first runs a read query to detect duplicates:

```typescript
// Lines 413–433 — OUTSIDE the DB transaction
const existing = await this.repo.find({
  where: {
    transactionId: In(transactionIds),
    status: Not(In([CANCELED, REJECTED, ARCHIVED])),
  },
  select: ['transactionId'],
});
if (existing.length > 0) throw new BadRequestException(...);
``` [1](#0-0) 

Then, in a **separate** database transaction, it saves the new records:

```typescript
// Lines 436–462 — separate DB transaction
const savedTransactions = await this.entityManager.transaction(async (entityManager) => {
  ...
  return await entityManager.save(Transaction, transactions);
});
``` [2](#0-1) 

The gap between the `find` and the `save` is the race window.

**No database-level safety net:**

The `Transaction` entity declares `transactionId` as a plain `@Column()` with no `@Unique` decorator: [3](#0-2) 

The initial migration creates the `transaction` table without any `UNIQUE` constraint on `transactionId`: [4](#0-3) 

There is no `UNIQUE INDEX` or `ON CONFLICT` clause anywhere that would reject a second insert with the same `transactionId`.

**Exploit flow:**

1. Attacker (any authenticated user) constructs a valid Hedera transaction with a chosen `transactionId` (e.g. `0.0.1003@1700000000.000000000`).
2. Two concurrent POST requests are sent to `POST /transactions` carrying identical `transactionBytes`.
3. Both requests execute the `repo.find(...)` check at the same instant — neither finds an existing record.
4. Both proceed to `entityManager.save(...)` — both succeed because there is no unique constraint.
5. Two rows with the same `transactionId` now exist in the `transaction` table, both in `WAITING_FOR_SIGNATURES` status.

---

### Impact Explanation

- **Duplicate signing burden**: All designated signers are presented with two identical pending transactions and must sign both, wasting effort and causing confusion in multi-signature organization workflows.
- **Guaranteed FAILED record**: When both duplicates reach `WAITING_FOR_EXECUTION`, the chain service submits both to Hedera. Hedera's protocol rejects the second submission with `DUPLICATE_TRANSACTION`. The `_executeTransaction` handler catches this code and returns `null`, leaving the second record permanently in `WAITING_FOR_EXECUTION` or transitioning it to `FAILED`, polluting the transaction history. [5](#0-4) 

- **State integrity violation**: The invariant "one active record per Hedera `transactionId`" is broken. Downstream queries, dashboards, and notification logic that assume uniqueness will produce incorrect results.
- **No financial double-spend**: Hedera's protocol prevents the same `transactionId` from being executed twice on-chain, so there is no on-chain double-spend. The damage is confined to application-layer state corruption and operational disruption.

---

### Likelihood Explanation

- **Attacker profile**: Any authenticated, non-privileged user with a valid JWT can reach `POST /transactions`.
- **Trigger**: Sending two HTTP requests in rapid succession (e.g., via `Promise.all` in a script, or a browser double-submit) is trivially achievable with no special tooling.
- **Window size**: The race window spans the round-trip time of the `repo.find` query — typically tens of milliseconds — which is wide enough to be reliably hit with a simple concurrent client.
- **No privilege required**: Standard user credentials suffice; no admin or operator role is needed.

---

### Recommendation

1. **Add a conditional unique index** at the database level on `transactionId` filtered to active statuses (PostgreSQL partial index):
   ```sql
   CREATE UNIQUE INDEX uq_transaction_id_active
     ON "transaction" ("transactionId")
     WHERE status NOT IN ('CANCELED', 'REJECTED', 'ARCHIVED');
   ```
   This makes the database the authoritative guard and eliminates the race entirely.

2. **Move the duplicate check inside the database transaction** using a `SELECT ... FOR UPDATE` or an `INSERT ... ON CONFLICT DO NOTHING RETURNING id` pattern so the check and insert are atomic.

3. **Add `@Unique` to the entity** (or a filtered unique index via TypeORM) so the ORM layer reflects the constraint.

---

### Proof of Concept

```typescript
// Attacker script — run with valid JWT
const tx = buildValidHederaTransaction(); // same bytes, same transactionId

await Promise.all([
  fetch('POST /transactions', { body: tx, headers: { Authorization: jwt } }),
  fetch('POST /transactions', { body: tx, headers: { Authorization: jwt } }),
]);

// Expected (broken) result:
// Both return HTTP 201
// DB now contains two rows with identical transactionId, both WAITING_FOR_SIGNATURES
// SELECT COUNT(*) FROM "transaction" WHERE "transactionId" = '0.0.1003@1700000000.000000000'
// → 2
```

The duplicate check at lines 415–427 of `transactions.service.ts` is bypassed because both requests read zero existing rows before either has written its row, and no database constraint prevents the second write. [6](#0-5)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L400-491)
```typescript
  async createTransactions(dtos: CreateTransactionDto[], user: User): Promise<Transaction[]> {
    if (dtos.length === 0) return [];

    await attachKeys(user, this.entityManager);

    const client = await getClientFromNetwork(dtos[0].mirrorNetwork);

    try {
      // Validate all DTOs upfront
      const validatedData = await Promise.all(
        dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)),
      );

      // Batch check for existing transactions
      const transactionIds = validatedData.map(v => v.transactionId);
      const existing = await this.repo.find({
        where: {
          transactionId: In(transactionIds),
          status: Not(
            In([
              TransactionStatus.CANCELED,
              TransactionStatus.REJECTED,
              TransactionStatus.ARCHIVED,
            ]),
          ),
        },
        select: ['transactionId'],
      });

      if (existing.length > 0) {
        throw new BadRequestException(
          `Transactions already exist: ${existing.map(t => t.transactionId).join(', ')}`,
        );
      }

      // Wrap database operations in transaction
      const savedTransactions = await this.entityManager.transaction(async (entityManager) => {
        const transactions = validatedData.map(data =>
          this.repo.create({
            name: data.name,
            type: data.type,
            description: data.description,
            transactionId: data.transactionId,
            transactionHash: data.transactionHash,
            transactionBytes: data.transactionBytes,
            unsignedTransactionBytes: data.unsignedTransactionBytes,
            status: TransactionStatus.WAITING_FOR_SIGNATURES,
            creatorKey: { id: data.creatorKeyId },
            signature: data.signature,
            mirrorNetwork: data.mirrorNetwork,
            validStart: data.validStart,
            isManual: data.isManual,
            cutoffAt: data.cutoffAt,
            publicKeys: data.publicKeys,
          }),
        );

        try {
          return await entityManager.save(Transaction, transactions);
        } catch (error) {
          throw new BadRequestException(ErrorCodes.FST);
        }
      });

      // Batch schedule reminders
      const reminderPromises = savedTransactions
        .map((tx, index) => {
          const dto = dtos[index];
          if (!dto.reminderMillisecondsBefore) return null;

          const remindAt = new Date(tx.validStart.getTime() - dto.reminderMillisecondsBefore);
          return this.schedulerService.addReminder(
            getTransactionSignReminderKey(tx.id),
            remindAt,
          );
        })
        .filter(Boolean);

      await Promise.all(reminderPromises);

      return savedTransactions;
    } catch (err) {
      // Preserve explicit BadRequestException, but annotate unexpected errors
      if (err instanceof BadRequestException) throw err;

      const PREFIX = 'An unexpected error occurred while creating transactions';
      const message = err instanceof Error && err.message ? `${PREFIX}: ${err.message}` : PREFIX;
      throw new BadRequestException(message);
    } finally {
      client.close();
    }
  }
```

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L83-85)
```typescript
  @Column()
  transactionId: string;

```

**File:** back-end/typeorm/migrations/1764999592722-InitialSchema.ts (L16-16)
```typescript
        await queryRunner.query(`CREATE TABLE IF NOT EXISTS "transaction" ("id" SERIAL NOT NULL, "name" character varying(50) NOT NULL, "type" character varying NOT NULL, "description" character varying(256) NOT NULL, "transactionId" character varying NOT NULL, "transactionHash" character varying NOT NULL, "transactionBytes" bytea NOT NULL, "unsignedTransactionBytes" bytea NOT NULL, "status" character varying NOT NULL, "statusCode" integer, "signature" bytea NOT NULL, "validStart" TIMESTAMP NOT NULL, "mirrorNetwork" character varying NOT NULL, "isManual" boolean NOT NULL DEFAULT false, "cutoffAt" TIMESTAMP, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "executedAt" TIMESTAMP, "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), "deletedAt" TIMESTAMP, "creatorKeyId" integer, CONSTRAINT "PK_89eadb9 ... (truncated)
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L166-185)
```typescript
      // Another pod already submitted this — don't touch the row, let the
      // successful pod win the update and emit the change
      if (statusCode === Status.DuplicateTransaction._code) {
        isDuplicate = true;
        this.logger.debug(
          `Duplicate transaction ${transaction.id} (txId=${sdkTransaction.transactionId}, statusCode=${statusCode}) detected; assuming it was successfully executed by another pod and skipping updates.`,
        );
      } else {
        transactionStatus = TransactionStatus.FAILED;
        transactionStatusCode = statusCode;
        result.error = message;
        this.logger.error(
          `Error executing transaction ${transaction.id} (txId=${sdkTransaction.transactionId}, statusCode=${statusCode}): ${message}`,
        );
      }
    } finally {
      client.close();
    }

    if (isDuplicate) return null;
```
