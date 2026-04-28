All four required checks pass based on direct code inspection. Here is the verified audit report.

---

Audit Report

## Title
TOCTOU Race Condition in `createTransactions` Allows Duplicate Transaction Creation via User-Controlled `transactionId`

## Summary
The `createTransactions` function in `back-end/apps/api/src/transactions/transactions.service.ts` performs a duplicate-check `SELECT` and a subsequent `INSERT` as two non-atomic steps with no database-level unique constraint on the `transactionId` column. Two concurrent HTTP requests carrying the same user-controlled `transactionId` can both pass the check and both be persisted, producing duplicate `Transaction` rows that independently advance toward Hedera network execution.

## Finding Description

**Root cause — check-then-act without atomicity or a DB unique constraint**

The uniqueness guard is a plain `repo.find()` call at lines 415–427, which runs **outside** the `entityManager.transaction()` block. The `entityManager.transaction()` at line 436 wraps only the `INSERT`:

```
// Step 1 – check (outside transaction boundary)
const existing = await this.repo.find({
  where: {
    transactionId: In(transactionIds),
    status: Not(In([CANCELED, REJECTED, ARCHIVED])),
  },
  select: ['transactionId'],
});
if (existing.length > 0) throw new BadRequestException(...);

// Step 2 – save (inside entityManager.transaction())
return await entityManager.save(Transaction, transactions);
``` [1](#0-0) 

Two concurrent requests that arrive within the same scheduling window will both execute Step 1 against an empty result set, both conclude no duplicate exists, and both proceed to Step 2 — where both `INSERT`s succeed because there is no database-level `UNIQUE` constraint on `transactionId`.

**No DB-level unique constraint on `transactionId`**

The `Transaction` entity defines `transactionId` with a plain `@Column()` decorator — no `@Unique`, no `@Index({unique:true})`: [2](#0-1) 

The class-level `@Index` decorators cover only `['status', 'mirrorNetwork']` and `['creatorKeyId']`. The initial migration creates the column as `"transactionId" character varying NOT NULL` with no `UNIQUE` modifier and no unique index: [3](#0-2) 

No subsequent migration adds a unique constraint on `transaction.transactionId`. The `catch` block inside `entityManager.save` only re-throws as `BadRequestException(ErrorCodes.FST)`, so even if a constraint existed the error surface would be opaque; without one, both rows are silently committed. [4](#0-3) 

**User-controlled `transactionId`**

The `transactionId` stored in the database is extracted from the user-supplied `transactionBytes` field of `CreateTransactionDto`. In Hedera, a transaction ID is `payerAccountId@validStartTime` — both values are chosen by the submitting client, giving full control over the resulting `transactionId` string.

## Impact Explanation

- **Duplicate transaction rows** in PostgreSQL break the platform's invariant that each Hedera `transactionId` maps to exactly one managed transaction.
- **Double-execution risk**: both rows enter `WAITING_FOR_SIGNATURES` → `WAITING_FOR_EXECUTION`. The chain service will attempt to execute both. The Hedera network deduplicates at the protocol level, but the platform's own state (`status`, `executedAt`, receipts) becomes inconsistent across the two rows.
- **Griefing / execution hijacking**: an attacker who races a victim's submission causes the victim's row to be rejected at the Hedera level (`DUPLICATE_TRANSACTION`) while the attacker's row is marked `EXECUTED`, effectively hijacking the execution record of the victim's transaction.
- **Accounting / audit integrity failure**: downstream reporting, fee accounting, and notification systems receive two events for one Hedera transaction.

## Likelihood Explanation

- **Attacker preconditions**: only a valid JWT (registered user account) is required — no admin or privileged role.
- **Triggering the race**: sending two HTTP requests within the same Node.js event-loop tick is trivially achievable (`Promise.all([fetch(...), fetch(...)])`). No mempool or blockchain timing is involved.
- **Predicting the victim's `transactionId`**: organizational deployments typically use well-known payer accounts (treasury, operator). An attacker who knows the payer account can enumerate valid-start timestamps in a tight window. Alternatively, the attacker can race their own duplicate submission without targeting a specific victim.

## Recommendation

Apply **both** of the following fixes — either alone is insufficient:

1. **Add a partial unique index at the database level** via a new migration:
   ```sql
   CREATE UNIQUE INDEX uq_transaction_id_active
     ON "transaction" ("transactionId")
     WHERE status NOT IN ('CANCELED', 'REJECTED', 'ARCHIVED');
   ```
   This mirrors the application-level check and makes the constraint atomic and enforced by the database engine.

2. **Move the duplicate check inside the `entityManager.transaction()` block** and use a `SELECT ... FOR UPDATE` or `INSERT ... ON CONFLICT DO NOTHING` pattern so the check and insert are atomic within the same database transaction:
   ```typescript
   const savedTransactions = await this.entityManager.transaction(async (em) => {
     // Re-check inside the transaction with a row-level lock
     const existing = await em.find(Transaction, {
       where: { transactionId: In(transactionIds), status: Not(In([...])) },
       lock: { mode: 'pessimistic_write' },
     });
     if (existing.length > 0) throw new BadRequestException(...);
     return await em.save(Transaction, transactions);
   });
   ```

## Proof of Concept

```typescript
// Attacker sends two identical requests concurrently
const payload = {
  transactionBytes: /* bytes encoding payerAccount@validStart */,
  creatorKeyId: 1,
  name: 'dup',
  description: 'dup',
  mirrorNetwork: 'testnet',
  signature: /* valid creator signature */,
};

const [r1, r2] = await Promise.all([
  fetch('POST /api/transactions', payload),
  fetch('POST /api/transactions', payload),
]);

// Both requests return HTTP 201 Created.
// Database now contains two rows with identical transactionId.
// Both rows enter WAITING_FOR_SIGNATURES and will be independently
// submitted to the Hedera network by the chain service.
```

The race is reliably reproducible because the `await this.repo.find(...)` at line 415 yields the event loop, allowing the second request's `find` to execute before either request's `save` completes. [5](#0-4)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L413-462)
```typescript
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
```

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L63-84)
```typescript
@Entity()
@Index(['status', 'mirrorNetwork'])
@Index(['creatorKeyId'])
@Index('idx_transaction_public_keys_gin', {
  // Tell TypeORM this index exists but is managed by migrations
  synchronize: false,
})
export class Transaction {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ length: 50 })
  name: string;

  @Column()
  type: TransactionType;

  @Column({ length: 256 })
  description: string;

  @Column()
  transactionId: string;
```

**File:** back-end/typeorm/migrations/1764999592722-InitialSchema.ts (L16-16)
```typescript
        await queryRunner.query(`CREATE TABLE IF NOT EXISTS "transaction" ("id" SERIAL NOT NULL, "name" character varying(50) NOT NULL, "type" character varying NOT NULL, "description" character varying(256) NOT NULL, "transactionId" character varying NOT NULL, "transactionHash" character varying NOT NULL, "transactionBytes" bytea NOT NULL, "unsignedTransactionBytes" bytea NOT NULL, "status" character varying NOT NULL, "statusCode" integer, "signature" bytea NOT NULL, "validStart" TIMESTAMP NOT NULL, "mirrorNetwork" character varying NOT NULL, "isManual" boolean NOT NULL DEFAULT false, "cutoffAt" TIMESTAMP, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "executedAt" TIMESTAMP, "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), "deletedAt" TIMESTAMP, "creatorKeyId" integer, CONSTRAINT "PK_89eadb9 ... (truncated)
```
