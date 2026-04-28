### Title
Race Condition in `createTransactions` Allows Duplicate Transaction Entries via Concurrent Requests

### Summary
The `POST /transactions` endpoint in the API service is vulnerable to a TOCTOU (Time-of-Check-Time-of-Use) race condition. Because the duplicate-existence check and the database insert are two separate, non-atomic operations with no database-level unique constraint on `transactionId`, two concurrent requests carrying the same Hedera `transactionId` can both pass the check and both be persisted, creating duplicate transaction rows. This is the direct analog of the external "duplicate pool creation" report.

### Finding Description

**Root cause — non-atomic check-then-insert:**

`createTransactions` in `back-end/apps/api/src/transactions/transactions.service.ts` performs two completely separate database operations:

**Step 1 — read check (lines 415–427):** [1](#0-0) 

```
SELECT … WHERE transactionId IN (…) AND status NOT IN (CANCELED, REJECTED, ARCHIVED)
```

**Step 2 — insert (lines 436–462), in a separate DB transaction:** [2](#0-1) 

Between Step 1 and Step 2 there is no lock, no advisory lock, and no serializable isolation. Two concurrent requests that arrive within the same millisecond window will both execute Step 1 and find zero existing rows, then both proceed to Step 2 and both successfully insert.

**No database-level safety net:**

The `Transaction` entity declares `transactionId` as a plain `@Column()` with no `unique: true`: [3](#0-2) 

The initial migration creates the column as `character varying NOT NULL` with no `UNIQUE` constraint — confirmed by the DDL in the migration: [4](#0-3) 

No subsequent migration adds a unique index on `transactionId`. The entity-level indexes are only on `['status', 'mirrorNetwork']` and `['creatorKeyId']`: [5](#0-4) 

**Reachable entry point:**

The `POST /transactions` endpoint is accessible to any authenticated, verified user who holds at least one key — no admin role required: [6](#0-5) 

**Downstream state corruption:**

When the duplicate row eventually reaches execution, `_executeTransaction` detects `Status.DuplicateTransaction` from Hedera and silently returns `null` without updating the row's status: [7](#0-6) 

This leaves the duplicate row permanently stuck in `WAITING_FOR_EXECUTION`, corrupting the organization's transaction state.

### Impact Explanation

- Two rows with the same Hedera `transactionId` are persisted in `WAITING_FOR_SIGNATURES` status.
- Both appear in every signer's and approver's queue, wasting their effort and causing confusion.
- When one is submitted to Hedera and succeeds, the other receives `DUPLICATE_TRANSACTION` from the network and is silently abandoned in `WAITING_FOR_EXECUTION` — an unrecoverable state without manual DB intervention.
- For atomic/sequential transaction groups, a stuck duplicate can block the entire group from progressing.
- Any authenticated user can trigger this against their own or shared organization transactions.

### Likelihood Explanation

- Attacker preconditions: a valid, verified user account with at least one registered key — the baseline for any organization member.
- Exploit requires sending two HTTP POST requests to `POST /transactions` with identical payloads simultaneously. This is trivially achievable with a two-line script (e.g., `Promise.all([fetch(...), fetch(...)])`).
- No privileged access, no leaked secrets, no physical access required.
- The window is wide enough to be reliably hit because `validateAndPrepareTransaction` involves async network calls (mirror node, key attachment), making the gap between check and insert measurable in hundreds of milliseconds.

### Recommendation

Apply both layers of defense:

1. **Database-level unique constraint** — add a partial unique index on `transactionId` filtered to active statuses. This is the only reliable guard against race conditions:
   ```sql
   CREATE UNIQUE INDEX uq_transaction_active_id
     ON "transaction" ("transactionId")
     WHERE status NOT IN ('CANCELED', 'REJECTED', 'ARCHIVED');
   ```
   Reflect this in the TypeORM entity with `@Index({ unique: true, where: "status NOT IN ('CANCELED','REJECTED','ARCHIVED')" })`.

2. **Move the existence check inside the DB transaction with a locking read** — use `SELECT … FOR UPDATE` or PostgreSQL's `INSERT … ON CONFLICT DO NOTHING RETURNING id` so the check and insert are atomic. The current `entityManager.transaction` block does not include the `repo.find` call, so it provides no protection against the race.

### Proof of Concept

```typescript
// Any authenticated verified user with a key can run this
const payload = {
  name: "Test",
  description: "Race condition PoC",
  transactionBytes: "<hex of a valid AccountCreateTransaction with transactionId 0.0.X@T>",
  creatorKeyId: <userKeyId>,
  signature: "<valid creator signature>",
  mirrorNetwork: "testnet",
};

const headers = { Authorization: `Bearer ${userJwt}`, "Content-Type": "application/json" };

// Fire two requests simultaneously
const [r1, r2] = await Promise.all([
  fetch("http://api-host/transactions", { method: "POST", headers, body: JSON.stringify(payload) }),
  fetch("http://api-host/transactions", { method: "POST", headers, body: JSON.stringify(payload) }),
]);

// Expected (broken) outcome: both return HTTP 201
// DB now contains two rows with the same transactionId in WAITING_FOR_SIGNATURES
console.log(await r1.json()); // { id: N, transactionId: "0.0.X@T", status: "WAITING FOR SIGNATURES" }
console.log(await r2.json()); // { id: N+1, transactionId: "0.0.X@T", status: "WAITING FOR SIGNATURES" }
```

Both rows appear in the signer queue. When one is executed on Hedera, the other is silently left in `WAITING_FOR_EXECUTION` with no further state transition, permanently corrupting the organization's transaction ledger.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L413-433)
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
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L435-462)
```typescript
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

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L63-69)
```typescript
@Entity()
@Index(['status', 'mirrorNetwork'])
@Index(['creatorKeyId'])
@Index('idx_transaction_public_keys_gin', {
  // Tell TypeORM this index exists but is managed by migrations
  synchronize: false,
})
```

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L83-84)
```typescript
  @Column()
  transactionId: string;
```

**File:** back-end/typeorm/migrations/1764999592722-InitialSchema.ts (L16-16)
```typescript
        await queryRunner.query(`CREATE TABLE IF NOT EXISTS "transaction" ("id" SERIAL NOT NULL, "name" character varying(50) NOT NULL, "type" character varying NOT NULL, "description" character varying(256) NOT NULL, "transactionId" character varying NOT NULL, "transactionHash" character varying NOT NULL, "transactionBytes" bytea NOT NULL, "unsignedTransactionBytes" bytea NOT NULL, "status" character varying NOT NULL, "statusCode" integer, "signature" bytea NOT NULL, "validStart" TIMESTAMP NOT NULL, "mirrorNetwork" character varying NOT NULL, "isManual" boolean NOT NULL DEFAULT false, "cutoffAt" TIMESTAMP, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "executedAt" TIMESTAMP, "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), "deletedAt" TIMESTAMP, "creatorKeyId" integer, CONSTRAINT "PK_89eadb9 ... (truncated)
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L69-78)
```typescript
  @UseGuards(HasKeyGuard)
  @Post()
  @Serialize(TransactionDto)
  @OnlyOwnerKey<CreateTransactionDto>('creatorKeyId')
  async createTransaction(
    @Body() body: CreateTransactionDto,
    @GetUser() user,
  ): Promise<Transaction> {
    return this.transactionsService.createTransaction(body, user);
  }
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L168-185)
```typescript
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
