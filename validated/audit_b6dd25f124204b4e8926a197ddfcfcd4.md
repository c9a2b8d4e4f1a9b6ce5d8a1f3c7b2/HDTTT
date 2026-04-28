All four required checks pass. The code confirms every claim made in the report.

**Verification summary:**

- **Non-atomic check-then-insert**: Confirmed at lines 415–427 (SELECT) and 436–462 (INSERT) in `transactions.service.ts` — two separate DB operations with no lock between them. [1](#0-0) 

- **No unique constraint**: The `Transaction` entity declares `transactionId` as a plain `@Column()` with no `unique: true`. [2](#0-1)  The initial migration creates it as `character varying NOT NULL` with no UNIQUE constraint, and no subsequent migration adds one. [3](#0-2) 

- **Entry point**: `POST /transactions` is guarded only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard`, and `HasKeyGuard` — no admin role required. [4](#0-3) 

- **Downstream stuck row**: When `DuplicateTransaction` is received, `_executeTransaction` sets `isDuplicate = true` and returns `null` without updating the row's status, leaving it permanently in `WAITING_FOR_EXECUTION`. [5](#0-4) 

---

# Audit Report

## Title
Race Condition in `createTransactions` Allows Duplicate Transaction Entries via Concurrent Requests

## Summary
The `POST /transactions` endpoint is vulnerable to a TOCTOU race condition. The duplicate-existence check and the database insert are two separate, non-atomic operations with no database-level unique constraint on `transactionId`. Two concurrent requests carrying the same Hedera `transactionId` can both pass the check and both be persisted, creating duplicate transaction rows.

## Finding Description

**Root cause — non-atomic check-then-insert in `createTransactions`:**

`createTransactions` in `back-end/apps/api/src/transactions/transactions.service.ts` performs two completely separate database operations:

**Step 1 — read check (lines 415–427):**
```ts
const existing = await this.repo.find({
  where: {
    transactionId: In(transactionIds),
    status: Not(In([CANCELED, REJECTED, ARCHIVED])),
  },
  select: ['transactionId'],
});
if (existing.length > 0) { throw new BadRequestException(...); }
``` [6](#0-5) 

**Step 2 — insert (lines 436–462), in a separate DB transaction:**
```ts
const savedTransactions = await this.entityManager.transaction(async (entityManager) => {
  ...
  return await entityManager.save(Transaction, transactions);
});
``` [7](#0-6) 

Between Step 1 and Step 2 there is no lock, no advisory lock, and no serializable isolation. Two concurrent requests that arrive within the same millisecond window will both execute Step 1 and find zero existing rows, then both proceed to Step 2 and both successfully insert.

**No database-level safety net:**

The `Transaction` entity declares `transactionId` as a plain `@Column()` with no `unique: true`: [2](#0-1) 

The initial migration creates the column as `character varying NOT NULL` with no `UNIQUE` constraint: [3](#0-2) 

No subsequent migration (`1765268917785`, `1766048132624`, `1766811596315`, `1768289349311`, `1770193855293`, `1770998025293`, `1772727369385`) adds a unique index on `transactionId`. The entity-level indexes are only on `['status', 'mirrorNetwork']` and `['creatorKeyId']`: [8](#0-7) 

**Reachable entry point:**

The `POST /transactions` endpoint is accessible to any authenticated, verified user who holds at least one key — no admin role required: [4](#0-3) 

**Downstream state corruption:**

When the duplicate row eventually reaches execution, `_executeTransaction` detects `Status.DuplicateTransaction` from Hedera, sets `isDuplicate = true`, and returns `null` without updating the row's status — leaving it permanently stuck in `WAITING_FOR_EXECUTION`: [5](#0-4) 

## Impact Explanation

- Two rows with the same Hedera `transactionId` are persisted in `WAITING_FOR_SIGNATURES` status.
- Both appear in every signer's and approver's queue, wasting effort and causing confusion.
- When one is submitted to Hedera and succeeds, the other receives `DUPLICATE_TRANSACTION` from the network and is silently abandoned in `WAITING_FOR_EXECUTION` — an unrecoverable state without manual DB intervention.
- For atomic/sequential transaction groups, a stuck duplicate can block the entire group from progressing.
- Any authenticated user can trigger this against their own or shared organization transactions.

## Likelihood Explanation

- Attacker preconditions: a valid, verified user account with at least one registered key — the baseline for any organization member.
- Exploit requires sending two HTTP POST requests to `POST /transactions` with identical payloads simultaneously. This is trivially achievable (e.g., `Promise.all([fetch(...), fetch(...)])`).
- No privileged access, no leaked secrets, no physical access required.
- The window is wide enough to be reliably hit because `validateAndPrepareTransaction` involves async network calls (mirror node, key attachment), making the gap between check and insert measurable in hundreds of milliseconds. [9](#0-8) 

## Recommendation

Apply **both** of the following fixes — defense in depth requires both layers:

1. **Add a partial unique index at the database level** via a new migration:
   ```sql
   CREATE UNIQUE INDEX uq_transaction_active_id
     ON transaction ("transactionId")
     WHERE status NOT IN ('CANCELED', 'REJECTED', 'ARCHIVED');
   ```
   This is the only reliable safety net against concurrent inserts.

2. **Perform the check inside the same database transaction as the insert**, using a pessimistic lock (`SELECT ... FOR UPDATE`) or by relying on the unique index with an `ON CONFLICT DO NOTHING / RAISE` pattern, so the check and insert are atomic.

3. Optionally, add `unique: true` to the `@Column()` decorator on `transactionId` in the `Transaction` entity if a global uniqueness guarantee is acceptable, or use a partial unique index as above if re-use after cancellation/rejection/archival is intentional.

## Proof of Concept

```js
const payload = { /* valid CreateTransactionDto with a fixed transactionId */ };
const headers = { Authorization: 'Bearer <valid_jwt>', 'Content-Type': 'application/json' };

// Fire two identical requests simultaneously
const [r1, r2] = await Promise.all([
  fetch('https://<host>/transactions', { method: 'POST', headers, body: JSON.stringify(payload) }),
  fetch('https://<host>/transactions', { method: 'POST', headers, body: JSON.stringify(payload) }),
]);

console.log(await r1.json()); // 201 Created — transaction row A
console.log(await r2.json()); // 201 Created — transaction row B (duplicate)
// Both rows now exist in the DB with the same transactionId
```

Both requests pass the existence check at lines 415–427 before either insert completes, then both succeed at lines 436–462, producing two rows with the same `transactionId`. [10](#0-9)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L407-414)
```typescript
    try {
      // Validate all DTOs upfront
      const validatedData = await Promise.all(
        dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)),
      );

      // Batch check for existing transactions
      const transactionIds = validatedData.map(v => v.transactionId);
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L415-462)
```typescript
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

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L56-78)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
  constructor(private transactionsService: TransactionsService) {}

  /* Submit a transaction */
  @ApiOperation({
    summary: 'Create a transaction',
    description: 'Create a transaction for the organization to approve, sign, and execute.',
  })
  @ApiResponse({
    status: 201,
    type: TransactionDto,
  })
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
