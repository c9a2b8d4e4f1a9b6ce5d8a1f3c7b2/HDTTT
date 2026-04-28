All referenced code has been verified against the actual repository. Here is the result:

---

Audit Report

## Title
TOCTOU Race Condition in `createTransactions` Allows Duplicate `transactionId` Records Due to Missing Database Unique Constraint

## Summary
The `createTransactions` function in `transactions.service.ts` performs an application-level duplicate check before inserting new `Transaction` records. Because the `Transaction` entity defines no database-level unique constraint on `transactionId`, two concurrent requests carrying the same `transactionId` can both pass the read check and both be inserted, producing orphaned records that are invisible to normal API flows but permanently present in the database.

## Finding Description

**Missing unique constraint on `transactionId`:**

The `Transaction` entity declares `transactionId` as a plain `@Column()` with no `@Unique()` decorator and no `unique: true` option: [1](#0-0) 

The only entity-level indexes are composite indexes on `['status', 'mirrorNetwork']` and `['creatorKeyId']` — none enforce uniqueness on `transactionId`: [2](#0-1) 

**TOCTOU in `createTransactions`:**

The service performs a `repo.find` duplicate check at the application layer (the read): [3](#0-2) 

Then, only if no duplicate is found, it saves the new records inside a separate database transaction (the write): [4](#0-3) 

The read and write are not atomic. Two concurrent requests carrying the same `transactionId` can both execute the `repo.find` before either write completes, both see `existing.length === 0`, and both proceed to insert — producing two rows with the same `transactionId`.

**Orphaned record behavior:**

`getTransactionById` (string lookup) fetches all rows matching the `transactionId` string, orders by `id DESC`, and returns the first non-inactive one: [5](#0-4) 

The older duplicate row (lower `id`) is permanently hidden from all string-based lookups — it cannot be canceled, rejected, or managed through any normal user flow — but it still exists in the database in `WAITING_FOR_SIGNATURES` status.

## Impact Explanation

- The orphaned transaction record is invisible through the standard `getTransactionById` string-based lookup, so it cannot be canceled, rejected, or managed through normal user flows.
- Any signers or approvers attached to the orphaned record waste effort signing a transaction the API will never surface.
- If the chain/execution service resolves transactions by their internal numeric `id` (not the string `transactionId`), the orphaned record could be picked up for execution, causing a `DUPLICATE_TRANSACTION` error on the Hedera network and leaving the record in a permanently `FAILED` or stuck state.
- The database accumulates permanently unmanageable records, constituting unrecoverable state corruption.

## Likelihood Explanation

Exploitation requires only a standard authenticated user account. The attacker submits two identical POST requests to the transaction creation endpoint simultaneously (e.g., via `Promise.all` or two parallel HTTP clients). No privileged access, no leaked secrets, and no special network position are required. The race window is the round-trip time of the `repo.find` duplicate-check query, which is wide enough to be reliably triggered under normal network conditions.

## Recommendation

Add a database-level unique constraint on `transactionId` in the `Transaction` entity. This is the only reliable fix, as application-level checks are inherently racy under concurrent load:

```typescript
// transaction.entity.ts
@Entity()
@Unique(['transactionId'])   // <-- add this
@Index(['status', 'mirrorNetwork'])
@Index(['creatorKeyId'])
export class Transaction { ... }
```

Alternatively, use `unique: true` directly on the column decorator:

```typescript
@Column({ unique: true })
transactionId: string;
```

A corresponding database migration must be generated and applied. After the constraint is in place, the database will reject the second concurrent insert with a unique-violation error, which the service can catch and surface as a `ConflictException`.

## Proof of Concept

```typescript
// Two concurrent authenticated POST requests with identical transactionId
const [r1, r2] = await Promise.all([
  fetch('/api/transactions', { method: 'POST', body: payload, headers }),
  fetch('/api/transactions', { method: 'POST', body: payload, headers }),
]);
// Both return HTTP 201 Created.
// Database now contains two rows with the same transactionId.
// Only the row with the higher `id` is reachable via getTransactionById(transactionId).
// The lower-id row is permanently orphaned in WAITING_FOR_SIGNATURES status.
```

### Citations

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

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L83-85)
```typescript
  @Column()
  transactionId: string;

```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L113-132)
```typescript
    const transactions = await this.repo.find({
      where: typeof id == 'number' ? { id } : { transactionId: id.toString() },
      relations: [
        'creatorKey',
        'creatorKey.user',
        'observers',
        'comments',
        'groupItem',
        'groupItem.group',
      ],
      order: { id: 'DESC' },
    });

    if (!transactions.length) return null;

    const inactiveStatuses = [TransactionStatus.CANCELED, TransactionStatus.REJECTED, TransactionStatus.ARCHIVED];

    const transaction =
      transactions.find(t => !inactiveStatuses.includes(t.status)) ??
      transactions[0]; // most recent, since ordered by id DESC
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L415-433)
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
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L436-462)
```typescript
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
