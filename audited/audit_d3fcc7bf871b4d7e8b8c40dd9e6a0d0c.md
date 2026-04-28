### Title
TOCTOU Race Condition in `createTransactions` Allows Duplicate `transactionId` Records Due to Missing Database Unique Constraint

### Summary
The `createTransactions` function in `transactions.service.ts` performs an application-level check for duplicate `transactionId` values before inserting new records, but the `Transaction` entity defines no database-level unique constraint on the `transactionId` column. Two concurrent POST requests carrying the same `transactionId` can both pass the read check simultaneously and both be inserted, creating orphaned transaction records that are invisible to normal API flows but still exist in the database — an analog to the Chainlink `internalId` overwrite vulnerability.

### Finding Description

**Root cause — no unique constraint on `transactionId`:**

The `Transaction` entity declares `transactionId` as a plain column with no `@Unique()` decorator and no `unique: true` option: [1](#0-0) 

The only indexes defined on the entity are composite indexes on `['status', 'mirrorNetwork']` and `['creatorKeyId']` — none enforce uniqueness on `transactionId`: [2](#0-1) 

**TOCTOU in `createTransactions`:**

The service performs a read-then-write duplicate check at the application layer: [3](#0-2) 

Then, if no duplicate is found, it saves the new records inside a transaction: [4](#0-3) 

Because there is no database-level unique constraint, two concurrent requests carrying the same `transactionId` can both pass the `existing.length > 0` check before either write completes, and both rows are inserted successfully.

**Orphaned record behavior:**

`getTransactionById` (string lookup) fetches all rows matching the `transactionId` string and returns the most recent non-inactive one: [5](#0-4) 

The older duplicate row is permanently hidden from all normal API flows (view, cancel, sign lookup) but still exists in the database in `WAITING_FOR_SIGNATURES` status.

### Impact Explanation

- The orphaned transaction record is invisible through the standard `getTransactionById` string-based lookup, so it cannot be canceled, rejected, or managed through normal user flows.
- Any signers or approvers attached to the orphaned record waste effort signing a transaction that the API will never surface.
- If the chain service resolves transactions by their internal numeric `id` (not the string `transactionId`), the orphaned record could be picked up for execution, causing a `DUPLICATE_TRANSACTION` error on the Hedera network and leaving the record in a permanently `FAILED` or stuck state.
- The database accumulates permanently unmanageable records, constituting unrecoverable state corruption — the direct analog to the Chainlink callbacks mapping overwrite.

### Likelihood Explanation

Exploitation requires only a standard authenticated user account. The attacker submits two identical POST requests to the transaction creation endpoint simultaneously (e.g., via two parallel HTTP clients or a single script with `Promise.all`). No privileged access, no leaked secrets, and no special network position are required. The race window is the round-trip time of the `repo.find` duplicate check query, which is wide enough to be reliably hit under normal network conditions.

### Recommendation

Add a `@Unique()` decorator (or `unique: true` in the `@Column` options) to the `transactionId` field in the `Transaction` entity, and back it with a database migration. This makes the uniqueness guarantee atomic and removes the TOCTOU window entirely:

```typescript
// back-end/libs/common/src/database/entities/transaction.entity.ts
@Column({ unique: true })
transactionId: string;
```

The application-level check in `createTransactions` can remain as a user-friendly early error, but the database constraint must be the authoritative enforcement layer.

### Proof of Concept

1. Authenticate as a normal user and obtain a JWT token.
2. Construct a valid `CreateTransactionDto` payload with a fixed `transactionId` (e.g., `0.0.1234@1700000000.000000000`).
3. Fire two simultaneous POST requests to `/transactions` with the identical payload:
   ```ts
   await Promise.all([
     axios.post('/transactions', payload, { headers }),
     axios.post('/transactions', payload, { headers }),
   ]);
   ```
4. Both requests return HTTP 201.
5. Query the database directly: `SELECT id, "transactionId", status FROM transaction WHERE "transactionId" = '0.0.1234@1700000000.000000000'` — two rows are present.
6. Call `GET /transactions/:transactionId` (string form) — only one row is returned; the other is permanently orphaned and unmanageable through the API. [6](#0-5) [1](#0-0)

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L400-433)
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
