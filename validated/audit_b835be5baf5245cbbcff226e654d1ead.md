All referenced code has been verified against the actual repository. Here is the audit result:

---

Audit Report

## Title
TOCTOU Race Condition in `createTransactions` Allows Duplicate `transactionId` Records, Permanently Corrupting Transaction State

## Summary
The `createTransactions` function performs an application-level uniqueness check via a `SELECT` query outside of the database transaction that performs the `INSERT`. Because no `UNIQUE` constraint exists on the `transactionId` column, two concurrent authenticated requests carrying the same `transactionId` can both pass the check and both be inserted. The resulting duplicate record becomes permanently stuck in `WAITING_FOR_EXECUTION` because the `_executeTransaction` method explicitly skips the status update when Hedera returns `DUPLICATE_TRANSACTION`.

## Finding Description

**Root cause 1 — No DB-level uniqueness constraint**

The `Transaction` entity declares `transactionId` as a plain `@Column()` with no `@Unique()` decorator: [1](#0-0) 

The initial migration creates the column without a `UNIQUE` constraint: [2](#0-1) 

No subsequent migration in the chain adds one. All later migrations (`1765268917785`, `1765908705319`, `1766048132624`, `1766811596315`, `1768289349311`, `1770193855293`, `1770998025293`, `1772727369385`) add unique indexes only on unrelated tables (`cached_account_key`, `cached_node_admin_key`, `transaction_cached_account`, `transaction_cached_node`).



**Root cause 2 — SELECT and INSERT are not atomic**

The uniqueness check (`repo.find`) is executed **outside** the `entityManager.transaction()` block that performs the `INSERT`: [3](#0-2) 

The `INSERT` (via `entityManager.save`) is in a separate database transaction: [4](#0-3) 

Because the `SELECT` and `INSERT` are in different database transactions with no serializable isolation or advisory lock between them, two concurrent requests can both observe zero existing records and both proceed to insert.

**Root cause 3 — `_executeTransaction` skips status update on `DUPLICATE_TRANSACTION`**

When the chain service executes the second (duplicate) DB row and Hedera returns `DUPLICATE_TRANSACTION`, the code sets `isDuplicate = true` and returns `null` without updating the row's status: [5](#0-4) 

The `@MurLock` on `executeTransaction` is keyed on `transaction.id` (the DB primary key), so it only prevents concurrent execution of the **same** DB row. Two different DB rows with the same Hedera `transactionId` are not mutually excluded and can both be dispatched. [6](#0-5) 

## Impact Explanation
- **Permanent state corruption**: The duplicate DB row remains in `WAITING_FOR_EXECUTION` indefinitely. Every subsequent scheduler pass re-attempts execution, receives `DUPLICATE_TRANSACTION` again, and skips the update — an infinite loop.
- **Scheduler resource exhaustion**: The stuck record consumes scheduler cycles on every polling interval for the lifetime of the deployment.
- **Workflow disruption**: All observers, signers, and approvers attached to the duplicate record see it perpetually pending, polluting the transaction list and triggering repeated (spurious) reminder notifications.
- **Cross-user interference**: Any authenticated user (no admin role required) can target another user's transaction by embedding the victim's `transactionId` in their own transaction bytes.

## Likelihood Explanation
- **Attacker preconditions**: Any registered, authenticated user. No privileged role is required.
- **`transactionId` discoverability**: The `transactionId` is returned in the `201` response body of the victim's `POST /transactions` request and is broadcast via WebSocket status-update notifications. No mempool observation is needed.
- **Signature check bypass**: The `publicKey.verify` check at creation time only verifies that the submitted bytes were signed by the attacker's own registered key — it does not verify that the payer account in the `transactionId` belongs to the attacker. The Hedera SDK allows embedding any payer account ID and valid-start timestamp in transaction bytes.
- **Race window**: The window between the `SELECT` (line 415) and the `INSERT` (line 458) spans at least one async `await` boundary, making it exploitable under normal Node.js async I/O even on a single-pod deployment. In a multi-pod deployment the window is always open.

## Recommendation
1. **Add a DB-level `UNIQUE` constraint** on `transactionId` (scoped to non-terminal statuses, or unconditionally). This is the only reliable fix. Add a migration:
   ```sql
   CREATE UNIQUE INDEX ON "transaction" ("transactionId")
   WHERE status NOT IN ('CANCELED', 'REJECTED', 'ARCHIVED');
   ```
   And add `@Index({ unique: true })` (or a partial unique index via a migration) to the entity.

2. **Move the uniqueness check inside the database transaction** so the `SELECT` and `INSERT` share the same transaction scope, ideally at `SERIALIZABLE` or `REPEATABLE READ` isolation level.

3. **Handle the stuck-record case in `_executeTransaction`**: When `isDuplicate` is true and the row is a different DB record from the one that succeeded (i.e., not a multi-pod re-submission of the same row), update its status to `FAILED` or a new `DUPLICATE` terminal state rather than silently returning `null`.

## Proof of Concept
```
1. User A submits POST /transactions with transactionId = "0.0.1@1716577920.000000000"
   → Server returns 201 with transactionId in response body.

2. Attacker (User B) crafts Hedera transaction bytes embedding the same transactionId,
   signs them with their own registered key (passes publicKey.verify),
   and submits POST /transactions concurrently with User A's request.

3. Both requests execute repo.find() [line 415] before either INSERT commits.
   Both find zero existing records. Both proceed past the check.

4. Both entityManager.save() calls [line 458] succeed.
   DB now has two rows with transactionId = "0.0.1@1716577920.000000000".

5. Chain service picks up both rows for execution:
   - Row A executes on Hedera → status updated to EXECUTED.
   - Row B executes on Hedera → receives DUPLICATE_TRANSACTION →
     isDuplicate = true → returns null [line 185] → status NOT updated.

6. Row B remains in WAITING_FOR_EXECUTION permanently.
   Every scheduler cycle repeats step 5 for Row B.
```

### Citations

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L83-84)
```typescript
  @Column()
  transactionId: string;
```

**File:** back-end/typeorm/migrations/1764999592722-InitialSchema.ts (L16-16)
```typescript
        await queryRunner.query(`CREATE TABLE IF NOT EXISTS "transaction" ("id" SERIAL NOT NULL, "name" character varying(50) NOT NULL, "type" character varying NOT NULL, "description" character varying(256) NOT NULL, "transactionId" character varying NOT NULL, "transactionHash" character varying NOT NULL, "transactionBytes" bytea NOT NULL, "unsignedTransactionBytes" bytea NOT NULL, "status" character varying NOT NULL, "statusCode" integer, "signature" bytea NOT NULL, "validStart" TIMESTAMP NOT NULL, "mirrorNetwork" character varying NOT NULL, "isManual" boolean NOT NULL DEFAULT false, "cutoffAt" TIMESTAMP, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "executedAt" TIMESTAMP, "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), "deletedAt" TIMESTAMP, "creatorKeyId" integer, CONSTRAINT "PK_89eadb9 ... (truncated)
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

**File:** back-end/libs/common/src/execute/execute.service.ts (L41-42)
```typescript
  @MurLock(15000, 'transaction.id')
  async executeTransaction(transaction: Transaction) {
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
