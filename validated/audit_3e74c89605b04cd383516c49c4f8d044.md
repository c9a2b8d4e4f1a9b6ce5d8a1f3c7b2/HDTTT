### Title
`isNode` Duplicate Check Bypassed for Threshold-Type Approver Nodes Allows Corrupted Approval Tree

### Summary
In `ApproversService.isNode()`, the duplicate-existence check unconditionally returns `false` for any approver node that lacks a `userId` (i.e., threshold/list nodes). A transaction creator can therefore call `POST /transactions/:id/approvers` multiple times with identical threshold-node payloads, inserting duplicate rows into `transaction_approver` with no error. There is no database-level unique constraint to catch this either. The resulting corrupted approval tree can make a transaction permanently un-approvable or cause incorrect approval-status computation.

### Finding Description

`isNode` is the sole guard against duplicate approver nodes before insertion: [1](#0-0) 

The critical flaw is the final return expression:

```typescript
return count > 0 && typeof approver.userId === 'number';
```

For a threshold node (`userId` is `undefined`), `typeof approver.userId === 'number'` is always `false`, so `isNode` always returns `false` regardless of whether a matching row already exists in the database. The guard at the call site therefore never fires for threshold nodes: [2](#0-1) 

The `transaction_approver` table has no unique constraint on `(transactionId, threshold, listId)` — only a serial primary key — so the database provides no safety net: [3](#0-2) 

The later migration that adds indexes for `transaction_observer` adds a `UNIQUE INDEX` on `(userId, transactionId)` for observers, but adds no equivalent uniqueness constraint for `transaction_approver`: [4](#0-3) 

The `TransactionObserver` entity itself also carries a `@Index(['userId', 'transactionId'], { unique: true })` decorator, but `TransactionApprover` has no analogous protection: [5](#0-4) 

### Impact Explanation

When a duplicate threshold node is inserted, each copy receives its own set of child rows (because children are created with `listId: approver.id` pointing to the newly inserted parent): [6](#0-5) 

The approval-status logic (frontend `isApproved`, and the recursive CTE used in `getTransactionsToApprove`) traverses the full tree. With duplicate subtrees, the transaction may require approvals from both copies of the same logical group, making it impossible to reach the "approved" state even when all intended approvers have signed. Alternatively, if the duplicate subtrees have different thresholds, the effective approval requirement diverges silently from what the creator intended. [7](#0-6) 

### Likelihood Explanation

The `createTransactionApprovers` endpoint is restricted to the transaction creator: [8](#0-7) 

Any authenticated user who creates a transaction can trigger this — no admin privilege is required. The creator can send two sequential `POST /transactions/:id/approvers` requests with an identical threshold-node payload (or include the same threshold node twice in a single `approversArray`). No special race condition or exploit chain is needed; the bug is reachable through normal API usage.

### Recommendation

Fix the return expression in `isNode` to also flag duplicate threshold nodes:

```typescript
// Before (broken for threshold nodes):
return count > 0 && typeof approver.userId === 'number';

// After (covers both user and threshold nodes):
return count > 0;
```

Additionally, add a partial unique index at the database level to enforce uniqueness for root threshold nodes:

```sql
CREATE UNIQUE INDEX ON transaction_approver (transactionId, threshold)
  WHERE userId IS NULL AND listId IS NULL AND deletedAt IS NULL;
```

And add the corresponding `@Index` decorator to the `TransactionApprover` entity, mirroring the pattern already used for `TransactionObserver`. [9](#0-8) 

### Proof of Concept

1. User A creates a transaction (becomes the creator).
2. User A calls `POST /transactions/1/approvers` with:
   ```json
   { "approversArray": [{ "threshold": 2, "approvers": [{"userId": 10}, {"userId": 11}] }] }
   ```
3. User A calls the same endpoint again with the identical payload.
4. Both calls succeed with HTTP 201. Two identical threshold nodes (each with their own copies of userId-10 and userId-11 children) now exist in `transaction_approver`.
5. Users 10 and 11 both approve — satisfying the first subtree — but the second duplicate subtree remains unsatisfied.
6. The transaction is stuck in `WAITING_FOR_EXECUTION` indefinitely; the approval-status query counts the second subtree as pending and never transitions the transaction. [10](#0-9)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L239-239)
```typescript
    await this.getCreatorsTransaction(transactionId, user);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L249-251)
```typescript
          /* Check if the approver already exists */
          if (await this.isNode(dtoApprover, transactionId, transactionalEntityManager))
            throw new Error(this.APPROVER_ALREADY_EXISTS);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L332-337)
```typescript
          /* Create approver */
          const approver = transactionalEntityManager.create(TransactionApprover, data);

          /* Insert approver */
          await transactionalEntityManager.insert(TransactionApprover, approver);
          approvers.push(approver);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L340-349)
```typescript
          if (dtoApprover.approvers) {
            for (const nestedDtoApprover of dtoApprover.approvers) {
              const nestedApprover = { ...nestedDtoApprover, listId: approver.id };

              if (!nestedDtoApprover.approvers || nestedDtoApprover.approvers.length === 0) {
                nestedApprover.threshold = null;
              }

              await createApprover({ ...nestedDtoApprover, listId: approver.id });
            }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L647-665)
```typescript
  async isNode(
    approver: CreateTransactionApproverDto,
    transactionId: number,
    entityManager?: EntityManager,
  ) {
    const find: FindManyOptions<TransactionApprover> = {
      where: {
        listId: typeof approver.listId === 'number' ? approver.listId : null,
        userId: typeof approver.userId === 'number' ? approver.userId : null,
        threshold:
          typeof approver.threshold === 'number' && approver.threshold !== 0
            ? approver.threshold
            : null,
        transactionId: typeof approver.listId === 'number' ? null : transactionId,
      },
    };

    const count = await (entityManager || this.repo).count(TransactionApprover, find);
    return count > 0 && typeof approver.userId === 'number';
```

**File:** back-end/typeorm/migrations/1764999592722-InitialSchema.ts (L7-7)
```typescript
        await queryRunner.query(`CREATE TABLE IF NOT EXISTS "transaction_approver" ("id" SERIAL NOT NULL, "transactionId" integer, "listId" integer, "threshold" integer, "userKeyId" integer, "signature" bytea, "userId" integer, "approved" boolean, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), "deletedAt" TIMESTAMP, CONSTRAINT "PK_d6d9eeb7f5b3590e3a20888463e" PRIMARY KEY ("id"))`);
```

**File:** back-end/typeorm/migrations/1768289349311-IndexFixesForCaching.ts (L47-52)
```typescript
        await queryRunner.query(`CREATE INDEX "IDX_b5401848ee318619792d9ead12" ON "transaction_approver" ("userId") `);
        await queryRunner.query(`CREATE INDEX "IDX_f68cf6105a89f541285e9095f4" ON "transaction_approver" ("transactionId") `);
        await queryRunner.query(`CREATE INDEX "IDX_953ae2424ce25d5db80bd2bb5e" ON "transaction_group_item" ("transactionId", "groupId") `);
        await queryRunner.query(`CREATE INDEX "IDX_adbc3bb6e05cc969fa33da99de" ON "transaction_observer" ("userId") `);
        await queryRunner.query(`CREATE INDEX "IDX_e4c900dabed404bf1348a0764c" ON "transaction_observer" ("transactionId") `);
        await queryRunner.query(`CREATE UNIQUE INDEX "IDX_8c6100299f3f937ced4a74c2be" ON "transaction_observer" ("userId", "transactionId") `);
```

**File:** back-end/libs/common/src/database/entities/transaction-observer.entity.ts (L19-22)
```typescript
@Entity()
@Index(['userId', 'transactionId'], { unique: true })
@Index(['transactionId'])
@Index(['userId'])
```

**File:** front-end/src/renderer/utils/sdk/index.ts (L342-358)
```typescript
export const isApproved = (approver: ITransactionApprover): boolean | null => {
  if (approver.approved === false) {
    return false;
  }

  if (approver.approved === true) {
    return true;
  }

  if (approver.approvers) {
    const approvals = approver.approvers.filter(approver => isApproved(approver) === true);
    const rejections = approver.approvers.filter(approver => isApproved(approver) === false);
    if (approvals.length >= (approver.threshold || approvals.length)) {
      return true;
    }
    return rejections.length >= (approver.threshold || rejections.length) ? false : null;
  }
```
