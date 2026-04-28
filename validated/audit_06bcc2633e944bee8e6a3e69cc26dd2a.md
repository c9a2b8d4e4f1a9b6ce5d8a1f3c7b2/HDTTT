I have all the information needed. Let me verify the `TransactionObserver` entity decorator claim quickly.

All claims are verified against the actual code. Here is the audit report:

---

Audit Report

## Title
`isNode` Duplicate Check Bypassed for Threshold-Type Approver Nodes Allows Corrupted Approval Tree

## Summary
`ApproversService.isNode()` unconditionally returns `false` for any approver node that lacks a `userId` (i.e., threshold/list nodes), because the return expression short-circuits on `typeof approver.userId === 'number'`. A transaction creator can therefore call `POST /transactions/:id/approvers` multiple times with identical threshold-node payloads, inserting duplicate rows into `transaction_approver` with no error. No database-level unique constraint exists to catch this either. The resulting corrupted approval tree can make a transaction permanently un-approvable or cause incorrect approval-status computation.

## Finding Description

`isNode` is the sole application-layer guard against duplicate approver nodes before insertion: [1](#0-0) 

The critical flaw is the final return expression of `isNode`:

```typescript
return count > 0 && typeof approver.userId === 'number';
```

For a threshold node (`userId` is `undefined`), `typeof approver.userId === 'number'` is always `false`, so `isNode` always returns `false` regardless of whether a matching row already exists in the database. [2](#0-1) 

The `transaction_approver` table is created with only a serial primary key — no unique constraint on `(transactionId, threshold, listId)` — so the database provides no safety net: [3](#0-2) 

The `TransactionApprover` entity carries only non-unique indexes on `transactionId` and `userId`, with no composite uniqueness protection: [4](#0-3) 

By contrast, `TransactionObserver` carries `@Index(['userId', 'transactionId'], { unique: true })`, providing the protection that `TransactionApprover` lacks: [5](#0-4) 

## Impact Explanation

When a duplicate threshold node is inserted, each copy receives its own set of child rows because children are created with `listId: approver.id` pointing to the newly inserted parent: [6](#0-5) 

The approval-status logic traverses the full tree via recursive CTEs. With duplicate subtrees, the transaction may require approvals from both copies of the same logical group, making it impossible to reach the "approved" state even when all intended approvers have signed. Alternatively, if the duplicate subtrees have different thresholds (e.g., after an update), the effective approval requirement diverges silently from what the creator intended.

## Likelihood Explanation

The `createTransactionApprovers` endpoint is restricted to the transaction creator: [7](#0-6) 

Any authenticated user who creates a transaction can trigger this — no admin privilege is required. The creator can send two sequential `POST /transactions/:id/approvers` requests with an identical threshold-node payload, or include the same threshold node twice in a single `approversArray`. No special race condition or exploit chain is needed; the bug is reachable through normal API usage.

## Recommendation

Fix the return expression in `isNode` to not gate on `userId` type:

```typescript
// Before (broken for threshold nodes):
return count > 0 && typeof approver.userId === 'number';

// After (correct for all node types):
return count > 0;
```

Additionally, add a composite unique index on `transaction_approver` for `(transactionId, threshold, listId)` (with appropriate NULL handling) to provide a database-level safety net, mirroring the protection already present on `transaction_observer`.

## Proof of Concept

```
# Step 1: Authenticate as a user who owns transaction ID 1
POST /auth/login  →  { token: "<JWT>" }

# Step 2: Send the same threshold-node payload twice
POST /transactions/1/approvers
Authorization: Bearer <JWT>
Content-Type: application/json
{
  "approversArray": [{
    "threshold": 1,
    "approvers": [{ "userId": 42 }]
  }]
}

# Step 3: Repeat the identical request
POST /transactions/1/approvers
Authorization: Bearer <JWT>
Content-Type: application/json
{
  "approversArray": [{
    "threshold": 1,
    "approvers": [{ "userId": 42 }]
  }]
}

# Result: Two identical threshold-node rows are inserted into transaction_approver,
# each with its own child row for userId=42.
# isNode() returns false for the threshold node on both calls because
# typeof undefined === 'number' is false, bypassing the duplicate guard.
# The approval tree now requires userId=42 to satisfy TWO independent
# threshold groups, making the transaction permanently un-approvable.
```

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

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L17-22)
```typescript
@Entity()
@Index(['transactionId'])
@Index(['userId'])
export class TransactionApprover {
  @PrimaryGeneratedColumn()
  id: number;
```

**File:** back-end/libs/common/src/database/entities/transaction-observer.entity.ts (L19-22)
```typescript
@Entity()
@Index(['userId', 'transactionId'], { unique: true })
@Index(['transactionId'])
@Index(['userId'])
```
