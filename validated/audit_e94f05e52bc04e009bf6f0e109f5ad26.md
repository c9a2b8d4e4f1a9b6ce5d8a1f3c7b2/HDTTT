Audit Report

## Title
Missing Tree-Node Existence Check in `isNode` Allows Duplicate Approval Trees, Corrupting Transaction Approval State

## Summary
`ApproversService.isNode()` is the sole server-side guard against duplicate approver entries. Its return expression unconditionally evaluates to `false` for any threshold/tree node (any approver without a `userId`), because the second operand of the `&&` is `typeof approver.userId === 'number'`, which is always `false` for tree nodes. As a result, any authenticated transaction creator can call `POST /transactions/:id/approvers` repeatedly with the same threshold tree body and each call inserts a fully-duplicated tree into the database.

## Finding Description

**Root cause — `isNode` ignores tree nodes**

The function builds a correct database query to locate an existing tree node, but its return expression is logically broken for threshold nodes:

```typescript
const count = await (entityManager || this.repo).count(TransactionApprover, find);
return count > 0 && typeof approver.userId === 'number';
``` [1](#0-0) 

For a threshold/tree node, `approver.userId` is `undefined` or `null`, so `typeof approver.userId === 'number'` is always `false`. The `&&` short-circuits to `false` regardless of whether `count > 0`. The function was clearly intended to return `count > 0` for all node types, but the extra condition restricts it to user-leaf nodes only.

**Exploit path in `createTransactionApprovers`**

The only duplicate check before insertion is:

```typescript
if (await this.isNode(dtoApprover, transactionId, transactionalEntityManager))
  throw new Error(this.APPROVER_ALREADY_EXISTS);
``` [2](#0-1) 

Because `isNode` returns `false` for tree nodes, the guard never fires. The tree node is inserted, and the recursive loop then creates child leaf nodes under the new parent id. Since child nodes reference the newly-inserted parent id (which is unique per insertion), `isNode` also returns `false` for each child (no existing record has that new `listId`), so the entire tree is cloned without error. [3](#0-2) 

**No database-level unique constraint prevents this**

The `TransactionApprover` entity carries only non-unique indexes on `transactionId` and `userId`. There is no composite unique constraint on `(transactionId, threshold, userId, listId)` or any equivalent, so the database silently accepts duplicate rows. [4](#0-3) 

## Impact Explanation

1. **Data corruption**: Each repeated `POST /transactions/:id/approvers` call with a threshold-tree body inserts a fully-duplicated tree of rows into `transaction_approver`. These ghost rows cannot be removed without individually calling `removeTransactionApprover` for each duplicate root node.

2. **Notification storm**: Every successful `createTransactionApprovers` call emits `emitTransactionStatusUpdate`, flooding all observers and signers with spurious events. [5](#0-4) 

3. **Approval-status degradation**: With a large number of duplicate trees, the recursive `getApproversByTransactionId` CTE query and any downstream `isApproved` traversal must process an exponentially growing number of rows, which can cause query timeouts or incorrect status computation, leaving the transaction stuck in `WAITING_FOR_SIGNATURES` with no self-service recovery path.

Note: In the simple case (small number of duplicates), `approveTransaction` bulk-updates all user-leaf records simultaneously via `whereInIds`, so the transaction is not permanently stalled. The stall risk is realistic only under deliberate large-scale duplication. [6](#0-5) 

## Likelihood Explanation

- **Attacker profile**: Any authenticated user who has created a transaction. No admin or privileged role is required.
- **Trigger**: Call `POST /transactions/:id/approvers` with the same threshold-tree body more than once. The only server-side guard is `isNode`, which is broken for tree nodes.
- **Realistic scenario**: A malicious or buggy client retries the approver-creation request (e.g., on network timeout), or a user deliberately submits the same tree repeatedly to corrupt the approval state of a multi-party transaction.

## Recommendation

Fix the return expression in `isNode` to return `count > 0` unconditionally, covering both user-leaf nodes and threshold/tree nodes:

```typescript
// Before (broken for tree nodes):
return count > 0 && typeof approver.userId === 'number';

// After (correct for all node types):
return count > 0;
``` [1](#0-0) 

Additionally, add a composite unique index on `transaction_approver` covering `(transactionId, userId, threshold, listId)` as a defense-in-depth measure to prevent duplicate rows at the database level, similar to the existing unique index on `TransactionObserver`.

## Proof of Concept

1. Authenticate as a user who is the creator of transaction with `id = 1`.
2. Send the following request twice:
```
POST /transactions/1/approvers
{
  "approversArray": [
    {
      "threshold": 1,
      "approvers": [
        { "userId": 2 },
        { "userId": 3 }
      ]
    }
  ]
}
```
3. After the first call, the database contains one root threshold node (e.g., `id=1`, `transactionId=1`, `threshold=1`) and two leaf nodes (`id=2`, `listId=1`, `userId=2`) and (`id=3`, `listId=1`, `userId=3`).
4. On the second call, `isNode` is invoked for the root threshold node. The DB query finds `count=1` (the existing root), but `typeof approver.userId === 'number'` is `false` (no `userId` on a threshold node), so `isNode` returns `false`. The guard does not throw. A second root node is inserted (`id=4`), and two more leaf nodes are inserted under it (`id=5`, `id=6`).
5. The `transaction_approver` table now contains 6 rows for a transaction that should have 3, with no way to distinguish originals from duplicates via the API. [7](#0-6)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L250-251)
```typescript
          if (await this.isNode(dtoApprover, transactionId, transactionalEntityManager))
            throw new Error(this.APPROVER_ALREADY_EXISTS);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L340-350)
```typescript
          if (dtoApprover.approvers) {
            for (const nestedDtoApprover of dtoApprover.approvers) {
              const nestedApprover = { ...nestedDtoApprover, listId: approver.id };

              if (!nestedDtoApprover.approvers || nestedDtoApprover.approvers.length === 0) {
                nestedApprover.threshold = null;
              }

              await createApprover({ ...nestedDtoApprover, listId: approver.id });
            }
          }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L358-358)
```typescript
      emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transactionId  }]);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L600-609)
```typescript
      await transactionalEntityManager
        .createQueryBuilder()
        .update(TransactionApprover)
        .set({
          userKeyId: dto.userKeyId,
          signature: dto.signature,
          approved: dto.approved,
        })
        .whereInIds(userApprovers.map(a => a.id))
        .execute();
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

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L17-20)
```typescript
@Entity()
@Index(['transactionId'])
@Index(['userId'])
export class TransactionApprover {
```
