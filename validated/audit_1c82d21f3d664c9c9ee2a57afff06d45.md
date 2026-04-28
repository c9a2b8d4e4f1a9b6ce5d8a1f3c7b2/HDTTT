### Title
Unguarded Subtraction in Approver Tree Threshold Update Enables Permanent Approval Freeze

### Summary
In `back-end/apps/api/src/transactions/approvers/approvers.service.ts`, the `updateTransactionApprover` function computes `parent.approvers.length - 1` without a lower-bound guard and without row-level locking. Under concurrent requests from the same transaction creator, two database transactions can both read the same stale `parent.approvers` snapshot, each subtract 1, and both skip the soft-delete branch — leaving the parent node with 0 children but a non-zero threshold. The approval requirement becomes permanently unsatisfiable, freezing the transaction.

### Finding Description
When a child approver's `listId` is set to `null` (detached from its parent), the code reads the parent with its `approvers` relation and computes the new child count: [1](#0-0) 

```
const newParentApproversLength = parent.approvers.length - 1;   // line 418

if (newParentApproversLength === 0) {
    await transactionalEntityManager.softRemove(...)             // line 422
} else if (newParentApproversLength < parent.threshold) {
    await transactionalEntityManager.update(..., {
        threshold: newParentApproversLength,                     // line 426
    });
}
```

The outer `dataSource.transaction()` uses the default PostgreSQL `READ COMMITTED` isolation level. Two concurrent requests both read `parent.approvers` before either commits. Consider a parent with `threshold = 1` and children `[A, B]`:

1. Request-1 reads `parent.approvers.length = 2`, computes `newParentApproversLength = 1`.
2. Request-2 reads `parent.approvers.length = 2`, computes `newParentApproversLength = 1`.
3. Both evaluate `1 === 0` → false; `1 < 1` → false. Neither soft-deletes nor adjusts the threshold.
4. Both detach their respective child. Parent now has **0 children, threshold = 1**.

The parent approver node is permanently stuck: it requires 1 approval but has no approvers attached to it.

There is also no guard preventing `parent.approvers.length` from being 0 before the subtraction, which would produce `newParentApproversLength = -1`, pass the `< parent.threshold` check, and write `-1` as the threshold — an invalid sentinel value that downstream approval-checking logic does not handle. [2](#0-1) 

### Impact Explanation
A transaction whose approver tree is corrupted this way can never reach `WAITING_FOR_EXECUTION` status. Any organization transaction that requires approvals is permanently blocked. The creator cannot delete and recreate the approver tree because the parent node still exists (not soft-deleted) and the duplicate-check (`isNode`) will reject re-creation. The transaction is effectively frozen and must be manually cancelled, losing any work already done by signers.

### Likelihood Explanation
The attacker is the transaction creator — a normal, unprivileged user. The creator has full legitimate access to the `PATCH /transactions/:id/approvers/:approverId` endpoint. Sending two concurrent HTTP requests (e.g., via a script or browser DevTools) is trivially achievable. No special timing precision is required because both requests execute the same read-then-write pattern under `READ COMMITTED`, making the race window wide.

### Recommendation
1. **Add a lower-bound guard** before the subtraction:
   ```typescript
   if (parent.approvers.length === 0) {
     // data inconsistency — log and return
     return approver;
   }
   const newParentApproversLength = parent.approvers.length - 1;
   ```
2. **Use a pessimistic lock** when reading the parent to serialize concurrent updates:
   ```typescript
   const parent = await transactionalEntityManager.findOne(TransactionApprover, {
     relations: ['approvers'],
     where: { id: approver.listId },
     lock: { mode: 'pessimistic_write' },
   });
   ```
3. **Validate the resulting threshold** is `>= 1` before writing it to the database.

### Proof of Concept

**Setup:** Transaction creator builds an approver tree — one parent node (threshold = 1) with two leaf children (user A, user B).

**Attack:**
```bash
# Send both requests simultaneously
curl -X PATCH .../transactions/42/approvers/10 \
  -d '{"listId": null}' -H "Authorization: Bearer <creator_token>" &

curl -X PATCH .../transactions/42/approvers/11 \
  -d '{"listId": null}' -H "Authorization: Bearer <creator_token>" &

wait
```

**Expected (correct) outcome:** After both children are detached, the parent (0 children) is soft-deleted.

**Actual outcome:** Both requests read `parent.approvers.length = 2`, compute `newParentApproversLength = 1`, skip both branches, and commit. The parent node remains in the database with `threshold = 1` and 0 children. The transaction's approval requirement can never be met. The transaction is permanently frozen. [3](#0-2)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L403-431)
```typescript
            const parent = await transactionalEntityManager.findOne(TransactionApprover, {
              relations: ['approvers'],
              where: { id: approver.listId },
            });

            /* Set the list id to null and set the transaction id */
            await transactionalEntityManager.update(TransactionApprover, approver.id, {
              listId: null,
              transactionId: rootNode.transactionId,
            });
            approver.listId = null;
            approver.transactionId = rootNode.transactionId;
            updated = true;

            if (parent) {
              const newParentApproversLength = parent.approvers.length - 1;

              /* Soft delete the parent if there are no more children */
              if (newParentApproversLength === 0) {
                await transactionalEntityManager.softRemove(TransactionApprover, parent);
              } else if (newParentApproversLength < parent.threshold) {
                /* Update the parent threshold if the current one is more than the children */
                await transactionalEntityManager.update(TransactionApprover, parent.id, {
                  threshold: newParentApproversLength,
                });
              }
            }

            return approver;
```
