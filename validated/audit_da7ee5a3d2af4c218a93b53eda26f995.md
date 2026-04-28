### Title
`createTransactionApprovers` passes original DTO instead of modified copy, silently discarding the `threshold: null` override for leaf-node approvers

---

### Summary

In `approvers.service.ts`, the `createTransactionApprovers` function builds a corrected copy of each nested approver DTO (`nestedApprover`) and conditionally sets its `threshold` to `null` for leaf nodes. However, the actual recursive call to `createApprover` spreads the **original** `nestedDtoApprover` instead of the corrected `nestedApprover`. The modified copy is dead code and the `threshold: null` fix is never applied — a direct structural analog to the Hats Protocol bug.

---

### Finding Description

Inside `createTransactionApprovers`, after inserting a parent approver, the code iterates over its children:

```typescript
if (dtoApprover.approvers) {
  for (const nestedDtoApprover of dtoApprover.approvers) {
    const nestedApprover = { ...nestedDtoApprover, listId: approver.id }; // ← corrected copy

    if (!nestedDtoApprover.approvers || nestedDtoApprover.approvers.length === 0) {
      nestedApprover.threshold = null; // ← intended fix: leaf nodes must not carry a threshold
    }

    await createApprover({ ...nestedDtoApprover, listId: approver.id }); // ← BUG: spreads original, not nestedApprover
  }
}
``` [1](#0-0) 

`nestedApprover` is constructed and mutated but **never passed anywhere**. The call on line 348 re-spreads `nestedDtoApprover` from scratch, so the `threshold: null` assignment on line 345 has zero effect.

The validation guard that this fix was meant to bypass is:

```typescript
/* Check if the approver has children when there is threshold */
if (
  typeof dtoApprover.threshold === 'number' &&
  (!dtoApprover.approvers || dtoApprover.approvers.length === 0)
)
  throw new Error(this.CHILDREN_REQUIRED);
``` [2](#0-1) 

Because the threshold is never nulled out, any nested leaf-node approver whose DTO carries a non-null `threshold` will hit this guard and throw `CHILDREN_REQUIRED`, aborting the entire transaction-wrapped creation of the approver tree.

---

### Impact Explanation

When a caller submits a nested approver tree where a leaf node (no `approvers` children) has a `threshold` value set in the DTO, the entire `createTransactionApprovers` call fails with a `BadRequestException`. The whole tree — including correctly-formed parent nodes — is rolled back inside the database transaction. No approver structure is persisted, leaving the transaction without any approval gate. Depending on the client, this can be triggered repeatedly, permanently preventing approver assignment for that transaction.

---

### Likelihood Explanation

The endpoint is reachable by any authenticated transaction creator. The bug is triggered whenever a client sends a nested approver DTO that includes a `threshold` field on a leaf node — a plausible scenario when a frontend or API consumer copies a parent-node DTO shape for a child node. The `nestedApprover` variable being entirely unused is a deterministic code defect, not a race condition or edge case.

---

### Recommendation

Replace the original spread in the `createApprover` call with the already-corrected `nestedApprover` object:

```diff
- await createApprover({ ...nestedDtoApprover, listId: approver.id });
+ await createApprover(nestedApprover);
``` [3](#0-2) 

---

### Proof of Concept

1. Create a transaction as an authenticated user.
2. Call the "create approvers" endpoint with a payload like:
   ```json
   {
     "approversArray": [{
       "threshold": 1,
       "approvers": [
         { "userId": 1, "threshold": 99 }
       ]
     }]
   }
   ```
   The leaf node `{ "userId": 1, "threshold": 99 }` has no `approvers` children but carries a `threshold`.
3. Observe: the code at line 344 sets `nestedApprover.threshold = null`, but line 348 calls `createApprover({ ...nestedDtoApprover, listId: approver.id })` — passing `threshold: 99` unchanged.
4. The guard at lines 296–300 fires (`CHILDREN_REQUIRED`), the database transaction rolls back, and a `400 BadRequestException` is returned.
5. No approver tree is stored. The transaction is left without an approval structure. [4](#0-3)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L295-300)
```typescript
          /* Check if the approver has children when there is threshold */
          if (
            typeof dtoApprover.threshold === 'number' &&
            (!dtoApprover.approvers || dtoApprover.approvers.length === 0)
          )
            throw new Error(this.CHILDREN_REQUIRED);
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
