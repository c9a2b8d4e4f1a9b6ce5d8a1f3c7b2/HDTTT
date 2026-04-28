I have verified all referenced code against the actual repository. Here is my assessment:

---

Audit Report

## Title
`isApproved` Rejection Logic Incorrectly Marks Threshold Approver Groups as Rejected with Small Thresholds, Enabling a Single Approver to Suppress Multi-Party Approval

## Summary
The `isApproved` function in `front-end/src/renderer/utils/sdk/index.ts` uses a mathematically incorrect condition to determine definitive rejection of a threshold approver group. When `rejections.length >= threshold`, the function returns `false` (rejected), even when enough un-voted approvers remain to satisfy the threshold. This causes the UI to display a false terminal "rejected" state for groups that are still pending, materially disrupting the multi-party approval workflow.

## Finding Description

The root cause is at line 357 of `front-end/src/renderer/utils/sdk/index.ts`:

```typescript
return rejections.length >= (approver.threshold || rejections.length) ? false : null;
``` [1](#0-0) 

The condition `rejections.length >= threshold` is the wrong predicate for *definitive* rejection. A threshold group can only be definitively rejected when it is mathematically impossible to reach the threshold — i.e., when `(total_approvers - rejections.length) < threshold`. The current code instead marks the group as rejected as soon as the rejection count equals the threshold, regardless of how many approvers have not yet voted.

**Concrete trace — 1-of-3 threshold group (A rejects, B and C pending):**

- `approvals.length = 0`, `rejections.length = 1`, `threshold = 1`, `total = 3`
- Line 354: `0 >= (1 || 0)` → `false` — not yet approved (correct)
- Line 357: `1 >= (1 || 1)` → `true` → returns `false` — **definitively rejected (wrong)**
- Correct answer: `(3 - 1) < 1` → `2 < 1` → `false` → return `null` (still pending)

The correct rejection guard is:
```typescript
const remaining = approver.approvers.length - rejections.length;
if (remaining < (approver.threshold ?? approver.approvers.length)) return false;
return null;
```

The `ITransactionApprover` interface confirms `threshold` is a plain optional number, making any value ≥ 1 and < child count a valid small threshold: [2](#0-1) 

The backend enforces `threshold ≥ 1` and `threshold ≤ approvers.length`, confirming threshold=1 with N>1 approvers is a fully valid, server-accepted configuration: [3](#0-2) 

The incorrect `false` return propagates into every UI component consuming `isApproved`:

- `ReadOnlyApproversList.vue` applies `bg-danger` (red badge) when `isApproved(approver) === false`: [4](#0-3) 

- `ApproverStructureStatus.vue` renders a red X icon (`bi-x-lg text-danger`) when `isApproved(approver) === false`: [5](#0-4) 

## Impact Explanation

Any organization using a threshold approver group where `threshold < total_approvers` (e.g., 1-of-3, 2-of-5) is affected. When a single approver in such a group rejects, the UI immediately displays the entire approval group as definitively rejected — red badge in `ReadOnlyApproversList.vue` and a red X icon in `ApproverStructureStatus.vue`. Other approvers who have not yet voted see a terminal "rejected" state and are likely to conclude no further action is needed, effectively suppressing the approval process. The transaction remains stuck in a state where the backend has not actually rejected it (it remains in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`), but the UI presents it as rejected — a soft-lock of the multi-party approval workflow. This materially disrupts the platform's core approval functionality, which is not excluded under SECURITY.md's "UX and UI impacts that do not materially disrupt use of the platform" carve-out.

## Likelihood Explanation

The actor is a **malicious normal user** who is a legitimate member of a threshold approver group. No privileged access is required. The exploit requires only submitting a rejection via the standard `POST /approvers/:id/approve` endpoint with `approved: false`: [6](#0-5) 

Threshold approver groups with small thresholds (e.g., 1-of-N) are a natural and common configuration for organizations that want any one of several designated approvers to be able to unblock a transaction. The backend validates and accepts such configurations without restriction.

## Recommendation

Replace the rejection condition at line 357 with the mathematically correct impossibility check:

```typescript
// Before (incorrect):
return rejections.length >= (approver.threshold || rejections.length) ? false : null;

// After (correct):
const threshold = approver.threshold ?? approver.approvers.length;
const remaining = approver.approvers.length - rejections.length;
return remaining < threshold ? false : null;
```

This ensures the group is only marked as definitively rejected when it is impossible for the remaining un-voted approvers to satisfy the threshold.

## Proof of Concept

Given a threshold approver group configured as 1-of-3 (threshold=1, approvers=[A, B, C]):

1. Approver A calls `POST /transactions/:id/approvers/:approverId/approve` with `{ approved: false, ... }`.
2. The backend records A's rejection. B and C remain with `approved = null`.
3. The frontend fetches the approver tree and calls `isApproved({ threshold: 1, approvers: [{ approved: false }, { approved: null }, { approved: null }] })`.
4. `approvals.length = 0`, `rejections.length = 1`.
5. Line 354: `0 >= 1` → `false` (not approved).
6. Line 357: `1 >= (1 || 1)` → `true` → returns `false`.
7. `ReadOnlyApproversList.vue` renders the group with `bg-danger`; `ApproverStructureStatus.vue` renders `bi-x-lg text-danger`.
8. Approvers B and C see a red "rejected" badge on the group and conclude the transaction has been rejected, taking no further action.
9. The transaction remains in `WAITING_FOR_SIGNATURES` on the backend indefinitely, never reaching approval despite the threshold being satisfiable.

### Citations

**File:** front-end/src/renderer/utils/sdk/index.ts (L351-358)
```typescript
  if (approver.approvers) {
    const approvals = approver.approvers.filter(approver => isApproved(approver) === true);
    const rejections = approver.approvers.filter(approver => isApproved(approver) === false);
    if (approvals.length >= (approver.threshold || approvals.length)) {
      return true;
    }
    return rejections.length >= (approver.threshold || rejections.length) ? false : null;
  }
```

**File:** front-end/src/shared/interfaces/organization/approvers/index.ts (L6-14)
```typescript
export interface ITransactionApprover extends IBaseTransactionApprover {
  listId?: number;
  threshold?: number;
  userId?: number;
  userKeyId?: number;
  signature?: string;
  approved?: boolean;
  approvers?: ITransactionApprover[];
}
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L302-307)
```typescript
          /* Check if the approver threshold is less or equal to the number of approvers */
          if (
            dtoApprover.approvers &&
            (dtoApprover.threshold > dtoApprover.approvers.length || dtoApprover.threshold === 0)
          )
            throw new Error(this.THRESHOLD_LESS_OR_EQUAL_APPROVERS(dtoApprover.approvers.length));
```

**File:** front-end/src/renderer/components/Approvers/ReadOnlyApproversList.vue (L40-43)
```vue
            :class="{
              'bg-success': isApproved(approver) === true,
              'bg-danger': isApproved(approver) === false,
            }"
```

**File:** front-end/src/renderer/components/Approvers/ApproverStructureStatus.vue (L19-20)
```vue
      <span v-if="isApproved(approver) === true" class="bi bi-check-lg text-success"></span>
      <span v-if="isApproved(approver) === false" class="bi bi-x-lg text-danger"></span>
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L65-73)
```typescript
  @Post('/approve')
  @OnlyOwnerKey<ApproverChoiceDto>('userKeyId')
  approveTransaction(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() body: ApproverChoiceDto,
  ): Promise<boolean> {
    return this.approversService.approveTransaction(body, transactionId, user);
  }
```
