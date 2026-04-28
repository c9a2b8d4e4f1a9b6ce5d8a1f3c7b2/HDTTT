All claims check out against the actual code. Here is the audit report:

---

Audit Report

## Title
Missing Lower-Bound Validation on `threshold` in `CreateTransactionApproverDto` Allows Negative Threshold Storage

## Summary
The `threshold` field in `CreateTransactionApproverDto` has no `@Min(1)` constraint, while the equivalent `UpdateTransactionApproverDto` does. The service-level guard only rejects `threshold === 0` and `threshold > approvers.length`, so a negative value such as `-1` passes every check and is persisted to the database, permanently satisfying any downstream `approvedCount >= threshold` comparison.

## Finding Description

**DTO layer — missing lower-bound constraint**

`CreateTransactionApproverDto.threshold` carries only `@IsNumber()` and `@IsOptional()`: [1](#0-0) 

`UpdateTransactionApproverDto.threshold` correctly applies `@Min(1)`: [2](#0-1) 

The protection is inconsistently applied: the update path is guarded, the create path is not.

**Service layer — guard does not cover negative values**

The only runtime threshold check in `createTransactionApprovers` is: [3](#0-2) 

For `threshold = -1` with two child approvers:
```
(-1 > 2 || -1 === 0)  →  (false || false)  →  false
```
No exception is thrown.

**`validateApprover` also passes**

The empty-approver guard treats `threshold === 0` as "missing", but `-1` is not `0`, so the check passes: [4](#0-3) 

**Database write persists the negative value**

Because `-1` is truthy in JavaScript (only `0` is falsy among numbers), the expression `dtoApprover.threshold && dtoApprover.approvers` evaluates to truthy, and `-1` is written to the database: [5](#0-4) 

## Impact Explanation
A stored `threshold` of `-1` violates the invariant `1 ≤ threshold ≤ child_count` that the approval-tree evaluation relies on. Any downstream logic computing `approvedCount >= threshold` will treat the condition as permanently satisfied (every integer ≥ −1), allowing a transaction to advance through the approval workflow with zero actual approvals. A creator can self-approve a transaction that is supposed to require multi-party approval.

## Likelihood Explanation
The attacker only needs a valid account and the ability to create a transaction — both are standard, unprivileged operations available to every registered user. The payload is a single crafted JSON body with no special timing, race condition, or external dependency required.

## Recommendation
Add `@Min(1)` to the `threshold` field in `CreateTransactionApproverDto`, mirroring the constraint already present in `UpdateTransactionApproverDto`:

```typescript
// create-transaction-approver.dto.ts
import { IsArray, IsNumber, IsOptional, Min, ValidateNested, ArrayMinSize } from 'class-validator';

@IsNumber()
@Min(1)
@IsOptional()
threshold?: number;
```

Additionally, update the service-level guard to use `< 1` instead of `=== 0` as a defence-in-depth measure:

```typescript
// approvers.service.ts  line 305
(dtoApprover.threshold > dtoApprover.approvers.length || dtoApprover.threshold < 1)
```

## Proof of Concept

```http
POST /transactions/42/approvers
Authorization: Bearer <valid_user_token>
Content-Type: application/json

{
  "approversArray": [{
    "threshold": -1,
    "approvers": [{"userId": 2}, {"userId": 3}]
  }]
}
```

**Step-by-step:**
1. DTO validation passes — `@IsNumber()` accepts `-1`; no `@Min(1)` exists.
2. `validateApprover` passes — `-1 !== 0`, so the approver is not considered empty.
3. `CHILDREN_REQUIRED` check passes — `typeof -1 === 'number'` and approvers array is non-empty.
4. Threshold guard passes — `-1 > 2` is `false` and `-1 === 0` is `false`.
5. `threshold: -1` is persisted because `-1` is truthy in JavaScript.
6. Any subsequent `approvedCount >= -1` check is permanently satisfied, bypassing multi-party approval.

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts (L9-11)
```typescript
  @IsNumber()
  @IsOptional()
  threshold?: number;
```

**File:** back-end/apps/api/src/transactions/dto/update-transaction-approver.dto.ts (L8-11)
```typescript
  @IsNumber()
  @Min(1)
  @IsOptional()
  threshold?: number;
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L313-314)
```typescript
            threshold:
              dtoApprover.threshold && dtoApprover.approvers ? dtoApprover.threshold : null,
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L692-699)
```typescript
  private validateApprover(approver: CreateTransactionApproverDto): void {
    if (
      (approver.listId === null || isNaN(approver.listId)) &&
      (approver.threshold === null || isNaN(approver.threshold) || approver.threshold === 0) &&
      (approver.userId === null || isNaN(approver.userId)) &&
      (!approver.approvers || approver.approvers.length === 0)
    )
      throw new BadRequestException(this.CANNOT_CREATE_EMPTY_APPROVER);
```
