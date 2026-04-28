I need to verify the exact code before rendering a verdict.

All three code layers have been verified. Here is the verdict:

---

## Audit Report

## Title
Missing Lower-Bound Validation on `threshold` in `CreateTransactionApproverDto` Allows Negative Threshold to Bypass Approval Requirements

## Summary
`CreateTransactionApproverDto.threshold` accepts negative integers because no `@Min(1)` constraint is applied at the DTO layer. The service-level guard in `createTransactionApprovers` only rejects `threshold === 0` and `threshold > approvers.length`, leaving negative values unchecked. A negative threshold is persisted to the database and causes the front-end approval-count comparison (`approvals.length >= threshold`) to be trivially satisfied, visually bypassing the multi-signature approval requirement.

## Finding Description

**Root cause — DTO layer (`back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts`):**

`CreateTransactionApproverDto.threshold` carries only `@IsNumber()` and `@IsOptional()` — no `@Min(1)`: [1](#0-0) 

Compare with `UpdateTransactionApproverDto`, which correctly adds `@Min(1)`: [2](#0-1) 

**Root cause — service layer (`back-end/apps/api/src/transactions/approvers/approvers.service.ts`):**

The guard at line 302–307 only checks `threshold === 0` and `threshold > approvers.length`. A value of `-1` evaluates as `-1 === 0` → `false` and `-1 > 1` → `false`, so both guards pass: [3](#0-2) 

The `validateApprover` helper also fails to catch negative values — it only throws when `threshold === null`, `isNaN(threshold)`, or `threshold === 0`: [4](#0-3) 

**Negative threshold is persisted:**

The data assignment at line 314 uses a JavaScript truthiness check: `dtoApprover.threshold && dtoApprover.approvers`. In JavaScript, `-1` is truthy, so `-1 && [{userId: victim_id}]` evaluates to the approvers array (truthy), and `threshold = -1` is written to the database: [5](#0-4) 

**Root cause — approval evaluation (`front-end/src/renderer/utils/sdk/index.ts`):**

The `isApproved` function evaluates tree satisfaction as `approvals.length >= (approver.threshold || approvals.length)`. With `threshold = -1`, since `-1` is truthy in JavaScript, this becomes `approvals.length >= -1`, which is always `true` regardless of how many approvals exist: [6](#0-5) 

## Impact Explanation
An authenticated transaction creator can inject `threshold: -1` into the approver tree. The negative value bypasses all DTO and service-layer guards and is stored in the database. The front-end `isApproved` utility then reports the approval tree as satisfied with zero actual approvals, breaking the organization's multi-signature consensus model. Any UI component relying on `isApproved` — including `ApproverStructureStatus.vue` — will display the transaction as approved and allow it to proceed to execution without the required sign-offs. [7](#0-6) 

## Likelihood Explanation
Any authenticated organization member who can create a transaction can trigger this. No elevated privileges are required. The payload is trivially constructed (`{ "approversArray": [{ "threshold": -1, "approvers": [{ "userId": <id> }] }] }`). The discrepancy between `CreateTransactionApproverDto` (no `@Min`) and `UpdateTransactionApproverDto` (`@Min(1)` present) confirms this is an oversight rather than intentional design. [8](#0-7) 

## Recommendation

1. **DTO layer:** Add `@Min(1)` to `threshold` in `CreateTransactionApproverDto`, mirroring `UpdateTransactionApproverDto`:
   ```typescript
   @IsNumber()
   @Min(1)
   @IsOptional()
   threshold?: number;
   ``` [1](#0-0) 

2. **Service layer:** Update the threshold guard to also reject negative values:
   ```typescript
   if (
     dtoApprover.approvers &&
     (dtoApprover.threshold > dtoApprover.approvers.length ||
      dtoApprover.threshold <= 0)
   )
   ``` [3](#0-2) 

3. **`validateApprover`:** Update the empty-approver check to treat any non-positive threshold as invalid:
   ```typescript
   approver.threshold === null || isNaN(approver.threshold) || approver.threshold <= 0
   ``` [9](#0-8) 

## Proof of Concept

```http
POST /transactions/1/approvers
Authorization: Bearer <valid_user_token>
Content-Type: application/json

{
  "approversArray": [
    {
      "threshold": -1,
      "approvers": [
        { "userId": 2 }
      ]
    }
  ]
}
```

**Step-by-step trace:**
1. DTO validation passes — `@IsNumber()` accepts `-1`; no `@Min(1)` present.
2. `validateApprover` passes — `-1 === null` → false, `isNaN(-1)` → false, `-1 === 0` → false.
3. Service guard passes — `-1 > 1` → false, `-1 === 0` → false.
4. Data assignment: `-1 && [{userId:2}]` → truthy → `threshold = -1` inserted into `transaction_approver`.
5. Front-end `isApproved`: `approvals.length >= (-1 || approvals.length)` → `approvals.length >= -1` → always `true`.
6. The approval tree is shown as satisfied with zero actual approvals; the transaction proceeds to the execution queue without any member signing off. [10](#0-9)

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts (L1-23)
```typescript
import { IsArray, IsNumber, IsOptional, ValidateNested, ArrayMinSize } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateTransactionApproverDto {
  @IsNumber()
  @IsOptional()
  listId?: number;

  @IsNumber()
  @IsOptional()
  threshold?: number;

  @IsNumber()
  @IsOptional()
  userId?: number;

  @IsArray()
  @ArrayMinSize(1)
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionApproverDto)
  approvers?: CreateTransactionApproverDto[];
}
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L692-700)
```typescript
  private validateApprover(approver: CreateTransactionApproverDto): void {
    if (
      (approver.listId === null || isNaN(approver.listId)) &&
      (approver.threshold === null || isNaN(approver.threshold) || approver.threshold === 0) &&
      (approver.userId === null || isNaN(approver.userId)) &&
      (!approver.approvers || approver.approvers.length === 0)
    )
      throw new BadRequestException(this.CANNOT_CREATE_EMPTY_APPROVER);
  }
```

**File:** front-end/src/renderer/utils/sdk/index.ts (L342-361)
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

  return null;
};
```

**File:** front-end/src/renderer/components/Approvers/ApproverStructureStatus.vue (L17-21)
```vue
  <div v-if="Array.isArray(approver.approvers)">
    <p>
      <span v-if="isApproved(approver) === true" class="bi bi-check-lg text-success"></span>
      <span v-if="isApproved(approver) === false" class="bi bi-x-lg text-danger"></span>
      Threshold ({{
```
