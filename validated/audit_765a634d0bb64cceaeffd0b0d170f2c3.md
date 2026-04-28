Audit Report

## Title
Negative Threshold Bypass in `createTransactionApprovers` Allows Approval Requirement to Be Circumvented

## Summary
The `createTransactionApprovers` function in `approvers.service.ts` and its corresponding DTO `CreateTransactionApproverDto` lack a lower-bound check on the `threshold` field. A negative integer such as `-1` passes all validation layers and is persisted to the database. The frontend `isApproved` utility then evaluates `approvals.length >= -1` as always `true`, permanently satisfying the approval gate with zero actual approvals.

## Finding Description

**Root cause 1 — Missing `@Min(1)` in `CreateTransactionApproverDto`**

The create DTO applies only `@IsNumber()` and `@IsOptional()` to `threshold`, with no minimum-value constraint: [1](#0-0) 

Compare this to `UpdateTransactionApproverDto`, which correctly applies `@Min(1)`: [2](#0-1) 

The update path is therefore protected at the DTO level; the create path is not.

**Root cause 2 — Service-level guard does not reject negative values**

Inside `createTransactionApprovers`, the only range check is: [3](#0-2) 

`-1 > N` is `false` and `-1 === 0` is `false`, so a negative threshold passes silently.

**Root cause 3 — `validateApprover` helper does not catch negative values**

The private helper only rejects `null`, `NaN`, or `0`: [4](#0-3) 

`isNaN(-1)` is `false` and `-1 === 0` is `false`, so `-1` passes this check as well.

**Root cause 4 — Negative threshold is persisted**

At the point of record construction, the falsy-check `dtoApprover.threshold && dtoApprover.approvers` evaluates `-1` as truthy, so the negative value is written to the database: [5](#0-4) 

**How the stored negative threshold is consumed**

The `isApproved` utility used for approval-status evaluation reads: [6](#0-5) 

Because `-1` is truthy in JavaScript, `approver.threshold || approvals.length` evaluates to `-1`. `approvals.length >= -1` is always `true` (array length is always ≥ 0), so the approval gate is permanently open regardless of how many approvers have actually signed.

## Impact Explanation
A transaction creator can silently nullify the multi-party approval requirement. Transactions that are supposed to require N-of-M approvals from designated organization members are immediately evaluated as fully approved with zero actual approvals. This directly enables unauthorized movement of HBAR or other assets on the Hedera network, bypassing the multi-signature coordination the system is designed to enforce.

## Likelihood Explanation
The attack requires only a valid authenticated session as a transaction creator — no admin keys, no leaked credentials, no privileged role. The malicious payload is a single integer field in a standard API request. Any user who can create a transaction can exploit this immediately.

## Recommendation

1. **Add `@Min(1)` to `CreateTransactionApproverDto`** to mirror the protection already present in `UpdateTransactionApproverDto`:
   ```typescript
   @IsNumber()
   @Min(1)
   @IsOptional()
   threshold?: number;
   ```
2. **Add a lower-bound check in the service** for both create and update paths:
   ```typescript
   if (dtoApprover.threshold !== undefined && dtoApprover.threshold < 1)
     throw new Error('Threshold must be a positive integer');
   ```
3. **Fix `validateApprover`** to explicitly reject non-positive values:
   ```typescript
   (approver.threshold !== undefined && approver.threshold < 1)
   ```

## Proof of Concept

```
POST /transactions/:id/approvers
Authorization: Bearer <valid_user_token>
Content-Type: application/json

{
  "approversArray": [{
    "threshold": -1,
    "approvers": [
      { "userId": 2 },
      { "userId": 3 }
    ]
  }]
}
```

1. `CreateTransactionApproverDto` has no `@Min(1)` — `-1` passes DTO validation.
2. `validateApprover`: `isNaN(-1)` is `false`, `-1 === 0` is `false` — passes.
3. Service guard: `-1 > 2` is `false`, `-1 === 0` is `false` — passes.
4. Persistence: `-1 && [array]` is truthy — `threshold: -1` is written to `transaction_approver`.
5. `isApproved`: `approvals.length >= (approver.threshold || approvals.length)` → `0 >= -1` → `true`.
6. The transaction is immediately evaluated as approved with zero actual approvals.

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

**File:** front-end/src/renderer/utils/sdk/index.ts (L354-355)
```typescript
    if (approvals.length >= (approver.threshold || approvals.length)) {
      return true;
```
