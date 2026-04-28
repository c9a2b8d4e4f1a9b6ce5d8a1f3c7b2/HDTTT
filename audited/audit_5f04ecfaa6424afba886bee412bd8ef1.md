### Title
Missing Bounds Validation on `threshold` in `CreateTransactionApproverDto` Allows Approval Workflow Bypass or Permanent DoS

### Summary
The `threshold` field in `CreateTransactionApproverDto` accepts any integer value with no minimum or maximum constraint. An authenticated user can submit `threshold: 0` to bypass the approval requirement entirely, or submit a `threshold` larger than the number of approvers to permanently block a transaction from ever reaching the execution stage.

### Finding Description
In `back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts`, the `threshold` field is decorated only with `@IsNumber()` and `@IsOptional()`:

```typescript
@IsNumber()
@IsOptional()
threshold?: number;
```

There is no `@Min(1)` constraint, no `@Max()` constraint, and no `@IsInt()` constraint. This means a caller can supply:

- `threshold: 0` — zero approvals required; the approval gate is trivially satisfied
- `threshold: 999999` — more approvals required than there are approvers; the transaction can never advance past `WAITING_FOR_SIGNATURES`
- `threshold: -1` or `threshold: 0.5` — values that are semantically nonsensical for a count of required approvers

The DTO is used directly in `CreateTransactionApproversArrayDto` and consumed by the approvers controller/service without any downstream range check to compensate. [1](#0-0) 

### Impact Explanation
- **Bypass (threshold: 0):** If the approval-check logic evaluates `approvedCount >= threshold`, a threshold of 0 is always satisfied, meaning the transaction advances to `WAITING_FOR_EXECUTION` without any approver acting. This undermines the entire multi-approver governance model.
- **DoS (threshold > approver count):** A transaction creator sets a threshold of, say, 1000 with only 2 approvers. The condition can never be met; the transaction is permanently stuck and can only be canceled by the creator — effectively a self-inflicted but also organizationally disruptive denial of service.
- **Float/negative values:** Non-integer or negative thresholds can produce undefined comparison behavior depending on how the service evaluates the approval count.

### Likelihood Explanation
Any authenticated user who creates a transaction can immediately add approvers with an arbitrary threshold via the approvers endpoint. No special role or privilege is required beyond being the transaction creator. The attack path is a single API call with a crafted `threshold` value.

### Recommendation
Add `@Min(1)` and `@IsInt()` to the `threshold` field, and add a cross-field validation in the service layer that asserts `threshold <= approvers.length` before persisting the approver tree:

```typescript
@IsInt()
@Min(1)
@IsOptional()
threshold?: number;
```

Additionally, in `approvers.service.ts`, when creating or updating an approver list, validate:
```typescript
if (dto.threshold !== undefined && dto.approvers && dto.threshold > dto.approvers.length) {
  throw new BadRequestException('Threshold cannot exceed the number of approvers');
}
```

### Proof of Concept
Send the following request as an authenticated transaction creator (replace `:transactionId` with a real transaction ID):

```http
POST /transactions/:transactionId/approvers
Authorization: Bearer <valid_jwt>
Content-Type: application/json

{
  "approversArray": [
    {
      "threshold": 0,
      "approvers": [
        { "userId": 1 },
        { "userId": 2 }
      ]
    }
  ]
}
```

With `threshold: 0`, the approval condition is satisfied immediately without either `userId: 1` or `userId: 2` taking any action, allowing the transaction to proceed to execution bypassing the intended governance control.

For the DoS variant, replace `"threshold": 0` with `"threshold": 999999`. The transaction will be permanently blocked from advancing past `WAITING_FOR_SIGNATURES`. [2](#0-1)

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
