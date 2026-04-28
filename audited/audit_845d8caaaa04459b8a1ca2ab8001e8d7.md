### Title
Missing Minimum Bound Validation on `threshold` in `CreateTransactionApproverDto` Allows Zero-Threshold Approval Bypass

---

### Summary

The `CreateTransactionApproverDto` class accepts a `threshold` value of `0` (or any negative number) with no lower-bound constraint, while the corresponding `UpdateTransactionApproverDto` correctly enforces `@Min(1)`. A transaction creator can submit a threshold-based approver structure with `threshold: 0`, meaning the approval gate is trivially satisfied with zero approvals — effectively bypassing the multi-signature approval workflow.

---

### Finding Description

In `back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts`, the `threshold` field is decorated only with `@IsNumber()` and `@IsOptional()`: [1](#0-0) 

There is no `@Min(1)` constraint. By contrast, `UpdateTransactionApproverDto` in `back-end/apps/api/src/transactions/dto/update-transaction-approver.dto.ts` correctly applies `@Min(1)` to the same field: [2](#0-1) 

The global `ValidationPipe` in `back-end/apps/api/src/setup-app.ts` enforces DTO constraints at the API boundary: [3](#0-2) 

Because `CreateTransactionApproverDto` lacks `@Min(1)`, the pipe passes `threshold: 0` through without rejection. The `CreateTransactionApproverDto` is also used recursively for nested approver lists via `@ValidateNested({ each: true })`: [4](#0-3) 

This means the zero-threshold bypass applies at every level of a nested approver tree.

A secondary, lower-severity gap exists in `CreateTransactionGroupDto`: the `description` field carries `@IsString()` but no `@IsNotEmpty()`, permitting an empty-string description to be stored: [5](#0-4) 

---

### Impact Explanation

In the Organization mode multi-signature workflow, the approval gate is the primary control preventing unauthorized transaction execution. A `threshold: 0` approver structure means the system considers the approval requirement met with **zero approvals collected**. Any transaction submitted with this structure can advance to `WAITING_FOR_EXECUTION` and be submitted to the Hedera network without any approver ever acting on it. This directly undermines the governance model the tool is designed to enforce.

---

### Likelihood Explanation

The API endpoint for creating transaction approvers is accessible to any authenticated user with the Creator role. No privileged compromise is required. The inconsistency between the create and update DTOs suggests this is an oversight rather than intentional design, making accidental or deliberate exploitation realistic.

---

### Recommendation

Add `@Min(1)` to the `threshold` field in `CreateTransactionApproverDto`, mirroring the constraint already present in `UpdateTransactionApproverDto`:

```typescript
// create-transaction-approver.dto.ts
import { IsArray, IsNumber, IsOptional, ValidateNested, ArrayMinSize, Min } from 'class-validator';

export class CreateTransactionApproverDto {
  @IsNumber()
  @IsOptional()
  listId?: number;

  @IsNumber()
  @Min(1)          // <-- add this
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

Additionally, add `@IsNotEmpty()` to `description` in `CreateTransactionGroupDto` to prevent empty-string group descriptions from being persisted.

---

### Proof of Concept

An authenticated Creator sends the following request to the approver creation endpoint:

```json
POST /transactions/{id}/approvers
{
  "approversArray": [
    {
      "listId": 1,
      "threshold": 0,
      "approvers": [
        { "userId": 10 },
        { "userId": 11 }
      ]
    }
  ]
}
```

Because `CreateTransactionApproverDto` has no `@Min(1)` on `threshold`, the `ValidationPipe` accepts this payload. The resulting approver structure records a threshold of `0`, meaning the approval condition is satisfied immediately without any of the listed approvers (`userId: 10`, `userId: 11`) ever casting a vote. The transaction proceeds to execution on the Hedera network with zero approvals collected.

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

**File:** back-end/apps/api/src/transactions/dto/update-transaction-approver.dto.ts (L1-18)
```typescript
import { IsNumber, IsOptional, Min } from 'class-validator';

export class UpdateTransactionApproverDto {
  @IsNumber()
  @IsOptional()
  listId?: number;

  @IsNumber()
  @Min(1)
  @IsOptional()
  threshold?: number;

  @IsNumber()
  @IsOptional()
  userId?: number;
}


```

**File:** back-end/apps/api/src/setup-app.ts (L18-34)
```typescript
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      exceptionFactory(errors: ValidationError[]) {
        console.error(
          'Validation failed:',
          errors.map((error) => ({
            property: error.property,
            type: error.target?.constructor?.name || 'Unknown', // Logs the type being validated
            valueKeys: error.value ? Object.keys(error.value) : [], // Logs the keys of the value
          })),
        );
        return new BadRequestException(ErrorCodes.IB);
      },
    }),
  );
```

**File:** back-end/apps/api/src/transactions/dto/create-transaction-group.dto.ts (L12-29)
```typescript
export class CreateTransactionGroupDto {
  @IsString()
  description: string;

  @IsOptional()
  @IsBoolean()
  atomic: boolean;

  @IsOptional()
  @IsBoolean()
  sequential: boolean;

  @IsArray()
  @IsNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionGroupItemDto)
  groupItems: CreateTransactionGroupItemDto[];
}
```
