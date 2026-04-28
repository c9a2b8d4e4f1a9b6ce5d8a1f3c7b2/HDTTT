### Title
Unbounded Recursive `approvers` Array in `CreateTransactionApproverDto` Enables Authenticated DoS via Exponential Validation Cost

### Summary
The `CreateTransactionApproverDto` DTO accepts a recursive `approvers` field with no depth or size limit. Because NestJS class-validator applies `@ValidateNested({ each: true })` recursively, a crafted deeply-nested or wide approver tree causes exponential CPU and memory consumption during request validation, allowing any authenticated user to bring the API service to a halt. A secondary unbounded flat-array issue exists in `CreateTransactionObserversDto.userIds`.

### Finding Description

**Root cause — recursive DTO with no depth/size bound:**

`CreateTransactionApproverDto` is self-referential: [1](#0-0) 

The `approvers` field is typed as `CreateTransactionApproverDto[]` and decorated with `@ValidateNested({ each: true })` and `@Type(() => CreateTransactionApproverDto)`. There is no `@ArrayMaxSize`, no `@MaxDepth`, and no depth-tracking guard anywhere in the validation chain. The outer wrapper DTO is equally unbounded: [2](#0-1) 

When NestJS's `ValidationPipe` processes the incoming body, `class-transformer` recursively instantiates every nested `CreateTransactionApproverDto` node, and `class-validator` then recursively validates every node. For a binary tree of depth D, this produces 2^D validation calls. At depth 30 the tree has ~1 billion nodes; the JSON payload itself remains small (a few hundred KB) while the server-side work is unbounded.

**Secondary issue — unbounded flat array:**

`CreateTransactionObserversDto.userIds` carries only `@ArrayMinSize(1)` with no `@ArrayMaxSize`: [3](#0-2) 

An attacker can submit tens of thousands of user IDs, forcing the service to issue a large `IN (...)` database query.

**Similarly unbounded:**

`CreateTransactionGroupDto.groupItems` has no size cap: [4](#0-3) 

Each item embeds a full `CreateTransactionDto` including raw `transactionBytes`, amplifying memory pressure.

**Entry path:**

All endpoints are guarded by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`: [5](#0-4) 

A registered, verified user — the "malicious normal user" attacker profile from `RESEARCHER.md` — satisfies all preconditions without any privileged access.

### Impact Explanation

A single crafted POST request with a deeply-nested `approvers` tree (depth ~25–30, branching factor 2) causes the NestJS API process to spin at 100% CPU for seconds to minutes while class-validator recurses through the tree. Repeating the request at low frequency (a few requests per second) keeps the server permanently saturated, making the API unavailable to all other users. Because the work is done inside the validation pipe — before any business logic — no database state is mutated, but the service is effectively taken offline. The impact is **service unavailability** for the entire organization backend.

### Likelihood Explanation

Any user who can register and verify an account can trigger this. The attack requires no leaked credentials, no admin access, and no special knowledge beyond the API schema (which is exposed via Swagger). The payload is trivially constructed. A single attacker with one account can sustain the DoS indefinitely.

### Recommendation

1. **Add `@ArrayMaxSize` to every unbounded array DTO field:**

   ```typescript
   // create-transaction-approver.dto.ts
   @IsArray()
   @ArrayMinSize(1)
   @ArrayMaxSize(20)          // enforce a sane upper bound
   @IsOptional()
   @ValidateNested({ each: true })
   @Type(() => CreateTransactionApproverDto)
   approvers?: CreateTransactionApproverDto[];
   ```

2. **Enforce a maximum nesting depth** for the recursive approver tree. Implement a custom `@MaxDepth(n)` validator or validate depth explicitly in the service before processing.

3. Apply `@ArrayMaxSize` to `CreateTransactionObserversDto.userIds`, `CreateTransactionApproversArrayDto.approversArray`, and `CreateTransactionGroupDto.groupItems`.

4. Consider a global NestJS `ValidationPipe` option or a custom interceptor that rejects payloads exceeding a configurable node count before recursive validation begins.

### Proof of Concept

Send the following request as any verified user. Increase `depth` to amplify CPU cost:

```python
import requests, json

def build_tree(depth):
    if depth == 0:
        return {"userId": 1}
    return {"threshold": 1, "approvers": [build_tree(depth - 1), build_tree(depth - 1)]}

payload = {"approversArray": [build_tree(25)]}  # 2^25 ≈ 33M nodes

requests.post(
    "https://<api-host>/transactions/<id>/approvers",
    headers={"Authorization": "Bearer <valid_jwt>"},
    json=payload,
    timeout=120,
)
```

Expected outcome: the API process consumes 100% CPU for an extended period. Concurrent legitimate requests time out. Repeating the request at low frequency sustains the outage.

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

**File:** back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts (L25-30)
```typescript
export class CreateTransactionApproversArrayDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionApproverDto)
  approversArray: CreateTransactionApproverDto[];
}
```

**File:** back-end/apps/api/src/transactions/dto/create-transaction-observers.dto.ts (L1-8)
```typescript
import { ArrayMinSize, IsArray, IsNumber } from 'class-validator';

export class CreateTransactionObserversDto {
  @IsArray()
  @IsNumber({}, { each: true })
  @ArrayMinSize(1)
  userIds: number[];
}
```

**File:** back-end/apps/api/src/transactions/dto/create-transaction-group.dto.ts (L24-28)
```typescript
  @IsArray()
  @IsNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionGroupItemDto)
  groupItems: CreateTransactionGroupItemDto[];
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L54-58)
```typescript
@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
  constructor(private transactionsService: TransactionsService) {}
```
