### Title
Unbounded String Inputs in Backend DTOs Allow Authenticated DoS via Database and Memory Exhaustion

### Summary
The backend API accepts arbitrarily large strings in several DTO fields (`CreateCommentDto.message`, `CreateTransactionDto.name`/`description`, `CreateTransactionGroupDto.description`) with no server-side length enforcement. Any authenticated, verified user can exploit this to bloat the PostgreSQL database and exhaust server memory when those records are fetched — particularly through the comment endpoint, which returns all records without pagination.

### Finding Description

The front-end applies some length guards:

- `validate100CharInput` caps transaction memo at 100 chars [1](#0-0) 
- `ValidateRequestHandler.vue` rejects `name > 50` and `description > 256` chars before submission [2](#0-1) 

However, these are **client-side only**. The backend DTOs carry no corresponding `@MaxLength()` decorators:

**`CreateCommentDto`** — `message` is only `@IsString()`, no upper bound: [3](#0-2) 

**`CreateTransactionDto`** — `name` and `description` are only `@IsString()`: [4](#0-3) 

**`CreateTransactionGroupDto`** — `description` is only `@IsString()`: [5](#0-4) 

These values are persisted directly to PostgreSQL. The `transaction.description` column is typed as `Text` (unbounded): [6](#0-5) 

The `transaction_comment.message` column is also an unbounded `String`: [7](#0-6) 

The `CommentsController` exposes a `POST /transactions/:transactionId/comments` endpoint that writes the unbounded `message` directly to the database: [8](#0-7) 

The `getTransactionComments` retrieval path returns **all** comments for a transaction with no pagination: [9](#0-8) 

### Impact Explanation

An attacker who is a verified organization member can:
1. POST repeated comments with multi-megabyte `message` payloads to any transaction they have access to.
2. Each write is persisted to PostgreSQL without size restriction.
3. Any subsequent `GET /transactions/:transactionId/comments` call loads all comments into memory at once (no pagination), causing memory exhaustion proportional to total stored payload.
4. This degrades or crashes the API service for all users of the organization.

The `CreateTransactionDto.name`/`description` and `CreateTransactionGroupDto.description` fields are similarly unbounded, compounding the storage attack surface.

### Likelihood Explanation

Any authenticated, verified user within an organization can reach the comment endpoint — no admin privilege is required. The `VerifiedUserGuard` is the only gate: [10](#0-9) 

A single malicious insider or a compromised account is sufficient to execute the attack. The API is directly reachable over HTTPS, so the front-end guards are trivially bypassed with `curl` or any HTTP client.

### Recommendation

Add `@MaxLength(N)` decorators to all unbounded string fields in the affected DTOs:

- `CreateCommentDto.message` — e.g., `@MaxLength(2000)`
- `CreateTransactionDto.name` — e.g., `@MaxLength(50)` (matching the front-end guard)
- `CreateTransactionDto.description` — e.g., `@MaxLength(256)` (matching the front-end guard)
- `CreateTransactionGroupDto.description` — e.g., `@MaxLength(256)`

Additionally, add pagination to `getTransactionComments` to prevent bulk memory loading even if large records exist.

### Proof of Concept

```bash
# Authenticated attacker posts a 10 MB comment
curl -X POST https://api.example.com/transactions/1/comments \
  -H "Authorization: Bearer <valid_jwt>" \
  -H "Content-Type: application/json" \
  -d "{\"message\": \"$(python3 -c 'print("A" * 10_000_000)')\"}"

# Repeat N times to fill the database.
# Then trigger OOM on the API server:
curl https://api.example.com/transactions/1/comments \
  -H "Authorization: Bearer <valid_jwt>"
# Returns all N × 10 MB records into a single in-memory array.
```

### Citations

**File:** front-end/src/renderer/utils/sdk/validation.ts (L43-47)
```typescript
export function validate100CharInput(str: string, inputDescription: string) {
  if (str.length > 100) {
    throw new Error(`${inputDescription} is limited to 100 characters`);
  }
}
```

**File:** front-end/src/renderer/components/Transaction/TransactionProcessor/components/ValidateRequestHandler.vue (L63-69)
```vue
  if (request.name && request.name?.length > 50) {
    throw new Error('Transaction name is too long');
  }

  if (request.description && request.description?.length > 256) {
    throw new Error('Transaction description is too long');
  }
```

**File:** back-end/apps/api/src/transactions/dto/create-comment.dto.ts (L1-6)
```typescript
import { IsString } from 'class-validator';

export class CreateCommentDto {
  @IsString()
  message: string;
}
```

**File:** back-end/apps/api/src/transactions/dto/create-transaction.dto.ts (L8-14)
```typescript
export class CreateTransactionDto {
  @IsString()
  name: string;

  @IsString()
  description: string;

```

**File:** back-end/apps/api/src/transactions/dto/create-transaction-group.dto.ts (L12-14)
```typescript
export class CreateTransactionGroupDto {
  @IsString()
  description: string;
```

**File:** docs/database/tables/transaction.md (L12-12)
```markdown
| **description**     | Text      | Detailed description of the transaction.                                                                                                             |
```

**File:** back-end/libs/common/src/database/entities/transaction-comment.entity.ts (L16-17)
```typescript
  @Column()
  message: string;
```

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L14-17)
```typescript
@ApiTags('Transaction Comments')
@Controller('transactions/:transactionId?/comments')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
//TODO add serializer
```

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L21-29)
```typescript
  @Post()
  //TODO need some sort of guard or check to ensure user can comment here
  createComment(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() dto: CreateCommentDto,
  ) {
    return this.commentsService.createComment(user, transactionId, dto);
  }
```

**File:** back-end/apps/api/src/transactions/comments/comments.service.ts (L32-37)
```typescript
  getTransactionComments(transactionId: number) {
    return this.repo
      .createQueryBuilder('comment')
      .where('comment.transactionId = :transactionId', { transactionId })
      .getMany();
  }
```
