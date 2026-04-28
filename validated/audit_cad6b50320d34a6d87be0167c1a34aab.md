All referenced code has been verified. Here is the audit result:

---

Audit Report

## Title
Unbounded String Fields in Backend DTOs Allow Authenticated Users to Exhaust Database Storage and Cause Memory Pressure

## Summary
Multiple backend API DTOs accept string fields with no `@MaxLength()` constraint. The most critical instance is `CreateCommentDto.message`, which has no length limit at the DTO level or the database entity level. The body-parser limit is explicitly set to `2mb` (larger than the 100 KB assumed in the report). Any verified organization member can POST arbitrarily large strings that are persisted directly to PostgreSQL, and the comment retrieval path loads all rows with no pagination.

## Finding Description

**`CreateCommentDto.message` — no length constraint at any layer:**

`CreateCommentDto` only applies `@IsString()` with no `@MaxLength()`: [1](#0-0) 

The `TransactionComment` entity maps `message` to a plain `@Column()` with no `length` argument. TypeORM emits `character varying` without a length specifier, which PostgreSQL treats as unlimited: [2](#0-1) 

The migration confirms the column is `character varying NOT NULL` with no length: [3](#0-2) 

The controller passes the DTO directly to the service with no intermediate sanitization, protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — no admin role required: [4](#0-3) 

The service calls `repo.create(dto)` and `repo.save(comment)` immediately: [5](#0-4) 

`getTransactionComments` loads all comment rows for a transaction with no pagination or size guard: [6](#0-5) 

**`CreateTransactionGroupDto.description` — same pattern:**

`CreateTransactionGroupDto.description` has only `@IsString()`: [7](#0-6) 

The `TransactionGroup` entity also uses a bare `@Column()` with no length: [8](#0-7) 

**Body-parser limit is 2 MB (larger than the 100 KB assumed in the report):** [9](#0-8) 

**Note on `CreateTransactionDto.name` / `description`:** The report claims these are also unbounded, but the `Transaction` entity *does* enforce `{ length: 50 }` and `{ length: 256 }` at the column level, so PostgreSQL will reject oversized values there. The DTO still lacks `@MaxLength()`, but the database acts as a backstop. This does not affect the validity of the comment and group-description findings.

**Why front-end guards do not help:**

The front-end `ValidateRequestHandler.vue` checks `name.length > 50` and `description.length > 256` for transactions only, and has no equivalent check for comment `message`: [10](#0-9) 

An attacker bypasses the front-end entirely by calling the REST API directly.

## Impact Explanation

- **Database disk exhaustion**: Each `POST /transactions/:transactionId/comments` request can carry up to 2 MB of `message` data. Repeated calls fill the `transaction_comment` table with no per-user or per-transaction quota.
- **Server-side memory pressure**: `getTransactionComments` loads all comment rows for a transaction into the Node.js heap with no pagination. A transaction with many large comments can cause OOM in the API process.
- **Degraded availability for all users**: Once the database disk is full or the API process OOMs, the entire organization's transaction workflow (approvals, signing, execution) is disrupted.
- The same disk-exhaustion risk applies to `transaction_group.description` via `POST /transaction-groups`.

## Likelihood Explanation

Any user who has completed email verification can reach the comment endpoint — no admin role is required. The guard chain is `JwtBlackListAuthGuard → JwtAuthGuard → VerifiedUserGuard`: [11](#0-10) 

The attack requires only a standard HTTP client (curl, Postman) and a valid JWT. No cryptographic material, no privileged access, and no special knowledge beyond a valid JWT is needed.

## Recommendation

1. Add `@MaxLength(N)` to `CreateCommentDto.message` (e.g., 1 000 characters) and `CreateTransactionGroupDto.description` (e.g., 256 characters).
2. Add a `length` argument to the corresponding TypeORM `@Column()` decorators in `TransactionComment` and `TransactionGroup` entities to enforce the constraint at the database level as well.
3. Add `@MaxLength()` to `CreateTransactionDto.name` and `description` at the DTO level to match the existing entity-level constraints and return a clean 400 rather than a database error.
4. Add pagination (e.g., `take`/`skip`) to `getTransactionComments` to bound the memory footprint of a single retrieval.

## Proof of Concept

```bash
# 1. Obtain a JWT for any verified organization user
TOKEN=$(curl -s -X POST https://<host>/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@org.com","password":"password"}' | jq -r .accessToken)

# 2. Generate a ~1.9 MB message string
PAYLOAD=$(python3 -c "import json; print(json.dumps({'message': 'A'*1900000}))")

# 3. POST the oversized comment (repeatable in a loop)
curl -X POST https://<host>/transactions/1/comments \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$PAYLOAD"
# Returns 201 Created; the full 1.9 MB string is persisted to transaction_comment.

# 4. Retrieve all comments — the full payload is loaded into heap
curl https://<host>/transactions/1/comments \
  -H "Authorization: Bearer $TOKEN"
```

Each iteration persists up to ~2 MB to the `transaction_comment` table. Looping this across multiple transactions fills database disk. Subsequent `GET /transactions/:id/comments` calls load the accumulated data into the Node.js heap, risking OOM.

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-comment.dto.ts (L1-6)
```typescript
import { IsString } from 'class-validator';

export class CreateCommentDto {
  @IsString()
  message: string;
}
```

**File:** back-end/libs/common/src/database/entities/transaction-comment.entity.ts (L16-17)
```typescript
  @Column()
  message: string;
```

**File:** back-end/typeorm/migrations/1764999592722-InitialSchema.ts (L8-8)
```typescript
        await queryRunner.query(`CREATE TABLE IF NOT EXISTS "transaction_comment" ("id" SERIAL NOT NULL, "message" character varying NOT NULL, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "transactionId" integer, "userId" integer, CONSTRAINT "PK_67f9bea51814cdd1344eaab12f9" PRIMARY KEY ("id"))`);
```

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L16-29)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
//TODO add serializer
export class CommentsController {
  constructor(private commentsService: CommentsService) {}

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

**File:** back-end/apps/api/src/transactions/comments/comments.service.ts (L20-23)
```typescript
    const comment = this.repo.create(dto);
    comment['transaction'].id = transactionId;
    comment.user = user;
    return this.repo.save(comment);
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

**File:** back-end/apps/api/src/transactions/dto/create-transaction-group.dto.ts (L13-14)
```typescript
  @IsString()
  description: string;
```

**File:** back-end/libs/common/src/database/entities/transaction-group.entity.ts (L9-10)
```typescript
  @Column()
  description: string;
```

**File:** back-end/apps/api/src/setup-app.ts (L43-43)
```typescript
  app.use(json({ limit: '2mb' }));
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
