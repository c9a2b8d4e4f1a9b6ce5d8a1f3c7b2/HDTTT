### Title
Unbounded Recursive Approver Tree Enables Authenticated DoS via Excessive Database Operations

### Summary
The `POST /transactions/:id/approvers` endpoint accepts a deeply nested, arbitrarily wide approver tree with no depth or size limit. The server-side handler processes this tree with a recursive async function that issues multiple sequential database queries per node, all inside a single long-running database transaction. Any verified user who has created a transaction can exploit this to exhaust database connections and degrade server availability.

### Finding Description

**Vulnerability class: DoS via underpriced/unbounded resource-intensive operation** (analog to EIP 160 — underpriced EXP opcode).

`CreateTransactionApproverDto` declares a recursive `approvers` field. Neither the DTO nor the outer `CreateTransactionApproversArrayDto` applies any `@ArrayMaxSize()` constraint. A grep across the entire repository confirms `ArrayMaxSize` is never used anywhere. [1](#0-0) 

The service method `createTransactionApprovers` defines an inner recursive async function `createApprover`. For every single node in the submitted tree it performs, sequentially inside a database transaction:

1. `isNode` — a DB count query
2. `findOne` for the parent (if `listId` is set)
3. `getRootNodeFromNode` — a recursive SQL CTE query
4. `count(User, ...)` — a user existence check
5. `getApproversByTransactionId` — another recursive SQL CTE query
6. `insert(TransactionApprover, ...)` — the actual write

Then it recurses into every child node. [2](#0-1) 

A payload shaped as a wide flat tree (e.g., `approversArray` with 10,000 leaf entries, each with `threshold: 1, approvers: [{userId: X}]`) or a deeply nested chain (each node wrapping the next) triggers O(N) to O(N²) database round-trips within a single open database transaction, holding connection pool resources for the entire duration.

The same missing limit exists on the observer endpoint. `CreateTransactionObserversDto.userIds` has `@ArrayMinSize(1)` but no `@ArrayMaxSize()`, so a creator can add thousands of observers in one call, each triggering a DB insert and a NATS notification event. [3](#0-2) [4](#0-3) 

### Impact Explanation

A single malicious POST request can hold a PostgreSQL connection open for an extended period while processing thousands of recursive DB queries. With a small number of concurrent requests, the database connection pool is exhausted, causing all other API operations (including legitimate transaction signing and execution) to queue or fail. This is a server-wide denial of service reachable by any authenticated, verified user.

### Likelihood Explanation

Any registered and verified user can create a transaction and immediately become its creator, granting them the right to call `POST /transactions/:id/approvers`. The user throttler allows 100 requests per minute and 10 per second — sufficient to sustain the attack. No admin privilege is required. The attack payload is trivially constructed as a JSON object. [5](#0-4) 

### Recommendation

1. Add `@ArrayMaxSize(N)` to `CreateTransactionApproverDto.approvers` and `CreateTransactionApproversArrayDto.approversArray` (e.g., max 50 entries each).
2. Enforce a maximum recursion depth inside `createApprover` (e.g., reject trees deeper than 5 levels).
3. Add `@ArrayMaxSize(N)` to `CreateTransactionObserversDto.userIds` (e.g., max 100 entries per call).
4. Consider moving the per-node DB validation queries outside the recursive loop where possible, or batching them.

### Proof of Concept

```http
POST /transactions/1/approvers
Authorization: Bearer <valid_creator_token>
Content-Type: application/json

{
  "approversArray": [
    { "threshold": 1, "approvers": [{ "userId": 1 }] },
    { "threshold": 1, "approvers": [{ "userId": 1 }] },
    ... // repeated 5000 times
  ]
}
```

Each entry in `approversArray` causes `createApprover` to be called, which issues at minimum 3–5 sequential DB queries before inserting, then recurses into the child. 5,000 top-level entries with one child each = ~30,000+ DB round-trips inside a single open database transaction, blocking a connection for the entire duration. [6](#0-5)

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts (L1-29)
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
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L244-355)
```typescript
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

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L47-68)
```typescript
    const observers: TransactionObserver[] = [];

    for (const userId of dto.userIds) {
      if (!transaction.observers.some(o => o.userId === userId)) {
        const observer = this.repo.create({ userId, transactionId, role: Role.FULL });
        observers.push(observer);
      }
    }

    if (observers.length === 0) {
      return [];
    }

    try {
      const result = await this.repo.save(observers);

      emitTransactionUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);

      return result;
    } catch (error) {
      throw new BadRequestException(error.message);
    }
```

**File:** back-end/apps/api/src/throttlers/user-throttler.module.ts (L16-18)
```typescript
            ttl: seconds(60),
            limit: 100,
          },
```
