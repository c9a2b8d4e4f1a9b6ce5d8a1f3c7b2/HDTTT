Based on my code review, the core claims are verified. Let me now produce the audit report.

**Key verified facts:**

1. `CreateTransactionApproverDto.approvers` has `@ArrayMinSize(1)` but no `@ArrayMaxSize`. `CreateTransactionApproversArrayDto.approversArray` has no size constraint at all.
2. `createApprover` is recursive and executes multiple sequential DB operations per node inside a single `dataSource.transaction(...)`.
3. The body limit is confirmed at `2mb`.
4. An `IpThrottlerGuard` IS applied globally — the report's claim of "no rate limiting" is inaccurate — but it limits *request count*, not *per-request payload complexity*, so a single crafted request still exhausts the DB.

---

Audit Report

## Title
Unbounded Recursive Iteration in `createTransactionApprovers` Enables Authenticated DoS via Exhaustive DB Operations

## Summary
The `POST /transactions/:transactionId/approvers` endpoint accepts an arbitrarily large, arbitrarily deep `approversArray` with no maximum-size constraint. The internal `createApprover` function is recursive and executes 2–4 sequential database queries per node, all inside a single held DB transaction. An authenticated transaction creator can craft a wide or deeply nested approver tree that triggers tens of thousands of DB operations in a single request, exhausting the database connection pool and degrading service for all users.

## Finding Description

**Missing `@ArrayMaxSize` on both DTO fields:**

`CreateTransactionApproverDto` enforces only `@ArrayMinSize(1)` on the recursive `approvers` field, and `CreateTransactionApproversArrayDto` has no size constraint at all on `approversArray`: [1](#0-0) 

**Unbounded recursive loop with per-node DB I/O:**

Inside `createTransactionApprovers`, the inner async function `createApprover` calls itself for every element of `dtoApprover.approvers`. Each invocation performs:

- `isNode` — a `count(TransactionApprover)` query
- `findOne(TransactionApprover)` — parent lookup (if `listId` is set)
- `getRootNodeFromNode` — recursive CTE query (if `listId` is set)
- `count(User)` — user existence check (if `userId` is set)
- `getApproversByTransactionId` — recursive CTE query (if `userId` is set)
- `insert(TransactionApprover)` — DB write [2](#0-1) 

All of this runs inside a single `dataSource.transaction(...)` block, holding a DB connection open for the entire duration.

**The outer loop that starts the recursion:** [3](#0-2) 

**Body size is the only per-request complexity guard — and it is insufficient:**

The only server-wide protection is a 2 MB JSON body limit: [4](#0-3) 

A 2 MB payload can encode tens of thousands of approver nodes. For example, a flat `approversArray` of entries like `{"threshold":1,"approvers":[{"userId":N}]}` (~45 bytes each) yields ~44,000 root entries, each spawning a child — approximately 264,000 sequential DB operations in a single transaction.

**IP throttler exists but does not mitigate per-request complexity:**

An `IpThrottlerGuard` is applied globally and limits request *count* per IP per time window: [5](#0-4) [6](#0-5) 

However, this throttler does not constrain the *complexity* of a single request. A single allowed request with a maximally crafted payload is sufficient to trigger the attack.

**Secondary surface — observers endpoint:**

`CreateTransactionObserversDto` also lacks `@ArrayMaxSize`: [7](#0-6) 

The loop at `observers.service.ts` line 49 iterates over every supplied `userId` in memory before a batch `save`. This is less severe (no recursive CTE per entry, just an in-memory loop and one batch insert), but still allows an unbounded in-memory array. [8](#0-7) 

## Impact Explanation

A single crafted request holds a PostgreSQL connection open while executing tens of thousands of recursive CTE queries and inserts. With a small number of concurrent such requests (each within the IP throttle window), the database connection pool is exhausted, causing all other API operations — authentication, transaction reads, signature submissions — to queue and time out. The impact is service-wide and persists until the attacker stops sending requests; no admin action can recover the pool while the long transaction is running.

## Likelihood Explanation

The attacker must be an authenticated user who is the creator of at least one transaction — a condition reachable by any registered organization member. No elevated privilege is required. The attack requires only a single HTTP request with a crafted JSON body, which any HTTP client can produce. The IP throttler limits request frequency but does not prevent a single maximally crafted request from causing significant DB load. The attack is therefore practically executable by any authenticated user.

## Recommendation

1. **Add `@ArrayMaxSize` to both DTO fields.** Apply a reasonable upper bound (e.g., 100) to `CreateTransactionApproversArrayDto.approversArray` and to `CreateTransactionApproverDto.approvers`. This is the primary fix.
2. **Add a maximum recursion depth guard** inside `createApprover` to reject trees deeper than a defined limit (e.g., 5 levels).
3. **Add `@ArrayMaxSize` to `CreateTransactionObserversDto.userIds`** to bound the observers endpoint as well.
4. **Consider a per-user throttle on the approvers POST endpoint** (a `UserThrottlerGuard` already exists in the codebase but is not applied to this route).

## Proof of Concept

```http
POST /transactions/1/approvers HTTP/1.1
Authorization: Bearer <valid_jwt>
Content-Type: application/json

{
  "approversArray": [
    {"threshold": 1, "approvers": [{"userId": 1}]},
    {"threshold": 1, "approvers": [{"userId": 2}]},
    {"threshold": 1, "approvers": [{"userId": 3}]},
    ... (repeat ~44,000 times, staying under 2 MB)
  ]
}
```

Each root entry spawns one child leaf. For ~44,000 entries:
- ~44,000 × `isNode` (count) + `insert` = ~88,000 DB ops for root nodes
- ~44,000 × `isNode` (count) + `count(User)` + `getApproversByTransactionId` (recursive CTE) + `insert` = ~176,000 DB ops for leaf nodes
- **Total: ~264,000 sequential DB operations inside a single held transaction.**

Sending 2–3 such requests concurrently (from different IPs to bypass the IP throttler) exhausts the connection pool and denies service to all other users.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L244-356)
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
      });
```

**File:** back-end/apps/api/src/setup-app.ts (L43-43)
```typescript
  app.use(json({ limit: '2mb' }));
```

**File:** back-end/apps/api/src/api.module.ts (L73-83)
```typescript
  providers: [
    {
      provide: APP_GUARD,
      useClass: IpThrottlerGuard,
    },
    {
      provide: APP_GUARD,
      useClass: FrontendVersionGuard,
    },
    LoggerMiddleware,
  ],
```

**File:** back-end/apps/api/src/throttlers/ip-throttler.module.ts (L12-26)
```typescript
        storage: new ThrottlerStorageRedisService(configService.getOrThrow('REDIS_URL')),
        throttlers: [
          {
            name: 'global-minute',
            ttl: seconds(60),
            limit: configService.getOrThrow<number>('GLOBAL_MINUTE_LIMIT'),
          },
          {
            name: 'global-second',
            ttl: seconds(1),
            limit: configService.getOrThrow<number>('GLOBAL_SECOND_LIMIT'),
          },
        ],
      }),
    }),
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

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L49-54)
```typescript
    for (const userId of dto.userIds) {
      if (!transaction.observers.some(o => o.userId === userId)) {
        const observer = this.repo.create({ userId, transactionId, role: Role.FULL });
        observers.push(observer);
      }
    }
```
