I have verified all the specific code references. Here is my assessment:

**Key findings from the code:**

1. `@ArrayMaxSize` is confirmed absent from both DTO fields.
2. The recursive `createApprover` function and its DB queries are confirmed.
3. The claim that "no rate-limiting guard is present" is **inaccurate** — a global `IpThrottlerGuard` is registered as `APP_GUARD` in `api.module.ts`, applying IP-based throttling to all routes. However, this throttles *request count*, not *payload complexity*, so a single oversized request still bypasses it.
4. The observers secondary surface is less severe than described: the per-`userId` loop only does an in-memory `.some()` check, not a DB query per item, and uses a single bulk `repo.save()`.

The core vulnerability is real and verifiable. The inaccuracy about rate limiting does not invalidate the primary finding.

---

Audit Report

## Title
Unbounded Recursive Approver Tree Submission Causes Server-Side DoS via Resource Exhaustion

## Summary
The `POST /transactions/:transactionId/approvers` endpoint accepts an arbitrarily large and arbitrarily deep nested approver tree with no maximum size or depth constraint. The service processes each node recursively, executing multiple synchronous database queries per node inside a single database transaction. A malicious authenticated user can submit a crafted payload with many nested nodes, exhausting the database connection pool and causing service unavailability.

## Finding Description

**Root Cause — Missing `@ArrayMaxSize` on both DTO fields:**

`CreateTransactionApproverDto.approvers` carries only `@ArrayMinSize(1)` with no upper bound, and `CreateTransactionApproversArrayDto.approversArray` has no size constraint at all: [1](#0-0) 

Neither field has an `@ArrayMaxSize` decorator, and there is no depth limit enforced anywhere in the DTO or service layer.

**Exploit Path — Recursive DB-heavy processing per node:**

`createTransactionApprovers` defines an inner async function `createApprover` that is called recursively for every node in the submitted tree: [2](#0-1) 

For each node the function executes:
1. `isNode(...)` — a DB query to check for duplicates (line 250)
2. `transactionalEntityManager.findOne(TransactionApprover, ...)` — parent lookup (line 255)
3. `getRootNodeFromNode(...)` — a recursive SQL CTE query (line 262)
4. `transactionalEntityManager.count(User, ...)` — user existence check (line 272)
5. `getApproversByTransactionId(...)` — existing approver lookup (line 319)
6. `transactionalEntityManager.insert(TransactionApprover, ...)` — DB write (line 336)

All of this runs inside a single `dataSource.transaction(...)` block, holding one database connection open for the entire duration of the request.

**Entry Point — Reachable by any verified user:**

The controller applies only authentication guards (`JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard`): [3](#0-2) 

A global `IpThrottlerGuard` is registered as `APP_GUARD`: [4](#0-3) 

However, this throttler limits *request count per IP per time window* (configured via `GLOBAL_MINUTE_LIMIT` / `GLOBAL_SECOND_LIMIT`), not payload complexity or tree depth: [5](#0-4) 

A single request with a deeply nested tree exhausts resources within the throttle window. The service additionally checks that the caller is the transaction creator: [6](#0-5) 

**Secondary surface — `CreateTransactionObserversDto.userIds` also unbounded:** [7](#0-6) 

The observers service iterates over `dto.userIds` with an in-memory duplicate check and a single bulk `repo.save()`: [8](#0-7) 

This surface is less severe than the approvers endpoint since there are no per-item DB queries, but a very large `userIds` array still results in a large bulk insert.

## Impact Explanation
A single crafted HTTP request with a deeply nested or very wide approver tree triggers many synchronous database queries within one open transaction. This holds a database connection for the full duration of the request, can saturate the database connection pool blocking all other queries, and causes request timeouts and HTTP 500 errors for concurrent users. The attack can be repeated within the IP throttle window (which limits request count, not payload size) to sustain the outage.

## Likelihood Explanation
The attacker preconditions are minimal: a registered, verified account and one created transaction, both achievable through normal product flows with no privileged access. The payload is a standard JSON body. The global IP throttler does not prevent a single large request from causing resource exhaustion, and the throttle limits are configurable environment variables that may be set permissively.

## Recommendation

1. Add `@ArrayMaxSize(N)` to both `CreateTransactionApproversArrayDto.approversArray` and `CreateTransactionApproverDto.approvers` with a reasonable bound (e.g., 20).
2. Enforce a maximum tree depth in the service before entering the transaction, by pre-validating the submitted tree structure.
3. Add `@ArrayMaxSize(N)` to `CreateTransactionObserversDto.userIds`.
4. Consider applying a per-user throttler (a `UserThrottlerGuard` already exists in the codebase at `back-end/apps/api/src/guards/user-throttler.guard.ts`) to the approvers and observers `POST` endpoints to limit abuse even within the IP throttle window.

## Proof of Concept

```bash
# 1. Register and verify an account, obtain JWT token
# 2. Create a transaction, obtain transactionId

curl -X POST https://target/transactions/1/approvers \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{
    "approversArray": [
      {
        "threshold": 1,
        "approvers": [
          {
            "threshold": 1,
            "approvers": [
              {
                "threshold": 1,
                "approvers": [
                  ... (hundreds of levels deep, each with userId nodes)
                ]
              }
            ]
          }
        ]
      }
    ]
  }'
```

Each node in the tree triggers up to 6 database operations inside a single open transaction. A tree with 200+ nodes will hold a DB connection for the full request duration, and concurrent such requests will exhaust the connection pool.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L239-239)
```typescript
    await this.getCreatorsTransaction(transactionId, user);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L244-351)
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
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L31-54)
```typescript
@ApiTags('Transaction Approvers')
@Controller('transactions/:transactionId?/approvers')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
@Serialize(TransactionApproverDto)
export class ApproversController {
  constructor(private approversService: ApproversService) {}

  /* Create transaction approvers for the given transaction id with the user ids */
  @ApiOperation({
    summary: 'Creates transaction approvers',
    description: 'Create transaction approvers for the given transaction with the provided data.',
  })
  @ApiResponse({
    status: 201,
    type: [TransactionApproverDto],
  })
  @Post()
  createTransactionApprovers(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() body: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    return this.approversService.createTransactionApprovers(user, transactionId, body);
  }
```

**File:** back-end/apps/api/src/api.module.ts (L73-78)
```typescript
  providers: [
    {
      provide: APP_GUARD,
      useClass: IpThrottlerGuard,
    },
    {
```

**File:** back-end/apps/api/src/throttlers/ip-throttler.module.ts (L13-25)
```typescript
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

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L49-61)
```typescript
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
```
