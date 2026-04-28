I have verified all the code references. Let me confirm the key facts before rendering a verdict.

All code references verified. Here is the result:

---

Audit Report

## Title
Unbounded Recursive Approver Tree Causes Server Resource Exhaustion (DoS)

## Summary
The `POST /transactions/:transactionId/approvers` endpoint accepts an arbitrarily deep and wide approver tree with no depth or node-count limit. The internal `createApprover` function processes every node recursively, issuing multiple sequential database queries per node inside a single database transaction. An authenticated transaction creator can submit one crafted request containing hundreds of nested threshold nodes, exhausting the database connection pool and degrading the API for all concurrent users.

## Finding Description

**1. No size or depth constraint on the DTO**

`CreateTransactionApproverDto` carries `@ArrayMinSize(1)` on its `approvers` field but no `@ArrayMaxSize` and no depth guard. The outer wrapper `CreateTransactionApproversArrayDto` is equally unconstrained: [1](#0-0) 

**2. Unbounded recursive processing with per-node DB queries**

`createTransactionApprovers` defines an inner async `createApprover` and calls it recursively for every node in the submitted tree: [2](#0-1) 

For each node the function issues:
- `isNode` → `count` query (line 250)
- `findOne` for parent (line 255) — when `listId` is set
- `getRootNodeFromNode` recursive CTE (line 262) — when `listId` is set
- `count` for user existence (line 272) — when `userId` is set
- `getApproversByTransactionId` recursive CTE (line 319) — when `userId` is set
- `create` + `insert` (lines 333–336) — always

For pure threshold nodes (no `userId`, no `listId`) the minimum is 3 queries per node; for user-leaf nodes it reaches 5. All of these execute sequentially inside a single open database transaction.

**3. The duplicate-check does not protect against threshold-only nodes**

`isNode` returns `true` only when `typeof approver.userId === 'number'`: [3](#0-2) 

Pure threshold nodes (`threshold` + nested `approvers`, no `userId`) always return `false` from `isNode`, so an attacker can create an unlimited chain of them. The threshold validation only requires `threshold ≤ approvers.length`, which is satisfied by a chain where every threshold node has exactly one child:

```json
{ "threshold": 1, "approvers": [{ "threshold": 1, "approvers": [{ "threshold": 1, "approvers": [..., { "userId": 1 }] }] }] }
```

**4. Authenticated entry point**

The endpoint is guarded by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`, and restricted to the transaction creator via `getCreatorsTransaction`. However, any registered, verified user can create a transaction and then call this endpoint: [4](#0-3) 

## Impact Explanation

A single HTTP request containing a deep threshold-only chain (e.g., 300 nodes × ~3 DB queries = ~900 sequential queries) will:

- Hold one TypeORM connection open for the entire duration of the database transaction.
- Saturate the connection pool when repeated in parallel, causing all other API requests requiring a DB connection to queue or time out.
- Spike database CPU due to repeated recursive CTEs (`getRootNodeFromNode`, `getApproversByTransactionId`).

The result is a denial of service for all organization users sharing the same API and database instance.

## Likelihood Explanation

- **Attacker preconditions:** A valid, verified account — achievable by any user who can register on the platform.
- **Effort:** A single crafted POST request; no special tooling required.
- **Detection:** No rate limiting, request-size guard, or depth limit specific to the approver endpoint exists in the codebase.
- **Repeatability:** The attacker can repeat the request after each one completes, or issue parallel requests from multiple accounts, to maintain sustained pressure.

## Recommendation

1. **Add `@ArrayMaxSize` to both DTOs** — enforce a reasonable maximum (e.g., 20) on `approvers` in `CreateTransactionApproverDto` and on `approversArray` in `CreateTransactionApproversArrayDto`.
2. **Enforce a maximum tree depth** — add a depth counter to `createApprover` and throw if it exceeds a configured limit (e.g., 5).
3. **Extend the duplicate check to threshold nodes** — remove the `typeof approver.userId === 'number'` guard from `isNode` so that identical threshold nodes are also rejected.
4. **Apply per-endpoint rate limiting** — use a NestJS throttler guard on the `POST /approvers` route to limit how frequently a single user can call it.

## Proof of Concept

```http
POST /transactions/1/approvers
Authorization: Bearer <valid_jwt>
Content-Type: application/json

{
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
                ... (repeat 297 more levels)
                { "userId": 1 }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

This payload passes all DTO validation (each threshold node has exactly one child, satisfying `threshold ≤ approvers.length`), bypasses the `isNode` duplicate check (no `userId` on intermediate nodes), and forces ~900 sequential DB queries inside a single open transaction, holding a connection for the entire duration.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L647-665)
```typescript
  async isNode(
    approver: CreateTransactionApproverDto,
    transactionId: number,
    entityManager?: EntityManager,
  ) {
    const find: FindManyOptions<TransactionApprover> = {
      where: {
        listId: typeof approver.listId === 'number' ? approver.listId : null,
        userId: typeof approver.userId === 'number' ? approver.userId : null,
        threshold:
          typeof approver.threshold === 'number' && approver.threshold !== 0
            ? approver.threshold
            : null,
        transactionId: typeof approver.listId === 'number' ? null : transactionId,
      },
    };

    const count = await (entityManager || this.repo).count(TransactionApprover, find);
    return count > 0 && typeof approver.userId === 'number';
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
