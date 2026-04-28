### Title
Unbounded Approver Tree in `createTransactionApprovers` Enables Server-Side DoS

### Summary
The `POST /transactions/:transactionId/approvers` endpoint accepts a `CreateTransactionApproversArrayDto` whose `approversArray` field has no enforced size limit and whose nested `approvers` sub-arrays have no depth limit. Any authenticated user who creates a transaction can submit an arbitrarily large or deeply nested approver tree, exhausting server memory during recursive processing and making all subsequent recursive SQL queries against that transaction prohibitively expensive.

### Finding Description

**Root cause — no size or depth cap on the approver DTO**

`createTransactionApprovers` in `approvers.service.ts` iterates over `dto.approversArray` and, for every element that carries a nested `approvers` array, calls itself recursively with no guard on either the breadth or the depth of the tree: [1](#0-0) 

The only uniqueness check (`isNode`) is keyed on `userId`. Threshold/tree nodes (those without a `userId`) carry no such uniqueness constraint, so a caller can submit a payload with thousands of threshold nodes nested arbitrarily deep.

**Controller — no rate-limit or body-size guard beyond JSON parsing** [2](#0-1) 

**Downstream amplification — every subsequent operation runs an unbounded recursive SQL query**

After the tree is persisted, every call to `getApproversByTransactionId`, `getTransactionApproversById`, and `getRootNodeFromNode` issues a `WITH RECURSIVE` CTE that walks the entire tree: [3](#0-2) 

`approveTransaction` calls `getVerifiedApproversByTransactionId`, which in turn calls `getApproversByTransactionId`, so every approval attempt on a bloated transaction hits the same unbounded recursive query: [4](#0-3) 

**Exploit path (end-to-end)**

1. Attacker registers a normal user account and authenticates (JWT).
2. Attacker creates a transaction (`POST /transactions`).
3. Attacker sends a single `POST /transactions/:id/approvers` with a payload containing thousands of threshold nodes nested many levels deep — e.g., a tree of depth 100 each with 10 children = 10^100 logical nodes, or simply a flat `approversArray` with 50 000 entries.
4. The recursive `createApprover` function processes each node synchronously inside a single DB transaction, consuming unbounded Node.js heap and holding a long-lived DB connection.
5. All future calls to `GET /transactions/:id/approvers`, `POST /transactions/:id/approvers/approve`, and any query that joins the approver table via the recursive CTE become extremely slow or time out, effectively freezing that transaction and degrading the shared DB for all users.

### Impact Explanation

- **Server memory exhaustion**: The recursive JavaScript call stack and the in-memory `approvers[]` accumulator grow proportionally to the number of submitted nodes. A sufficiently large payload can OOM the NestJS process.
- **Database CPU exhaustion**: The unbounded `WITH RECURSIVE` CTE runs on every read/approve operation for the affected transaction, consuming PostgreSQL CPU and blocking other queries.
- **Permanent transaction freeze**: Once the bloated tree is persisted, the transaction cannot be approved or managed without first removing the approver tree, which itself requires a recursive delete query (`removeNode`).

### Likelihood Explanation

Any verified (non-admin) user can create a transaction and immediately call the approvers endpoint. No privileged role is required. The attack requires only a crafted JSON body — no special tooling. The `approversArray` field is a plain JSON array with no `@MaxLength`, `@ArrayMaxSize`, or depth-limit decorator applied in the DTO.

### Recommendation

1. Add `@ArrayMaxSize(N)` (e.g., `N = 50`) to `approversArray` in `CreateTransactionApproversArrayDto`.
2. Enforce a maximum nesting depth (e.g., 5 levels) inside `createApprover` by passing and checking a `depth` counter.
3. Add a total-node cap across the entire tree (e.g., 200 nodes) checked before any DB insert.
4. Consider adding a request body size limit at the NestJS/Express layer for this route.

### Proof of Concept

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
            ... // 100 levels deep, each with 10 children
          ]
        }
      ]
    },
    ... // repeated 1000 times at the top level
  ]
}
```

The server will enter the recursive `createApprover` loop, accumulate thousands of in-flight DB inserts inside a single transaction, and either exhaust Node.js heap or hold the DB connection open long enough to time out. Subsequent `GET /transactions/1/approvers` or `POST /transactions/1/approvers/approve` calls will trigger the unbounded `WITH RECURSIVE` CTE and return extremely slowly or not at all. [5](#0-4) [2](#0-1)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L92-108)
```typescript
    return (entityManager || this.repo).query(
      `
      with recursive approverList as
        (
          select * from transaction_approver 
          where "transactionId" = $1
            union all
              select approver.* from transaction_approver as approver
              join approverList on approverList."id" = approver."listId"
        )
      select * from approverList
      where approverList."deletedAt" is null
        ${userId ? 'and approverList."userId" = $2' : ''}
      `,
      userId ? [transactionId, userId] : [transactionId],
    );
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-364)
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

      emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transactionId  }]);
    } catch (error) {
      throw new BadRequestException(error.message);
    }

    return approvers;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L552-556)
```typescript
    /* Get all the approvers */
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);

    /* If user is approver, filter the records that belongs to the user */
    const userApprovers = approvers.filter(a => a.userId === user.id);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L47-54)
```typescript
  @Post()
  createTransactionApprovers(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() body: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    return this.approversService.createTransactionApprovers(user, transactionId, body);
  }
```
