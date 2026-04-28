### Title
`isNode` Duplicate-Check Logic Silently Skips Threshold Approver Nodes, Allowing Unlimited Duplicate Threshold Nodes to Be Injected into the Approval Tree

### Summary
The `isNode` method in `approvers.service.ts` is the sole guard that prevents duplicate approver nodes from being inserted into a transaction's approval tree. Its return expression contains a wrong boolean conjunction (`count > 0 && typeof approver.userId === 'number'`) that makes the function unconditionally return `false` for every threshold-type (non-user) approver node, regardless of whether a matching record already exists in the database. Any authenticated user who is the creator of a transaction can therefore call `POST /transactions/:id/approvers` repeatedly with the same threshold node payload and insert an unbounded number of duplicate threshold nodes, permanently corrupting the approval tree for that transaction.

### Finding Description

**Root cause — line 665 of `approvers.service.ts`:**

```typescript
// back-end/apps/api/src/transactions/approvers/approvers.service.ts
async isNode(
  approver: CreateTransactionApproverDto,
  transactionId: number,
  entityManager?: EntityManager,
) {
  const find: FindManyOptions<TransactionApprover> = {
    where: {
      listId: typeof approver.listId === 'number' ? approver.listId : null,
      userId: typeof approver.userId === 'number' ? approver.userId : null,
      threshold: ...,
      transactionId: ...,
    },
  };

  const count = await (entityManager || this.repo).count(TransactionApprover, find);
  return count > 0 && typeof approver.userId === 'number';  // ← BUG
}
```

The DB query (lines 652–661) already constructs a precise `WHERE` clause that matches on `listId`, `userId`, `threshold`, and `transactionId`. When `count > 0` the record exists. The extra conjunct `&& typeof approver.userId === 'number'` is the defect:

| Approver type | `typeof approver.userId === 'number'` | `isNode` result when duplicate exists |
|---|---|---|
| User node (`userId` set) | `true` | `true` ✓ (duplicate blocked) |
| Threshold node (`userId` not set) | `false` | **`false` ✗ (duplicate allowed)** |

For every threshold node the function returns `false` unconditionally, so the guard at line 250–251 never fires for threshold nodes:

```typescript
// line 250-251
if (await this.isNode(dtoApprover, transactionId, transactionalEntityManager))
  throw new Error(this.APPROVER_ALREADY_EXISTS);
```

**Exploit path:**

1. Attacker registers as a normal user and creates a transaction (any type).
2. Attacker calls `POST /transactions/:id/approvers` with a threshold payload, e.g.:
   ```json
   { "approversArray": [{ "threshold": 1, "approvers": [{ "userId": 2 }] }] }
   ```
3. `createTransactionApprovers` calls `getCreatorsTransaction` — passes (attacker is creator).
4. `isNode` is called for the threshold node. `typeof approver.userId === 'number'` → `false`. Returns `false`.
5. The threshold node is inserted. Attacker repeats step 2 N times.
6. N identical threshold root nodes now exist for the same transaction, each with its own child user-approver subtree. [1](#0-0) [2](#0-1) 

### Impact Explanation

**Approval tree corruption / permanent transaction DoS.**

`getTreeStructure` builds the tree by iterating all approver rows and linking children to parents by `listId`. Duplicate root threshold nodes (all with `listId = null`) each appear as independent roots. The approval evaluation logic must satisfy every root node. If N identical threshold roots exist, N independent sets of approvals are required — a condition that can never be met because the same user cannot approve the same transaction twice (the `userApprovers.every(a => a.signature)` guard at line 563 blocks re-approval). The transaction is permanently locked in `WAITING_FOR_SIGNATURES` and can never be executed or cancelled through normal flows.

Additionally, because each duplicate threshold root spawns its own child user-approver rows (each with a distinct `id`), the total number of rows grows unboundedly, causing storage bloat and degraded query performance for all recursive CTE queries (`getApproversByTransactionId`, `getRootNodeFromNode`, `getTransactionApproversById`). [3](#0-2) [4](#0-3) 

### Likelihood Explanation

The attack requires only that the attacker be an authenticated user who has created a transaction — a capability available to every registered user of the system. No admin privileges, no leaked secrets, and no race conditions are required. The endpoint `POST /transactions/:id/approvers` is a standard REST call documented in the API docs. The bug is deterministic and reproducible on every call. [5](#0-4) 

### Recommendation

Remove the extra conjunct. The DB `WHERE` clause already encodes all the identity conditions; `count > 0` alone is the correct predicate:

```typescript
// Before (buggy)
return count > 0 && typeof approver.userId === 'number';

// After (correct)
return count > 0;
```

This mirrors the fix described in the referenced external report (changing `&&` to the correct logical operator), applied here to the TypeScript analog of the same pattern. [6](#0-5) 

### Proof of Concept

**Preconditions:** Two registered users (attacker = User A, target approver = User B). Attacker has a valid JWT.

```
# Step 1 – Create a transaction (any type) as User A
POST /transactions
Authorization: Bearer <userA_token>
→ { "id": 42, ... }

# Step 2 – Add a threshold approver tree (first time — succeeds)
POST /transactions/42/approvers
Authorization: Bearer <userA_token>
Content-Type: application/json
{
  "approversArray": [{
    "threshold": 1,
    "approvers": [{ "userId": <userB_id> }]
  }]
}
→ 201 Created

# Step 3 – Repeat Step 2 (second time — should be rejected, but is NOT)
POST /transactions/42/approvers
Authorization: Bearer <userA_token>
Content-Type: application/json
{ same payload }
→ 201 Created   ← BUG: duplicate threshold root inserted

# Step 4 – Repeat N times to create N duplicate roots

# Step 5 – User B attempts to approve
POST /transactions/42/approvers/approve
Authorization: Bearer <userB_token>
→ Approval recorded for one root's child node only.
   Remaining N-1 roots remain unsatisfied.
   Transaction is permanently stuck in WAITING_FOR_SIGNATURES.
```

**Expected:** Step 3 returns `400 Bad Request: "Approver already exists"`.
**Actual:** Step 3 returns `201 Created`, inserting a duplicate threshold node. [1](#0-0) [7](#0-6)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-239)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L249-251)
```typescript
          /* Check if the approver already exists */
          if (await this.isNode(dtoApprover, transactionId, transactionalEntityManager))
            throw new Error(this.APPROVER_ALREADY_EXISTS);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L562-563)
```typescript
    /* Check if the user has already approved the transaction */
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L646-666)
```typescript
  /* Check if the approver node already exists */
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
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L668-689)
```typescript
  /* Get the tree structure of the approvers */
  getTreeStructure(approvers: TransactionApprover[]): TransactionApprover[] {
    const approverMap = new Map(approvers.map(approver => [approver.id, { ...approver }]));

    approverMap.forEach(approver => {
      if (approver.listId) {
        const parentApprover = approverMap.get(approver.listId);
        if (parentApprover) {
          if (!parentApprover.approvers) {
            parentApprover.approvers = [];
          }
          parentApprover.approvers.push(approver);
        }
      }
    });

    const rootApprovers = Array.from(approverMap.values()).filter(
      approver => approver.listId === null,
    );

    return rootApprovers;
  }
```

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L20-67)
```typescript
export class TransactionApprover {
  @PrimaryGeneratedColumn()
  id: number;

  /* If the approver has a listId, then transactionId should be null */
  @ManyToOne(() => Transaction, transaction => transaction.approvers, {
    nullable: true,
  })
  @JoinColumn({ name: 'transactionId' })
  transaction?: Transaction;

  @Column({ nullable: true })
  transactionId?: number;

  @ManyToOne(() => TransactionApprover, approverList => approverList.approvers, {
    nullable: true,
  })
  @JoinColumn({ name: 'listId' })
  list?: TransactionApprover;

  @Column({ nullable: true })
  listId?: number;

  @Column({ nullable: true })
  threshold?: number;

  @ManyToOne(() => UserKey, userKey => userKey.approvedTransactions, { nullable: true })
  @JoinColumn({ name: 'userKeyId' })
  userKey?: UserKey;

  @Column({ nullable: true })
  userKeyId?: number;

  @Column({ type: 'bytea', nullable: true })
  signature?: Buffer;

  @ManyToOne(() => User, user => user.approvableTransactions, { nullable: true })
  @JoinColumn({ name: 'userId' })
  user?: User;

  @Column({ nullable: true })
  userId?: number;

  @Column({ nullable: true })
  approved?: boolean;

  @OneToMany(() => TransactionApprover, approver => approver.list)
  approvers: TransactionApprover[];
```
