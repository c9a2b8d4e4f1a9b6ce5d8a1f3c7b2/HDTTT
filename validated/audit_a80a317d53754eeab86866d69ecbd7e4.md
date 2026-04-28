### Title
`updateTransactionApprover` Allows Duplicate `userId` Entries in Approver List, Enabling Threshold Bypass

### Summary
The `updateTransactionApprover` function in `back-end/apps/api/src/transactions/approvers/approvers.service.ts` allows a transaction creator to update an existing approver's `userId` to a `userId` that already exists as another approver for the same transaction. Unlike `createTransactionApprovers`, which calls `isNode()` to reject duplicates, the update path has no such check. This allows a malicious transaction creator to insert duplicate user entries into the approver list, causing a single user's approval to satisfy multiple approver slots and bypass the intended threshold.

### Finding Description

**Root cause — missing duplicate check in `updateTransactionApprover`:**

`createTransactionApprovers` correctly guards against duplicates at line 250:

```typescript
if (await this.isNode(dtoApprover, transactionId, transactionalEntityManager))
  throw new Error(this.APPROVER_ALREADY_EXISTS);
``` [1](#0-0) 

However, `updateTransactionApprover`'s `userId` branch (lines 489–517) only checks that the user exists and that the approver is not a tree node. It never checks whether the target `userId` is already present as an approver for the same transaction:

```typescript
} else if (typeof dto.userId === 'number') {
  if (typeof approver.threshold === 'number') throw new Error(this.APPROVER_IS_TREE);
  const userCount = await transactionalEntityManager.count(User, { where: { id: dto.userId } });
  if (userCount === 0) throw new Error(this.USER_NOT_FOUND(dto.userId));
  if (approver.userId !== dto.userId) {
    // ← no isNode() / duplicate check here
    await transactionalEntityManager.update(TransactionApprover, approver.id, data);
    ...
  }
}
``` [2](#0-1) 

**Exploit path:**

1. Attacker (a normal authenticated user) creates a transaction and sets two approvers: User A (`approverId=10`) and User B (`approverId=11`), with a threshold of 2.
2. Attacker calls `PATCH /transactions/:txId/approvers/11` with body `{ userId: <User A's id> }`.
3. No duplicate check fires; the DB now contains two `TransactionApprover` rows for the same `transactionId`, both with `userId = User A`.
4. User A calls `POST /transactions/:txId/approvers/approve`. The `approveTransaction` function filters `userApprovers = approvers.filter(a => a.userId === user.id)`, collecting both duplicate rows, then bulk-updates all of them with User A's signature:

```typescript
.whereInIds(userApprovers.map(a => a.id))
.execute();
``` [3](#0-2) 

5. Both approver records now carry User A's signature. The threshold of 2 is satisfied by a single unique approver.

The controller endpoint that exposes this is: [4](#0-3) 

### Impact Explanation
A malicious transaction creator can reduce the effective approval threshold to 1 regardless of the configured value. In an organizational workflow where multi-party approval is the security control preventing unauthorized Hedera transactions (e.g., large HBAR transfers, account updates), this completely undermines the approval model. The attacker controls which transaction gets executed and can self-approve it by duplicating their own `userId` across all approver slots.

### Likelihood Explanation
Any authenticated, verified user who creates a transaction is the transaction creator and therefore has the authority to call `updateTransactionApprover`. No admin keys, leaked credentials, or privileged roles are required. The attack requires only two sequential API calls (create approvers, then update one approver's userId) and is fully deterministic.

### Recommendation
In the `updateTransactionApprover` function, before applying a `userId` update, call `isNode` (or an equivalent inline count query) to verify that the target `userId` does not already exist as an approver for the same transaction:

```typescript
} else if (typeof dto.userId === 'number') {
  if (typeof approver.threshold === 'number') throw new Error(this.APPROVER_IS_TREE);
  const userCount = await transactionalEntityManager.count(User, { where: { id: dto.userId } });
  if (userCount === 0) throw new Error(this.USER_NOT_FOUND(dto.userId));

  // ADD: duplicate check
  const duplicateCount = await transactionalEntityManager.count(TransactionApprover, {
    where: { transactionId, userId: dto.userId },
  });
  if (duplicateCount > 0) throw new Error('Approver already exists for this transaction');

  if (approver.userId !== dto.userId) { ... }
}
```

### Proof of Concept

**Preconditions:** Two registered users (User A, id=1) and (User B, id=2). Attacker is logged in as the transaction creator.

1. `POST /transactions` → creates transaction id=42.
2. `POST /transactions/42/approvers` with body:
   ```json
   { "approversArray": [{ "userId": 1 }, { "userId": 2 }] }
   ```
   → creates approver rows id=10 (userId=1) and id=11 (userId=2).
3. `PATCH /transactions/42/approvers/11` with body:
   ```json
   { "userId": 1 }
   ```
   → succeeds with no error; row id=11 now has `userId=1`.
4. DB state: two `TransactionApprover` rows for transaction 42, both with `userId=1`.
5. User A (id=1) calls `POST /transactions/42/approvers/approve` with a valid signature.
6. `approveTransaction` collects both rows (ids 10 and 11) via `filter(a => a.userId === 1)` and bulk-updates both with User A's signature.
7. **Result:** Transaction threshold of 2 is satisfied by a single approval from User A. User B's approval is never required.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L249-251)
```typescript
          /* Check if the approver already exists */
          if (await this.isNode(dtoApprover, transactionId, transactionalEntityManager))
            throw new Error(this.APPROVER_ALREADY_EXISTS);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L489-517)
```typescript
        } else if (typeof dto.userId === 'number') {
          /* Check if the approver is a tree */
          if (typeof approver.threshold === 'number') throw new Error(this.APPROVER_IS_TREE);

          /* Check if the user exists */
          const userCount = await transactionalEntityManager.count(User, {
            where: { id: dto.userId },
          });
          if (userCount === 0) throw new Error(this.USER_NOT_FOUND(dto.userId));

          /* Update the user */
          if (approver.userId !== dto.userId) {
            const data: DeepPartial<TransactionApprover> = {
              userId: dto.userId,
              userKeyId: undefined,
              signature: undefined,
              approved: undefined,
            };

            approver.userKeyId = undefined;
            approver.signature = undefined;
            approver.approved = undefined;

            await transactionalEntityManager.update(TransactionApprover, approver.id, data);
            approver.userId = dto.userId;
            updated = true;

            return approver;
          }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L600-609)
```typescript
      await transactionalEntityManager
        .createQueryBuilder()
        .update(TransactionApprover)
        .set({
          userKeyId: dto.userKeyId,
          signature: dto.signature,
          approved: dto.approved,
        })
        .whereInIds(userApprovers.map(a => a.id))
        .execute();
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
