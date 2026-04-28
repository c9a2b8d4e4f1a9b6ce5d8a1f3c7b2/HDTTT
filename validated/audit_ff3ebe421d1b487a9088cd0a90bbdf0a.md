The code confirms the vulnerability. Here is the audit report:

---

Audit Report

## Title
Transaction Creator Can Add Themselves as an Approver to Self-Approve Their Own Transactions

## Summary
`createTransactionApprovers` in `approvers.service.ts` enforces that only the transaction creator may add approvers, but performs no check that the submitted `userId` differs from the creator's own `user.id`. Once registered, the creator can call `approveTransaction` as a valid approver, bypassing the multi-party approval workflow entirely.

## Finding Description

**Root cause — missing self-referral guard in `createTransactionApprovers`:**

The function opens with a creator-identity check: [1](#0-0) 

When iterating over the submitted approvers, the only identity validation performed on `dtoApprover.userId` is a user-existence check: [2](#0-1) 

There is **no guard** of the form `if (dtoApprover.userId === user.id) throw ...`. The creator's own `userId` passes this check trivially because their account exists.

**How `approveTransaction` then accepts the self-approval:**

`approveTransaction` filters the approver list for records matching the calling user's id: [3](#0-2) 

Because the creator's own record was inserted in step 2, `userApprovers` is non-empty, the authorization check passes, and the approval is recorded: [4](#0-3) 

**Accessible endpoint — any verified user can reach both routes:** [5](#0-4) [6](#0-5) 

## Impact Explanation
The approver workflow is the application's primary multi-party authorization control for Hedera transactions. A creator who self-approves can satisfy a threshold or advance a transaction to `WAITING_FOR_EXECUTION` without any independent review. This allows a single user to unilaterally authorize account updates, token transfers, or file operations on the Hedera network that were supposed to require a second party's sign-off.

## Likelihood Explanation
Any authenticated, verified organization user who creates a transaction can exploit this immediately with two standard API calls. No special privileges, leaked credentials, or external dependencies are required. The attacker operates entirely within normal product flows.

## Recommendation
In `createTransactionApprovers`, after the user-existence check (line 276), add a self-referral guard:

```typescript
if (dtoApprover.userId === user.id)
  throw new Error('The transaction creator cannot add themselves as an approver');
``` [2](#0-1) 

Apply the same guard in `updateTransactionApprover` where `dto.userId` is accepted, to prevent a creator from updating an existing approver slot to their own id. [7](#0-6) 

## Proof of Concept

```
# Step 1 — Authenticate as user A (verified org member), obtain JWT
POST /auth/login  →  { token: "<jwt>" }

# Step 2 — Create a transaction
POST /transactions
Authorization: Bearer <jwt>
→ { id: 42, status: "WAITING_FOR_SIGNATURES", ... }

# Step 3 — Add self as approver (no rejection — userId existence check passes)
POST /transactions/42/approvers
Authorization: Bearer <jwt>
Body: { "approversArray": [{ "userId": <user_A_id> }] }
→ 201 Created  ← creator's own record inserted as approver

# Step 4 — Self-approve with a valid signature over the transaction bytes
POST /transactions/42/approvers/approve
Authorization: Bearer <jwt>
Body: { "userKeyId": <key_id>, "signature": "<valid_sig>", "approved": true }
→ 200 true  ← approval recorded; transaction status advances without any second party
```

The `getCreatorsTransaction` check at line 239 passes in step 3 because user A is the creator. The user-existence check at lines 271–276 passes because user A's account exists. The `userApprovers` filter at line 556 returns user A's own approver record in step 4, completing the bypass. [8](#0-7) [9](#0-8)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L271-277)
```typescript
          if (typeof dtoApprover.userId === 'number') {
            const userCount = await transactionalEntityManager.count(User, {
              where: { id: dtoApprover.userId },
            });

            if (userCount === 0) throw new Error(this.USER_NOT_FOUND(dtoApprover.userId));
          }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L489-497)
```typescript
        } else if (typeof dto.userId === 'number') {
          /* Check if the approver is a tree */
          if (typeof approver.threshold === 'number') throw new Error(this.APPROVER_IS_TREE);

          /* Check if the user exists */
          const userCount = await transactionalEntityManager.count(User, {
            where: { id: dto.userId },
          });
          if (userCount === 0) throw new Error(this.USER_NOT_FOUND(dto.userId));
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L547-560)
```typescript
  async approveTransaction(
    dto: ApproverChoiceDto,
    transactionId: number,
    user: User,
  ): Promise<boolean> {
    /* Get all the approvers */
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);

    /* If user is approver, filter the records that belongs to the user */
    const userApprovers = approvers.filter(a => a.userId === user.id);

    /* Check if the user is an approver */
    if (userApprovers.length === 0)
      throw new UnauthorizedException('You are not an approver of this transaction');
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L599-610)
```typescript
    await this.dataSource.transaction(async transactionalEntityManager => {
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
    });
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L65-73)
```typescript
  @Post('/approve')
  @OnlyOwnerKey<ApproverChoiceDto>('userKeyId')
  approveTransaction(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() body: ApproverChoiceDto,
  ): Promise<boolean> {
    return this.approversService.approveTransaction(body, transactionId, user);
  }
```
