Based on my code review, the vulnerability is confirmed. Here is the audit report:

---

Audit Report

## Title
Transaction Creator Can Add Themselves as an Approver and Self-Approve Their Own Transaction

## Summary
`ApproversService.createTransactionApprovers` permits the transaction creator to supply their own `userId` in the `approversArray`. Once inserted, the creator can call `approveTransaction`, satisfy the approver check, and drive the transaction to execution status without any independent party's involvement.

## Finding Description

**Root cause — no self-referral guard in `createTransactionApprovers`:**

The function begins by confirming the caller is the transaction creator via `getCreatorsTransaction`: [1](#0-0) 

The only validation applied to each supplied `userId` is an existence check against the `User` table: [2](#0-1) 

There is no guard of the form `if (dtoApprover.userId === user.id) throw ...`. The creator's own `id` passes every validation and is inserted as a valid `TransactionApprover` record.

The same absence of a self-referral check exists in `updateTransactionApprover` when updating a `userId`: [3](#0-2) 

**Exploitation path — `approveTransaction` accepts the self-inserted record:**

`approveTransaction` resolves the caller's approver records by filtering on `a.userId === user.id`: [4](#0-3) 

Because the creator inserted themselves, `userApprovers` is non-empty and the `UnauthorizedException` is never thrown. The creator then supplies a valid signature over the transaction body (which they already possess) and the approval is recorded: [5](#0-4) 

**API surface — reachable by any authenticated user:**

Both endpoints are protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. No admin role is required: [6](#0-5) 

## Impact Explanation
The approver workflow exists to enforce independent oversight before a transaction is executed. A creator who self-approves satisfies the approval gate without any second party ever reviewing the transaction. In an organization context this completely nullifies the multi-party control model: a single user can create, self-approve, and drive a transaction to `WAITING_FOR_EXECUTION` status without any colleague's involvement. Depending on the Hedera transaction type (e.g., large HBAR transfers, account key updates, node admin operations), this can result in unauthorized asset movement or unauthorized network state changes.

## Likelihood Explanation
The attack requires only a valid JWT for any organization user who has created at least one transaction — no elevated privileges, no leaked secrets, no social engineering. The two API calls needed (`POST /transactions/:id/approvers` and `POST /transactions/:id/approvers/approve`) are standard documented endpoints. Any authenticated user who can create transactions can exploit this immediately.

## Recommendation
Add a self-referral guard inside the `createApprover` inner function in `createTransactionApprovers`, immediately after the user-existence check:

```typescript
// In approvers.service.ts, after line 276
if (dtoApprover.userId === user.id)
  throw new Error('Transaction creator cannot add themselves as an approver');
```

Apply the same guard in `updateTransactionApprover` at the `dto.userId` branch (around line 489) to prevent the creator from updating an existing approver record to point to themselves.

## Proof of Concept

```
# Step 1 – Creator adds themselves as an approver
POST /transactions/42/approvers
Authorization: Bearer <creator_jwt>
Content-Type: application/json

{ "approversArray": [{ "userId": <creator_user_id> }] }

# Step 2 – Creator self-approves with their own key signature
POST /transactions/42/approvers/approve
Authorization: Bearer <creator_jwt>
Content-Type: application/json

{
  "userKeyId": <creator_key_id>,
  "signature": "<valid_signature_over_tx_body>",
  "approved": true
}
```

After Step 2, the `TransactionApprover` row for the creator is updated with a valid signature and `approved: true`. The approval threshold is satisfied by the creator alone, and `emitTransactionStatusUpdate` fires, potentially advancing the transaction to `WAITING_FOR_EXECUTION` without any independent reviewer. [7](#0-6)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L553-560)
```typescript
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);

    /* If user is approver, filter the records that belongs to the user */
    const userApprovers = approvers.filter(a => a.userId === user.id);

    /* Check if the user is an approver */
    if (userApprovers.length === 0)
      throw new UnauthorizedException('You are not an approver of this transaction');
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L598-610)
```typescript
    /* Update the approver with the signature */
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L612-618)
```typescript
    const notificationEvent = [{ entityId: transaction.id }];

    if (!dto.approved || userApprovers.every(a => a.approved)) {
      emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
    } else {
      emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
    }
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
