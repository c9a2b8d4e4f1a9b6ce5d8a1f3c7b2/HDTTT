Audit Report

## Title
Transaction Creator Can Self-Assign as Approver, Bypassing Multi-Party Approval Workflow

## Summary
`createTransactionApprovers` in `approvers.service.ts` verifies the caller is the transaction creator but contains no guard preventing the creator from submitting their own `userId` in the `approversArray`. This allows the creator to insert themselves as an approver and subsequently call `approveTransaction` to unilaterally satisfy the approval requirement — defeating the multi-party authorization control the system is designed to enforce.

## Finding Description

In `createTransactionApprovers`, after confirming the caller is the creator via `getCreatorsTransaction` (line 239), the only validation performed on a submitted `userId` is a database existence check: [1](#0-0) 

There is no guard of the form `if (dtoApprover.userId === user.id) throw ...`. The creator's own `userId` passes this check trivially since they exist in the database.

The same gap exists in `updateTransactionApprover` when `dto.userId` is provided — only existence is checked: [2](#0-1) 

In `approveTransaction`, the function filters approvers by `a.userId === user.id` and proceeds if the user is found in the list. There is no check that the approver is not also the transaction creator: [3](#0-2) 

The controller exposes both endpoints to any `VerifiedUser` with no additional role guard: [4](#0-3) 

## Impact Explanation

The approval system exists to enforce organizational multi-party authorization before a Hedera transaction is submitted to the network. A creator who self-assigns as the sole approver can unilaterally satisfy the approval requirement. Once `approveTransaction` records the creator's signature against their own approver record, the transaction status update logic processes the approval as legitimate and can advance the transaction to `WAITING_FOR_EXECUTION` — without any independent party's review or consent. This is a privilege escalation: the creator gains the approver role they are not supposed to hold, bypassing the trust model the system is built on.

## Likelihood Explanation

Any authenticated, verified user can create transactions and set approvers — no privileged access is required. The API endpoints are reachable over standard HTTP with a valid JWT. The attacker only needs their own account credentials, which they legitimately possess. The steps are deterministic and require no race condition or timing dependency.

## Recommendation

Add a self-referential identity check inside `createTransactionApprovers` immediately after the user-existence check:

```typescript
// In createTransactionApprovers, after line 276
if (dtoApprover.userId === user.id)
  throw new Error('Transaction creator cannot be added as an approver');
```

Apply the same guard in `updateTransactionApprover` when `dto.userId` is being set:

```typescript
// In updateTransactionApprover, after line 497
if (dto.userId === user.id)
  throw new Error('Transaction creator cannot be set as an approver');
```

Optionally, add a defense-in-depth check in `approveTransaction` to reject approval if the approver's `userId` matches the transaction's `creatorKey.userId`.

## Proof of Concept

1. Attacker (authenticated, verified user) creates a transaction — they become the creator (`creatorKey.userId = attacker.id`).
2. Attacker calls `POST /transactions/:id/approvers` with body:
   ```json
   { "approversArray": [{ "userId": <attacker_id> }] }
   ```
3. `createTransactionApprovers` calls `getCreatorsTransaction` (passes — attacker is creator), then checks only that `attacker_id` exists in the `User` table (passes trivially). The attacker is inserted as the sole approver.
4. Attacker calls `POST /transactions/:id/approvers/approve` with a valid signature over the transaction body using one of their own keys.
5. `approveTransaction` finds the attacker in the approver list (line 556), validates the signature (line 593-596), and records the approval — the transaction advances without any independent party's consent. [5](#0-4) [6](#0-5)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L47-73)
```typescript
  @Post()
  createTransactionApprovers(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() body: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    return this.approversService.createTransactionApprovers(user, transactionId, body);
  }

  /* Approves a transaction */
  @ApiOperation({
    summary: 'Approves a transaction',
    description: 'Approves the transaction with the given transaction id.',
  })
  @ApiResponse({
    status: 200,
    type: Boolean,
  })
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
