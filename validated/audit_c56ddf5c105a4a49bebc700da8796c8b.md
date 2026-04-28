### Title
Creator Can Self-Approve Their Own Transaction, Bypassing Multi-Party Authorization

### Summary
The Hedera Transaction Tool implements an approval workflow where a transaction creator sets up approvers who must independently authorize a transaction before it proceeds to execution. However, there is no check preventing the creator from designating themselves as an approver and then approving their own transaction. This is the direct analog of the UMA bond-penalty self-transfer: the "two-party check" collapses to a single party, nullifying the organizational authorization control entirely.

### Finding Description
**Root cause:** `createTransactionApprovers` enforces that only the creator can set up approvers, but never validates that the designated approver is a different user from the creator. `approveTransaction` then allows any user who appears in the approver list to submit an approval, with no check that the approver is not the creator.

**Code path:**

Step 1 — Creator adds themselves as approver.

`createTransactionApprovers` in `approvers.service.ts`: [1](#0-0) 

The function verifies the caller is the creator via `getCreatorsTransaction`, then iterates the DTO and creates approver records. The only user-existence check is: [2](#0-1) 

There is **no check** of the form `if (dtoApprover.userId === user.id) throw ...`. The creator's own `userId` passes all validation and is persisted as an approver record.

Step 2 — Creator approves their own transaction.

`approveTransaction` in `approvers.service.ts`: [3](#0-2) 

The function fetches all approvers, filters for `a.userId === user.id`, and proceeds if the list is non-empty. There is **no check** that `user.id !== transaction.creatorKey.userId`. The creator's self-approval record satisfies the filter, and the approval is written: [4](#0-3) 

The `TransactionApprover` entity has no database-level constraint preventing `userId` from matching the transaction creator: [5](#0-4) 

### Impact Explanation
The approval system exists to enforce multi-party authorization before a transaction is executed. A malicious creator can:
1. Create a transaction.
2. `POST /transactions/:id/approvers` with their own `userId` — accepted without error.
3. `POST /transactions/:id/approvers/approve` with a valid signature — accepted without error.

The transaction now has a fully satisfied approval record signed by the creator alone. The chain service will treat the approval requirement as met and proceed to execution. Any organizational policy that mandates independent sign-off from a second party is silently bypassed. The creator can unilaterally execute transactions that were supposed to require external authorization.

### Likelihood Explanation
Every authenticated user who creates a transaction is a potential attacker. No elevated privileges, leaked credentials, or external dependencies are required. The attack requires only two standard API calls that are part of the normal product workflow. It is trivially reproducible by any organization member.

### Recommendation
In `createTransactionApprovers`, reject any `dtoApprover.userId` that equals the creator's `user.id`:

```typescript
if (dtoApprover.userId === user.id)
  throw new Error('The transaction creator cannot be designated as an approver');
```

In `approveTransaction`, add a secondary guard:

```typescript
if (transaction.creatorKey?.userId === user.id)
  throw new UnauthorizedException('The transaction creator cannot approve their own transaction');
```

Both checks are needed: the creation guard prevents the record from being inserted; the approval guard provides defense-in-depth in case the record exists through other means (e.g., `updateTransactionApprover` changing an existing approver's `userId` to the creator's).

### Proof of Concept
1. Authenticate as user A (creator). Obtain JWT token `TOKEN_A`.
2. Create a transaction: `POST /transactions` → receive `transactionId = 42`.
3. Add self as approver:
   ```
   POST /transactions/42/approvers
   Authorization: Bearer TOKEN_A
   { "approversArray": [{ "userId": <A's userId> }] }
   ```
   Response: `201 Created` — approver record inserted with `userId = A`.
4. Approve own transaction:
   ```
   POST /transactions/42/approvers/approve
   Authorization: Bearer TOKEN_A
   { "userKeyId": <A's keyId>, "signature": "<valid sig>", "approved": true }
   ```
   Response: `200 true` — approval recorded.
5. Observe: the transaction's approval requirement is now fully satisfied by the creator alone, with no involvement from any independent party. The chain service will proceed to execute the transaction.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-240)
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L547-563)
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

    /* Check if the user has already approved the transaction */
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
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

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L56-64)
```typescript
  @ManyToOne(() => User, user => user.approvableTransactions, { nullable: true })
  @JoinColumn({ name: 'userId' })
  user?: User;

  @Column({ nullable: true })
  userId?: number;

  @Column({ nullable: true })
  approved?: boolean;
```
