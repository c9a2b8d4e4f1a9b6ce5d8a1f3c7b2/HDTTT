### Title
Transaction Creator Can Self-Approve Their Own Transaction by Adding Themselves as an Approver

### Summary
The `createTransactionApprovers` function in `approvers.service.ts` allows a transaction creator to register their own `userId` as an approver of their own transaction. Because `approveTransaction` only checks that the approving user appears in the approvers list — with no check that the approver is not the creator — the creator can unilaterally satisfy the approval requirement, defeating the purpose of the independent approval mechanism.

### Finding Description

**Root cause — missing self-reference check in `createTransactionApprovers`:**

`createTransactionApprovers` begins by calling `getCreatorsTransaction`, which confirms the caller **is** the creator. [1](#0-0) 

It then validates the approver DTO. The only user-existence check is: [2](#0-1) 

There is **no check** that `dtoApprover.userId !== user.id`. The creator can freely pass their own `userId` in the `approversArray`, and the record is inserted without restriction. [3](#0-2) 

**Root cause — missing creator-exclusion check in `approveTransaction`:**

`approveTransaction` only verifies that the calling user appears in the approvers list: [4](#0-3) 

There is no check that the approving user is not the transaction creator. Once the creator has added themselves as an approver, they can call this endpoint and their approval is accepted as a valid independent approval. [5](#0-4) 

**The `updateTransactionApprover` path is equally affected:** when updating an approver's `userId`, the same pattern applies — only existence is checked, not whether the new `userId` equals the creator's. [6](#0-5) 

**API entry point** (no additional guard): [7](#0-6) 

### Impact Explanation
The approver mechanism exists to enforce independent oversight before a transaction is executed. A creator who can self-approve removes that independence entirely: they can create a transaction, add themselves as the sole approver, and approve it — all without any other party's involvement. This allows a malicious organization member to push arbitrary Hedera transactions (account updates, token operations, file changes, etc.) through the approval gate without genuine multi-party consent, violating the core trust model of the organization mode.

### Likelihood Explanation
Exploitation requires only a valid authenticated session and the ability to create a transaction — both are normal user capabilities with no privileged access needed. The steps are straightforward API calls available to any organization member who can create transactions. There is no race condition or timing dependency.

### Recommendation
1. In `createTransactionApprovers`, after confirming the caller is the creator, add:
   ```typescript
   if (dtoApprover.userId === user.id)
     throw new Error('Creator cannot add themselves as an approver');
   ```
2. Apply the same guard in `updateTransactionApprover` when `dto.userId` is being set.
3. Optionally, add a symmetric check in `approveTransaction` to reject approval if `transaction.creatorKey?.userId === user.id`, as defense-in-depth.

### Proof of Concept

1. Attacker (user A, `id = 42`) authenticates and creates a transaction, becoming its creator (`creatorKey.userId = 42`).
2. Attacker calls:
   ```
   POST /transactions/{txId}/approvers
   Body: { "approversArray": [{ "userId": 42 }] }
   ```
   `createTransactionApprovers` confirms the caller is the creator (passes `getCreatorsTransaction`), then checks only that user `42` exists in the `user` table — which it does. The approver record `{ userId: 42, transactionId: txId }` is inserted.
3. Attacker calls:
   ```
   POST /transactions/{txId}/approvers/approve
   Body: { "userKeyId": <their key id>, "signature": <valid sig>, "approved": true }
   ```
   `approveTransaction` finds `userApprovers = [{ userId: 42 }]`, length > 0, proceeds, verifies the signature against the transaction body, and marks the approver record as approved.
4. The transaction now has a satisfied approval requirement — set and fulfilled entirely by the creator — and proceeds toward execution without any independent party's consent.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L309-336)
```typescript
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
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L493-517)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L555-560)
```typescript
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
