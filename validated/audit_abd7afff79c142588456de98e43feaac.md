### Title
Transaction Creator Can Self-Approve Their Own Transaction, Bypassing the Approval Workflow

### Summary
The `createTransactionApprovers` function in `approvers.service.ts` verifies that the caller is the transaction creator before allowing approver assignment, but it does not prevent the creator from designating themselves as an approver. Because `approveTransaction` only checks that the approving user is in the approver list, the creator can add themselves as an approver and immediately approve their own transaction, fully bypassing the independent-approval control the workflow is designed to enforce.

### Finding Description

**Entry point 1 — `createTransactionApprovers`:**

`createTransactionApprovers` calls `getCreatorsTransaction` to confirm the caller is the creator, then iterates over the submitted `approversArray` and inserts each entry. The only per-entry checks are: duplicate detection, parent-node existence, user existence, and threshold/children consistency. There is no check that `dtoApprover.userId !== user.id`. [1](#0-0) [2](#0-1) 

**Entry point 2 — `updateTransactionApprover`:**

The update path also verifies the caller is the creator, then allows changing an existing approver's `userId` to any valid user — including the creator's own `user.id` — with no restriction. [3](#0-2) 

**Approval path — `approveTransaction`:**

`approveTransaction` only checks that the acting user appears in the approver list and has not already submitted a signature. It does not check whether the acting user is also the transaction creator. [4](#0-3) 

**HTTP surface:**

Both operations are exposed as authenticated REST endpoints with no additional guard beyond JWT + verified-user. [5](#0-4) 

### Impact Explanation

The approval workflow exists to enforce independent review of a transaction before it advances to execution. A creator who self-approves collapses this control to zero: they create the transaction, designate themselves as the sole (or threshold-satisfying) approver, and immediately approve it. Any organization policy that relies on "at least one independent approver must sign off" is silently defeated. Depending on the threshold configuration, this can allow a single malicious or compromised user to unilaterally push a transaction to `WAITING_FOR_EXECUTION` or `EXECUTED` state without any other party's knowledge or consent.

### Likelihood Explanation

The attacker only needs a valid authenticated session and creator rights over a transaction — both are normal, unprivileged capabilities available to any registered organization user. The exploit requires two ordinary API calls and no special tooling. There is no rate-limiting or secondary confirmation that would impede it.

### Recommendation

In `createTransactionApprovers`, after confirming the caller is the creator, add a guard that rejects any leaf-node approver whose `userId` equals the creator's `user.id`:

```typescript
if (typeof dtoApprover.userId === 'number' && dtoApprover.userId === user.id) {
  throw new Error('The transaction creator cannot be added as an approver');
}
```

Apply the same guard in `updateTransactionApprover` when `dto.userId` is being set:

```typescript
if (typeof dto.userId === 'number' && dto.userId === user.id) {
  throw new Error('The transaction creator cannot be set as an approver');
}
```

The creator identity is already available in both functions via the `user` parameter passed to `getCreatorsTransaction`. [6](#0-5) 

### Proof of Concept

1. Attacker (User A) authenticates and obtains a JWT.
2. User A creates a transaction via `POST /transactions`, becoming its creator (`creatorKey.userId === A.id`).
3. User A calls `POST /transactions/:id/approvers` with body `{ "approversArray": [{ "userId": A.id }] }`. The service confirms A is the creator, finds A's user record exists, and inserts the approver row — no rejection occurs.
4. User A calls `POST /transactions/:id/approvers/approve` with a valid signature from one of their own keys. `approveTransaction` finds A in the approver list, verifies the signature, and records the approval.
5. The transaction's approval requirement is now satisfied by the creator alone. Depending on the threshold, the transaction advances to `WAITING_FOR_EXECUTION` without any independent party having reviewed or approved it. [7](#0-6) [8](#0-7)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L244-316)
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L598-620)
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

    const notificationEvent = [{ entityId: transaction.id }];

    if (!dto.approved || userApprovers.every(a => a.approved)) {
      emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
    } else {
      emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
    }

    return true;
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L623-644)
```typescript
  /* Get the transaction by id and verifies that the user is the creator */
  async getCreatorsTransaction(
    transactionId: number,
    user: User,
    entityManager?: EntityManager,
  ): Promise<Transaction> {
    const find: FindOneOptions<Transaction> = {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user'],
    };

    const transaction = await (entityManager
      ? entityManager.findOne(Transaction, find)
      : this.dataSource.manager.findOne(Transaction, find));

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to modify it');

    return transaction;
  }
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
