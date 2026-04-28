### Title
Transaction Creator Can Manipulate Approver List at Any Time to Bypass Multi-Party Approval Requirements

### Summary
The `updateTransactionApprover` and `createTransactionApprovers` functions in `approvers.service.ts` allow the transaction creator (a normal authenticated user) to modify the approver list of a transaction at any time, with no check on the transaction's current status. A malicious creator can replace pending approvers with accounts they control — including themselves — after legitimate approvers have already signed, then self-approve to satisfy the threshold and advance the transaction without the intended organizational consent.

### Finding Description

The root cause is in `getCreatorsTransaction`, which is the sole authorization gate used by both `createTransactionApprovers` and `updateTransactionApprover`: [1](#0-0) 

This function only verifies that the calling user is the creator of the transaction. It performs **no check on the transaction's current status** (e.g., `WAITING_FOR_SIGNATURES`, `WAITING_FOR_EXECUTION`). As a result, the creator can modify approvers at any lifecycle stage.

`createTransactionApprovers` calls this gate with no status guard: [2](#0-1) 

`updateTransactionApprover` calls the same gate with no status guard: [3](#0-2) 

When a `userId` update is applied, the existing approver's signature, `userKeyId`, and `approved` fields are cleared for that slot only — other already-approved slots are untouched: [4](#0-3) 

There is no check in `createTransactionApprovers` or `updateTransactionApprover` preventing the creator from designating themselves as an approver: [5](#0-4) 

And `approveTransaction` does not prevent the creator from approving their own transaction if they appear in the approver list: [6](#0-5) 

### Impact Explanation

The approval system is the organizational governance control that ensures multiple designated parties consent to a transaction before it is submitted to the Hedera network. By replacing a pending approver with themselves (or a controlled account) after other approvers have already signed, the creator can satisfy any threshold requirement unilaterally. This constitutes an unauthorized state change: a transaction advances to `WAITING_FOR_EXECUTION` and is submitted to Hedera without the genuine consent of all required approvers. For Hedera Council use cases, this could mean unauthorized fund transfers, account updates, or other privileged network operations.

### Likelihood Explanation

The attacker is any authenticated user who creates a transaction — no admin or privileged role is required. The API endpoint for updating approvers is a standard authenticated REST call. The attack requires only that the creator wait for at least one legitimate approver to sign (to avoid suspicion), then replace the remaining unsigned approver slot with themselves. The steps are deterministic and require no race condition or special timing.

### Recommendation

Add a transaction status check inside `getCreatorsTransaction` (or at the entry of `createTransactionApprovers`, `updateTransactionApprover`, and `removeTransactionApprover`) that rejects modifications when the transaction is in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` status — i.e., once the approval collection phase has begun. Approver structure should only be mutable while the transaction is in `NEW` status. Additionally, add an explicit check preventing the creator from designating themselves as an approver.

### Proof of Concept

1. Creator (User A) creates a transaction and sets approvers: `[User B (threshold slot 1), User C (threshold slot 2)]` with threshold = 2.
2. User B calls `POST /transactions/:id/approvers/:approverId/approve` and submits a valid signature. Their slot is now `approved = true`.
3. Creator (User A) calls `PATCH /transactions/:id/approvers/:approverIdForUserC` with body `{ "userId": <User A's own id> }`. The service executes:
   - Clears User C's slot (`signature = undefined`, `approved = undefined`)
   - Sets `userId` to User A
   - No status check blocks this — transaction is `WAITING_FOR_SIGNATURES`
4. Creator (User A) calls `POST /transactions/:id/approvers/:approverIdForUserA/approve` with their own valid key signature. Their slot is now `approved = true`.
5. Both slots are now approved. The transaction advances to `WAITING_FOR_EXECUTION` and is submitted to Hedera — without User C's consent. [3](#0-2) [7](#0-6)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L270-277)
```typescript
          /* Check if the user exists */
          if (typeof dtoApprover.userId === 'number') {
            const userCount = await transactionalEntityManager.count(User, {
              where: { id: dtoApprover.userId },
            });

            if (userCount === 0) throw new Error(this.USER_NOT_FOUND(dtoApprover.userId));
          }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L366-394)
```typescript
  /* Updates an approver of a transaction */
  async updateTransactionApprover(
    id: number,
    dto: UpdateTransactionApproverDto,
    transactionId: number,
    user: User,
  ): Promise<TransactionApprover> {
    try {
      let updated = false;

      const approver = await this.dataSource.transaction(async transactionalEntityManager => {
        /* Check if the dto updates only one thing */
        if (Object.keys(dto).length > 1 || Object.keys(dto).length === 0)
          throw new Error(this.INVALID_UPDATE_APPROVER);

        /* Verifies that the approver exists */
        const approver = await this.getTransactionApproverById(id, transactionalEntityManager);
        if (!approver) throw new BadRequestException(ErrorCodes.ANF);

        /* Gets the root approver */
        const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
        if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

        /* Verifies that the root transaction is the same as the param */
        if (rootNode.transactionId !== transactionId)
          throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

        /* Verifies that the user is the creator of the transaction */
        await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L547-610)
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

    /* Ensures the user keys are passed */
    await attachKeys(user, this.dataSource.manager);
    if (user.keys.length === 0) return false;

    const signatureKey = user.keys.find(key => key.id === dto.userKeyId);

    /* Gets the public key that the signature belongs to */
    const publicKey = PublicKey.fromString(signatureKey?.publicKey);

    /* Get the transaction body */
    const transaction = await this.dataSource.manager.findOne(Transaction, {
      where: { id: transactionId },
      relations: { creatorKey: true, observers: true },
    });

    /* Check if the transaction exists */
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    /* Checks if the transaction is requires approval */
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    /* Verify the signature matches the transaction */
    if (
      !verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTransaction, dto.signature, publicKey)
    )
      throw new BadRequestException(ErrorCodes.SNMP);

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
