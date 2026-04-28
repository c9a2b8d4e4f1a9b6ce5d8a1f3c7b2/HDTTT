### Title
Transaction Creator Can Register Themselves as an Approver, Undermining Multi-Party Approval Governance

### Summary
In `createTransactionApprovers` within `approvers.service.ts`, there is no validation to ensure that the `userId` being registered as an approver is not the same as the transaction creator's `userId`. A malicious creator can add themselves as an approver and then self-approve the transaction, reducing the number of genuinely independent approvals required by the organization's governance model.

### Finding Description

The `createTransactionApprovers` function in `back-end/apps/api/src/transactions/approvers/approvers.service.ts` validates several constraints when adding approvers — it checks for duplicate approvers, parent node existence, user existence, and threshold consistency — but it never checks whether the `userId` being added as an approver matches the transaction creator's `userId`. [1](#0-0) 

The function first verifies the caller is the creator: [2](#0-1) 

Then iterates over the submitted approver DTOs and only checks that the user exists in the database: [3](#0-2) 

There is no guard of the form `if (dtoApprover.userId === transaction.creatorKey.userId) throw ...`. The creator can therefore submit their own `userId` in the `approversArray`, and the record is persisted without error. [4](#0-3) 

Once registered as an approver, the creator can call `approveTransaction`. That function only checks that the caller is listed as an approver and that the signature is valid — it does not check whether the approver is also the creator: [5](#0-4) 

The same gap exists in `createTransactionObservers` in `observers.service.ts` — the creator can add themselves as an observer — but the impact there is negligible since the creator already has full visibility. The approver path is the exploitable one. [6](#0-5) 

### Impact Explanation

The approval workflow is the primary governance control for multi-party transaction authorization in organization mode. If a creator can occupy one approver slot and self-approve, the effective number of independent approvals required is reduced by one. For example, in a 2-of-3 threshold structure where the creator is one of the three approvers, the creator's self-approval means only one additional independent approval is needed instead of two. This directly undermines the integrity of the organization's approval policy without any error or audit trail indicating the approval came from the transaction originator.

### Likelihood Explanation

The exploit requires no special privileges beyond being a normal authenticated organization user who creates a transaction. The `POST /transactions/:transactionId/approvers` endpoint is reachable by any creator, and the payload is trivially constructed by including the creator's own `userId` in `approversArray`. No race condition, timing dependency, or cryptographic weakness is required. [7](#0-6) 

### Recommendation

In `createTransactionApprovers`, after fetching the transaction and confirming the caller is the creator, add a check that rejects any `userId` in the submitted `approversArray` that matches `transaction.creatorKey.userId`:

```typescript
if (dtoApprover.userId === transaction.creatorKey?.userId)
  throw new Error('Transaction creator cannot be registered as an approver');
```

Apply the same guard in `createTransactionObservers` for consistency, even though the observer-path impact is lower. [3](#0-2) 

### Proof of Concept

1. Authenticate as user A (the creator). Obtain a JWT token.
2. Create a transaction via `POST /transactions`. Note the returned `transactionId`.
3. Call `POST /transactions/:transactionId/approvers` with body:
   ```json
   { "approversArray": [{ "userId": <creator_user_id> }] }
   ```
   The request succeeds with HTTP 201 and the creator's record is inserted as an approver.
4. Call `POST /transactions/:transactionId/approvers/:approverId/approve` (or the equivalent `POST /transactions/:transactionId/approvers/approve`) signed with the creator's own key.
5. The approval is accepted. The creator's approval now counts toward the threshold, reducing the number of genuinely independent approvals required for the transaction to proceed. [8](#0-7)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L547-620)
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

    const notificationEvent = [{ entityId: transaction.id }];

    if (!dto.approved || userApprovers.every(a => a.approved)) {
      emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
    } else {
      emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
    }

    return true;
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L49-54)
```typescript
    for (const userId of dto.userIds) {
      if (!transaction.observers.some(o => o.userId === userId)) {
        const observer = this.repo.create({ userId, transactionId, role: Role.FULL });
        observers.push(observer);
      }
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
