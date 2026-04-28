Audit Report

## Title
Transaction Creator Can Register Themselves as an Approver, Undermining Multi-Party Approval Governance

## Summary
`createTransactionApprovers` in `approvers.service.ts` verifies the caller is the transaction creator but never checks whether any submitted `userId` in `approversArray` matches the creator's own `userId`. A creator can register themselves as an approver and then self-approve, reducing the number of genuinely independent approvals required.

## Finding Description

In `createTransactionApprovers`, the call to `getCreatorsTransaction` at line 239 confirms the caller is the creator, but its return value is discarded — the resolved `transaction` object (which carries `creatorKey.userId`) is never used for comparison against incoming approver DTOs. [1](#0-0) 

The inner `createApprover` function then validates each DTO entry with five checks — duplicate detection, parent existence, root-transaction consistency, user existence, and threshold/children consistency — but none of them compare `dtoApprover.userId` against the creator's `userId`. [2](#0-1) 

The user-existence check (the closest guard) only confirms the user exists in the database: [3](#0-2) 

There is no guard of the form `if (dtoApprover.userId === creatorUserId) throw ...`. The record is therefore persisted without error.

Once registered, `approveTransaction` only checks that `user.id` appears in the approver list and that the supplied signature is cryptographically valid — it never checks whether the approver is also the creator: [4](#0-3) [5](#0-4) 

The same gap exists in `createTransactionObservers` (no creator-vs-observer check), but the security impact there is negligible since the creator already has full visibility. [6](#0-5) 

## Impact Explanation
The approval workflow is the primary governance control for multi-party transaction authorization. If a creator occupies one approver slot and self-approves, the effective number of independent approvals required is reduced by one. In a 2-of-3 threshold structure where the creator is one of the three approvers, only one additional independent approval is needed instead of two. This directly undermines the organization's approval policy with no error or audit trail indicating the approval came from the transaction originator.

## Likelihood Explanation
The exploit requires no special privileges beyond being a normal authenticated organization user who creates a transaction. The `POST /transactions/:transactionId/approvers` endpoint is reachable by any creator, and the payload is trivially constructed by including the creator's own `userId` in `approversArray`. No race condition, timing dependency, or cryptographic weakness is required. [7](#0-6) 

## Recommendation
Capture the return value of `getCreatorsTransaction` and compare each `dtoApprover.userId` against `transaction.creatorKey.userId` before persisting:

```typescript
const transaction = await this.getCreatorsTransaction(transactionId, user);
// inside createApprover:
if (typeof dtoApprover.userId === 'number' &&
    dtoApprover.userId === transaction.creatorKey.userId) {
  throw new Error('Transaction creator cannot be registered as an approver');
}
```

Apply the same guard in `updateTransactionApprover` when `dto.userId` is being updated, to prevent the creator from being substituted in via an update. [8](#0-7) 

## Proof of Concept

1. Authenticated user **Alice** (userId = 1) creates a transaction (transactionId = 42).
2. Alice calls `POST /transactions/42/approvers` with body:
   ```json
   { "approversArray": [{ "userId": 1 }] }
   ```
3. The service confirms Alice is the creator (passes), checks user 1 exists (passes), and persists the `TransactionApprover` record with `userId = 1`.
4. Alice calls `POST /transactions/42/approvers/approve` with a valid signature from one of her keys.
5. `approveTransaction` finds `userApprovers` containing Alice's record, validates the signature, and marks the approval — consuming one approval slot without any independent party being involved.
6. In a 2-of-3 threshold, only one more external approval is now needed to reach the threshold, instead of two. [9](#0-8)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L245-316)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L353-355)
```typescript
        for (const approver of dto.approversArray) {
          await createApprover(approver);
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L547-621)
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
  }
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L44-54)
```typescript
    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to delete it');

    const observers: TransactionObserver[] = [];

    for (const userId of dto.userIds) {
      if (!transaction.observers.some(o => o.userId === userId)) {
        const observer = this.repo.create({ userId, transactionId, role: Role.FULL });
        observers.push(observer);
      }
    }
```
