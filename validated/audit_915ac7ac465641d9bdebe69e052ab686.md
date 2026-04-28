### Title
Transaction Creator Can Retroactively Tip Approval Threshold by Modifying Approver Configuration on a Pending Transaction

### Summary
The `updateTransactionApprover` and `removeTransactionApprover` functions in `ApproversService` allow the transaction creator to modify the approver tree (threshold value, approver membership) of a transaction that is already in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` status. Because no status guard exists on these mutation paths, a creator who has collected fewer approvals than originally required can lower the threshold (or detach/remove approvers) to retroactively satisfy the approval condition, causing the transaction to be tipped to `WAITING_FOR_EXECUTION` and subsequently executed without the originally agreed-upon number of approvals.

### Finding Description

**Root cause — missing transaction-status guard in approver mutation functions**

`getCreatorsTransaction`, the only authorization check called by `createTransactionApprovers` and `updateTransactionApprover`, verifies only that the caller is the transaction creator. It never inspects `transaction.status`. [1](#0-0) 

`removeTransactionApprover` performs no authorization or status check at all before soft-deleting the approver node. [2](#0-1) 

**Path 1 — direct threshold reduction via `updateTransactionApprover`**

When `dto.threshold` is supplied, the function validates only that the new value is `≤ approver.approvers.length` and `> 0`. There is no check that the transaction is still in `NEW` status or that no approvals have been collected yet. [3](#0-2) 

After the update, `emitTransactionUpdate` is published. The periodic scheduler then calls `processTransactionStatus`, which re-evaluates the approval state against the now-lowered threshold and transitions the transaction to `WAITING_FOR_EXECUTION` if the condition is met. [4](#0-3) 

**Path 2 — implicit threshold reduction via child detachment**

When `dto.listId === null` is supplied (detaching a child from its parent), the code automatically lowers the parent's threshold to `newParentApproversLength` if the current threshold exceeds the remaining child count. [5](#0-4) 

This implicit reduction is followed by `emitTransactionUpdate`, again feeding into the scheduler's re-evaluation loop.

**Path 3 — approver removal via `removeTransactionApprover`**

`removeTransactionApprover` soft-deletes the approver node and immediately calls `emitTransactionStatusUpdate`, which triggers synchronous status re-evaluation in the notifications service. If removing the approver causes the remaining approved count to satisfy the (unchanged) threshold, the transaction is tipped immediately. [2](#0-1) 

**Approval evaluation logic**

The approval check counts approvals against the threshold: [6](#0-5) 

Lowering `threshold` to match the number of already-approved users causes `approvals.length >= approver.threshold` to become true, marking the tree as approved.

### Impact Explanation

The transaction creator can unilaterally bypass the multi-party approval requirement. After collecting fewer approvals than originally required, the creator lowers the threshold (or removes unapproved approvers) to make the existing approvals sufficient. The transaction then transitions to `WAITING_FOR_EXECUTION` and is submitted to the Hedera network. Approvers who had not yet voted — and who may have intended to reject — are bypassed. This breaks the integrity of the multi-signature coordination workflow, which is the core security guarantee of the platform.

### Likelihood Explanation

The attacker is the transaction creator, a role reachable by any authenticated organization member with no elevated privileges. The API endpoints for `updateTransactionApprover` and `removeTransactionApprover` are standard REST calls. The creator already has legitimate access to these endpoints. No special tooling, leaked credentials, or cryptographic breaks are required. The scenario is realistic whenever a creator anticipates that a required approver will reject the transaction.

### Recommendation

Add a transaction-status guard at the top of `createTransactionApprovers`, `updateTransactionApprover`, and `removeTransactionApprover`. Reject any modification when the transaction status is not `NEW` (i.e., when approvals may already have been collected):

```typescript
// Inside getCreatorsTransaction or at the start of each mutating function:
if (transaction.status !== TransactionStatus.NEW) {
  throw new BadRequestException(
    'Cannot modify approvers after the transaction has left NEW status',
  );
}
```

This mirrors the remediation applied in the referenced SPL Governance audit (PR #56), which blocked collection configuration changes while voting proposals were outstanding. [7](#0-6) 

### Proof of Concept

1. Creator (User C) creates a transaction and sets up an approver tree: threshold = 3, approvers = [User A, User B, User D].
2. User A and User B call `approveTransaction` with `approved: true`. The transaction now has 2 of 3 required approvals.
3. Creator calls `PATCH /transactions/{id}/approvers/{root_node_id}` with body `{ "threshold": 2 }`.
   - `updateTransactionApprover` accepts the request (no status check).
   - The threshold is persisted as 2.
   - `emitTransactionUpdate` is published.
4. The scheduler's next `updateTransactions` tick calls `processTransactionStatus`. It finds 2 approvals against a threshold of 2 → condition satisfied.
5. The transaction transitions to `WAITING_FOR_EXECUTION` and is submitted to the Hedera network.
6. User D, who would have rejected, was never consulted. [8](#0-7) [3](#0-2) [4](#0-3)

### Citations

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L417-429)
```typescript
            if (parent) {
              const newParentApproversLength = parent.approvers.length - 1;

              /* Soft delete the parent if there are no more children */
              if (newParentApproversLength === 0) {
                await transactionalEntityManager.softRemove(TransactionApprover, parent);
              } else if (newParentApproversLength < parent.threshold) {
                /* Update the parent threshold if the current one is more than the children */
                await transactionalEntityManager.update(TransactionApprover, parent.id, {
                  threshold: newParentApproversLength,
                });
              }
            }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L467-488)
```typescript
        } else if (typeof dto.threshold === 'number') {
          /* Check if the approver is a tree */
          if (typeof approver.threshold !== 'number' || typeof approver.userId === 'number')
            throw new Error(this.APPROVER_NOT_TREE);

          /* Check if the approver threshold is less or equal to the number of approvers */
          if (
            approver.approvers &&
            (dto.threshold > approver.approvers.length || dto.threshold === 0)
          )
            throw new Error(this.THRESHOLD_LESS_OR_EQUAL_APPROVERS(approver.approvers.length));

          /* Update the threshold */
          if (approver.threshold !== dto.threshold) {
            await transactionalEntityManager.update(TransactionApprover, approver.id, {
              threshold: dto.threshold,
            });
            approver.threshold = dto.threshold;
            updated = true;

            return approver;
          }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L533-544)
```typescript
  /* Removes the transaction approver by id */
  async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);

    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const result = await this.removeNode(approver.id);

    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);

    return result;
  }
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

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L130-158)
```typescript
  /* Checks if the signers are enough to sign the transactions and update their statuses */
  async updateTransactions(from: Date, to?: Date) {
    //Get the transaction, creatorKey, groupItem, and group. We need the group info upfront
    //in order to determine if the group needs to be processed together
    const transactions = await this.transactionRepo.find({
      where: {
        status: In([
          TransactionStatus.WAITING_FOR_SIGNATURES,
          TransactionStatus.WAITING_FOR_EXECUTION,
        ]),
        validStart: to ? Between(from, to) : MoreThan(from),
      },
      relations: {
        creatorKey: true,
        groupItem: {
          group: true,
        },
      },
      order: {
        validStart: 'ASC',
      },
    });

    const results = await processTransactionStatus(this.transactionRepo, this.transactionSignatureService, transactions);

    if (results.size > 0) {
      const events = Array.from(results.keys(), id => ({ entityId: id }));
      emitTransactionStatusUpdate(this.notificationsPublisher, events);
    }
```

**File:** front-end/src/renderer/utils/sdk/index.ts (L342-361)
```typescript
export const isApproved = (approver: ITransactionApprover): boolean | null => {
  if (approver.approved === false) {
    return false;
  }

  if (approver.approved === true) {
    return true;
  }

  if (approver.approvers) {
    const approvals = approver.approvers.filter(approver => isApproved(approver) === true);
    const rejections = approver.approvers.filter(approver => isApproved(approver) === false);
    if (approvals.length >= (approver.threshold || approvals.length)) {
      return true;
    }
    return rejections.length >= (approver.threshold || rejections.length) ? false : null;
  }

  return null;
};
```
