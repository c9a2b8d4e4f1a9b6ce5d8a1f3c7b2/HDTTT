Audit Report

## Title
Transaction Creator Can Modify Approval Threshold on In-Progress Transactions, Bypassing Multi-Signature Requirements

## Summary
`updateTransactionApprover` in `approvers.service.ts` allows the transaction creator to lower the `threshold` (or restructure the approver tree) on transactions already in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` status. Neither `updateTransactionApprover` nor `getCreatorsTransaction` checks `transaction.status` before mutating approver records. A malicious creator can lower the threshold after partial approvals have been collected, causing the scheduler to advance the transaction with fewer signatures than originally required.

## Finding Description

**Root cause — missing status guard in `updateTransactionApprover`**

`updateTransactionApprover` (lines 367–531) performs four checks before mutating an approver record:

1. DTO has exactly one field — line 378.
2. Approver exists — line 382–383.
3. Root node's `transactionId` matches the URL param — line 390–391.
4. Caller is the transaction creator via `getCreatorsTransaction` — line 394. [1](#0-0) 

None of these checks inspect `transaction.status`. `getCreatorsTransaction` (lines 624–644) only verifies ownership via `creatorKey.userId !== user.id` and never reads `transaction.status`: [2](#0-1) 

The threshold-update branch (lines 467–488) then writes the new value unconditionally once the structural validity checks pass: [3](#0-2) 

The unit-test fixture for `updateTransactionApprover` explicitly sets `status: TransactionStatus.WAITING_FOR_EXECUTION`, confirming the update succeeds in that state with no rejection: [4](#0-3) 

The HTTP surface is `PATCH /transactions/:transactionId/approvers/:id`, accessible to any authenticated creator: [5](#0-4) 

**Secondary vector — automatic threshold reduction on approver removal**

`removeTransactionApprover` (lines 534–544) also has no status guard: [6](#0-5) 

When a child approver is detached via `listId: null`, the parent's threshold is silently reduced if it would otherwise exceed the remaining child count: [7](#0-6) 

This gives the creator a second path to lower the effective approval bar after signatures have been collected.

## Impact Explanation
The multi-signature approval model is the primary trust boundary for organization-mode transactions. Approvers consent to sign under a specific threshold (e.g., 3-of-5). If the creator lowers the threshold to 2-of-5 after two approvals are already recorded, the scheduler's next `processTransactionStatus` pass will find the approval condition satisfied and advance the transaction to `WAITING_FOR_EXECUTION` or trigger submission — with fewer approvals than the approvers agreed to. This constitutes an unauthorized state change: the creator unilaterally overrides the multi-party governance rule, defeating the purpose of the approval workflow.

## Likelihood Explanation
The creator is a normal authenticated user with no elevated privileges. The attack requires only:
1. Create a transaction with a threshold > 1.
2. Wait for at least one approver to approve.
3. Call `PATCH /transactions/:id/approvers/:approverId` with `{ "threshold": 1 }`.

No leaked credentials, no admin access, and no race condition are required. The endpoint is documented and reachable in production.

## Recommendation
Add a transaction-status guard at the start of `updateTransactionApprover` (and in the controller before `removeTransactionApprover`) that rejects mutations when `transaction.status` is `WAITING_FOR_SIGNATURES`, `WAITING_FOR_EXECUTION`, or any terminal state. The guard should be placed inside `getCreatorsTransaction` or as an explicit check immediately after it is called, so all approver-mutation paths are covered uniformly. The `approveTransaction` method already demonstrates the correct pattern for this check: [8](#0-7) 

Apply the same pattern to `updateTransactionApprover` and `removeTransactionApprover`.

## Proof of Concept
```
# 1. Creator sets up a 2-of-3 threshold transaction
POST /transactions
{ ..., approvers: [{ threshold: 2, approvers: [userA, userB, userC] }] }
→ transactionId=42, approverId=10 (the tree node)

# 2. UserA approves
POST /transactions/42/approvers/approve
{ signature: "...", approved: true }

# 3. Creator lowers threshold to 1 — no status guard blocks this
PATCH /transactions/42/approvers/10
{ "threshold": 1 }
→ 200 OK, threshold updated to 1

# 4. Scheduler runs processTransactionStatus:
#    approved count (1) >= threshold (1) → transaction advances
#    Transaction submitted with only 1 of the original 3 required signatures
```

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L376-394)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L417-428)
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L534-544)
```typescript
  async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);

    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const result = await this.removeNode(approver.id);

    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);

    return result;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L583-588)
```typescript
    /* Checks if the transaction is requires approval */
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L624-644)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.spec.ts (L704-709)
```typescript
    const transaction = {
      id: 1,
      creatorKey: { userId: user.id },
      status: TransactionStatus.WAITING_FOR_EXECUTION,
      mirrorNetwork: 'testnet',
    };
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L125-133)
```typescript
  @Patch('/:id')
  async updateTransactionApprover(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Param('id', ParseIntPipe) id: number,
    @Body() body: UpdateTransactionApproverDto,
  ): Promise<TransactionApprover> {
    return this.approversService.updateTransactionApprover(id, body, transactionId, user);
  }
```
