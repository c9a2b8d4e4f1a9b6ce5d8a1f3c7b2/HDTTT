Let me check the backend's approval evaluation logic for transaction status transitions.

Audit Report

## Title
Transaction Creator Can Manipulate Approval Outcome by Modifying `threshold` After Approvals Are Collected

## Summary
The `updateTransactionApprover` function in `approvers.service.ts` permits the transaction creator to modify the `threshold` of an approver tree node at any point during the transaction lifecycle, including while the transaction is actively in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` status. No transaction status check is performed before the update is applied. Because the approval evaluation logic reads the live `threshold` value from the database, the creator can retroactively lower or raise the threshold to manipulate whether the transaction is considered approved.

## Finding Description

The `TransactionApprover` entity stores a mutable `threshold` column with no immutability constraint: [1](#0-0) 

The `updateTransactionApprover` function in `approvers.service.ts` handles threshold updates. The only guards applied are: (1) the caller must be the transaction creator, verified via `getCreatorsTransaction`, and (2) the new threshold must be `<= number of child approvers` and `!= 0`: [2](#0-1) 

The `getCreatorsTransaction` helper — the sole authorization check called before the update — only verifies creator identity. It does **not** inspect the transaction's current status: [3](#0-2) 

There is no status check anywhere in the `updateTransactionApprover` flow. The unit test for this function explicitly uses `TransactionStatus.WAITING_FOR_EXECUTION` as the transaction state and the threshold update succeeds without error, confirming the absence of any status guard: [4](#0-3) 

The approval evaluation logic (`isApproved`) reads the live `threshold` value directly from the approver object (which reflects the current database value), not a value frozen at transaction creation time: [5](#0-4) 

The `PATCH /:id` endpoint exposes this directly with no additional guards: [6](#0-5) 

## Impact Explanation

**Scenario A — Creator lowers threshold to force passage:**
1. Creator sets up a transaction with an approver tree requiring `threshold = 3` out of 5 approvers.
2. Only 2 approvers sign/approve.
3. Creator calls `PATCH /transactions/:id/approvers/:approverId` with `{ "threshold": 2 }`.
4. The transaction is now evaluated as approved with only 2 signatures, bypassing the originally agreed-upon 3-of-5 requirement.

**Scenario B — Creator raises threshold to block passage:**
1. Creator sets up a transaction with `threshold = 1` out of 3 approvers.
2. One approver approves, satisfying the original threshold.
3. Creator raises `threshold` to 3.
4. The transaction can no longer pass even though it met the threshold at the time of approval.

Both scenarios undermine the integrity of the multi-signature approval workflow, which is the core security guarantee of the system.

## Likelihood Explanation

The transaction creator is not a fully trusted role in the context of multi-party approval. The entire purpose of the approver system is to require independent sign-off from other users. The creator has direct API access to `PATCH /transactions/:transactionId/approvers/:id` and can exploit this at any point during the approval lifecycle. No special privileges beyond being the transaction creator are required. The exploit requires a single authenticated API call.

## Recommendation

Add a transaction status check at the beginning of `updateTransactionApprover` (or inside `getCreatorsTransaction` when called from this context) to reject modifications when the transaction is in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` status. Approver structure — including thresholds — should be locked once the transaction moves past the draft/setup phase. The same status guard already applied in `approveTransaction` (lines 584–588) should be mirrored here.

## Proof of Concept

```
# 1. Creator creates a transaction with threshold=3 (3-of-5 approvers required)
POST /transactions/1/approvers
{ "approversArray": [{ "threshold": 3, "approvers": [{"userId":2},{"userId":3},{"userId":4},{"userId":5},{"userId":6}] }] }

# 2. Two approvers submit their approvals (threshold not yet met)
POST /transactions/1/approvers/approve  (as user 2)
POST /transactions/1/approvers/approve  (as user 3)

# 3. Creator lowers threshold to 2 while transaction is WAITING_FOR_SIGNATURES
PATCH /transactions/1/approvers/<tree_node_id>
Authorization: Bearer <creator_token>
{ "threshold": 2 }
# Returns 200 OK — no status check performed

# 4. isApproved() now evaluates the tree with threshold=2 and finds 2 approvals >= 2 → approved
# Transaction proceeds as if the 3-of-5 requirement was satisfied
```

### Citations

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L43-44)
```typescript
  @Column({ nullable: true })
  threshold?: number;
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.spec.ts (L1151-1172)
```typescript
    it('should update the threshold of a tree', async () => {
      const transactionId = 1;
      const dto: UpdateTransactionApproverDto = {
        threshold: 1,
      };

      jest.spyOn(service, 'getTransactionApproverById').mockResolvedValueOnce({ ...treeApprover });
      jest.spyOn(service, 'getRootNodeFromNode').mockResolvedValueOnce({ ...treeApprover });
      dataSource.manager.findOne
        .calledWith(TransactionApprover, expect.anything())
        .mockResolvedValueOnce({ ...treeApprover });
      dataSource.manager.findOne
        .calledWith(Transaction, expect.anything())
        .mockResolvedValueOnce(transaction);

      await service.updateTransactionApprover(treeApprover.id, dto, transactionId, user);

      expect(dataSource.manager.update).toHaveBeenCalledWith(TransactionApprover, treeApprover.id, {
        threshold: 1,
      });
      expect(emitTransactionUpdate).toHaveBeenCalledWith(notificationsPublisher, [{ entityId: transactionId  }]);
    });
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
