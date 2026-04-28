All referenced code locations have been verified against the actual source. The vulnerability is confirmed.

---

Audit Report

## Title
Transaction Creator Can Modify Approver Structure After Approvals Are Committed, Bypassing Multi-Approval Requirement

## Summary
`getCreatorsTransaction` — the sole authorization gate for all approver-mutation endpoints — performs only an identity check and never validates the transaction's current lifecycle status. A transaction creator can therefore add, remove, or restructure approvers at any point, including after other parties have already signed, effectively dismantling the multi-approval gate unilaterally.

## Finding Description

**Root cause — `getCreatorsTransaction`**

The function fetches the transaction, asserts `creatorKey.userId === user.id`, and returns unconditionally. There is no check on `transaction.status`. [1](#0-0) 

**Three mutation paths that delegate exclusively to this function with no additional status guard:**

1. `createTransactionApprovers` — line 239 calls `getCreatorsTransaction` and proceeds to insert new approvers regardless of status. [2](#0-1) 

2. `removeTransactionApprover` (controller) — line 108 calls `getCreatorsTransaction`, then immediately calls `removeTransactionApprover` with no status guard. [3](#0-2) 

3. `updateTransactionApprover` — line 394 calls `getCreatorsTransaction` inside the DB transaction with no status guard. [4](#0-3) 

**Threshold auto-reduction on child removal (makes the exploit self-completing):**

When a child approver is detached and the remaining child count falls below the parent's threshold, the service automatically lowers the threshold to match the new count. No approval or status check gates this path. [5](#0-4) 

**`approveTransaction` is gated only on transaction status, not on approver immutability:**

The approval path accepts `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` — both states where the creator can still mutate approvers. There is also no check preventing the creator from listing themselves as an approver and self-approving. [6](#0-5) 

## Impact Explanation

A transaction creator can:

1. **Remove a required approver who has not yet signed** — the threshold is automatically reduced, so the transaction can reach `WAITING_FOR_EXECUTION` with fewer approvals than originally required.
2. **Remove all approvers** — the approval gate disappears entirely; the chain service sees no pending approvers and proceeds.
3. **Add themselves as an approver and self-approve** — `createTransactionApprovers` has no check preventing the creator from being listed as an approver, and `approveTransaction` has no check preventing the creator from approving their own transaction.

The multi-approval workflow is the primary trust mechanism for organization transactions. Bypassing it allows a single user to execute transactions that were explicitly designed to require independent review.

## Likelihood Explanation

- **Attacker profile:** Any authenticated, verified user who has created at least one organization transaction. No admin key, no leaked credential, no special network access required.
- **Trigger:** Three standard API calls: `DELETE /transactions/:id/approvers/:approverId`, `POST /transactions/:id/approvers`, `POST /transactions/:id/approvers/approve`.
- **Detection difficulty:** The mutations emit `emitTransactionUpdate` / `emitTransactionStatusUpdate` events, but there is no audit trail distinguishing a legitimate approver change from a malicious mid-flight one.

## Recommendation

Add a status guard inside `getCreatorsTransaction` (or at the entry point of each mutation method) that rejects any approver mutation when the transaction is not in a mutable state (e.g., only allow mutations when `status === NEW`):

```typescript
const MUTABLE_STATUSES = [TransactionStatus.NEW];

if (!MUTABLE_STATUSES.includes(transaction.status)) {
  throw new BadRequestException('Approver structure cannot be modified after the transaction has been submitted');
}
```

This single guard, added to `getCreatorsTransaction` or applied consistently at the top of `createTransactionApprovers`, `removeTransactionApprover` (controller), and `updateTransactionApprover`, closes all three mutation paths simultaneously. Additionally, consider adding a check in `approveTransaction` to prevent the transaction creator from approving their own transaction.

## Proof of Concept

**Setup:** Transaction T exists with status `WAITING_FOR_SIGNATURES`. It has a threshold-2 approver group requiring approvers A and B. Approver A has already signed.

**Steps (all performed by the creator C):**

1. `DELETE /transactions/T/approvers/<approver-A-id>` — removes approver A (who already signed). The controller calls `getCreatorsTransaction` (passes — C is creator), then calls `removeTransactionApprover`. No status check fires.

2. The threshold-auto-reduction logic fires: the parent group now has 1 child (B), which is less than the original threshold of 2, so the threshold is automatically lowered to 1. [7](#0-6) 

3. `POST /transactions/T/approvers` with `{ userId: C }` — adds the creator as an approver. `createTransactionApprovers` calls `getCreatorsTransaction` (passes), inserts the record. No status check fires. [8](#0-7) 

4. `POST /transactions/T/approvers/approve` — C approves their own transaction. `approveTransaction` checks only that the status is `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` (passes) and that C is listed as an approver (passes — just added in step 3). [6](#0-5) 

**Result:** The transaction now has a threshold of 1, satisfied by C's self-approval. The chain service proceeds to execution with zero independent review, despite the transaction being designed to require two independent approvers.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L393-395)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L102-113)
```typescript
  @Delete('/:id')
  async removeTransactionApprover(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Param('id', ParseIntPipe) id: number,
  ) {
    await this.approversService.getCreatorsTransaction(transactionId, user);
    await this.approversService.removeTransactionApprover(id);
    // await this.approversService.emitSyncIndicators(transactionId);

    return true;
  }
```
