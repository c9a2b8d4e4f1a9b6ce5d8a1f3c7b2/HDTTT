### Title
Transaction Creator Can Manipulate Approver Structure After Approvals Are Collected, Bypassing Governance Controls

### Summary

The `removeTransactionApprover` and `updateTransactionApprover` endpoints allow the transaction creator to remove approvers or lower the approval threshold at any point in the transaction lifecycle — including after approvals have already been collected — with no check on the current transaction status. This is a direct analog to the Teller TOCTOU: the approval requirement is verified at one point in time, but the structure governing that requirement can be silently changed before execution.

### Finding Description

The approval system is designed so that a transaction creator sets up an approver tree (with optional threshold logic), and the transaction cannot proceed to `WAITING_FOR_EXECUTION` until the required approvals are collected. The invariant that must hold is: **the approval structure in place when approvers sign must be the same structure evaluated at execution time.**

This invariant is broken because neither `removeTransactionApprover` nor `updateTransactionApprover` enforce any transaction-status guard.

**`removeTransactionApprover` in the controller** only verifies the caller is the creator via `getCreatorsTransaction`, then immediately soft-deletes the approver node: [1](#0-0) 

**`removeTransactionApprover` in the service** performs no status check before soft-deleting and emitting a status-update event: [2](#0-1) 

**`updateTransactionApprover`** similarly calls `getCreatorsTransaction` (creator check only) and then allows threshold reduction with no status guard: [3](#0-2) [4](#0-3) 

After either mutation, `emitTransactionStatusUpdate` is fired, which causes the chain service's `processTransactionStatus` to re-evaluate whether the approval threshold is now satisfied: [5](#0-4) 

**Concrete attack path — threshold lowering:**

1. Creator Alice creates a transaction with a threshold-3 approver tree (3-of-3 required).
2. Bob and Carol approve; Dave has not yet approved.
3. Alice calls `PATCH /transactions/{id}/approvers/{treeId}` with `{ threshold: 2 }`.
4. The service updates the threshold to 2 with no status check.
5. `emitTransactionStatusUpdate` fires; the scheduler sees 2 approvals against a threshold of 2 and promotes the transaction to `WAITING_FOR_EXECUTION`.
6. The transaction executes on Hedera without Dave's approval — the intended 3-of-3 governance is bypassed.

**Concrete attack path — approver removal:**

1. Creator Alice creates a transaction requiring all 3 approvers (threshold=3).
2. Bob and Carol approve; Dave has not yet approved.
3. Alice calls `DELETE /transactions/{id}/approvers/{daveId}`.
4. Dave's approver record is soft-deleted with no status check.
5. `emitTransactionStatusUpdate` fires; now 2 of 2 remaining approvers have approved, so the transaction moves to `WAITING_FOR_EXECUTION` and executes.

### Impact Explanation

The approval system is the primary governance control in organization mode. Bypassing it allows a transaction creator to execute arbitrary Hedera network transactions (account updates, file changes, token operations, node operations) without the required organizational sign-off. Approvers who already signed believed their approval was a meaningful gate; it is silently rendered irrelevant. The impact is unauthorized state changes on the Hedera network under the guise of a legitimately approved transaction.

### Likelihood Explanation

The attack requires only that the caller be the transaction creator — a standard, unprivileged role reachable by any registered organization user. No leaked credentials, admin keys, or race conditions are needed. The API endpoints are directly accessible and the manipulation is a single HTTP call. Any creator who wants to bypass the approval requirement can do so deterministically.

### Recommendation

Add a transaction-status guard at the start of both `removeTransactionApprover` and `updateTransactionApprover` (and `createTransactionApprovers`). Approver-structure mutations should only be permitted while the transaction is in `NEW` status (before it has been submitted for signing/approval). Once the transaction enters `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`, the approver tree must be immutable.

```typescript
// Example guard to add in removeTransactionApprover / updateTransactionApprover
const transaction = await this.getCreatorsTransaction(transactionId, user);
if (
  transaction.status !== TransactionStatus.NEW
) {
  throw new BadRequestException('Cannot modify approvers after transaction has been submitted');
}
```

### Proof of Concept

**Setup**: Organization with users Alice (creator), Bob, Carol, Dave. Transaction requires threshold=3 (all three must approve).

1. Alice: `POST /transactions` → creates transaction T1 in `WAITING_FOR_SIGNATURES`.
2. Alice: `POST /transactions/T1/approvers` → adds Bob, Carol, Dave with threshold=3.
3. Bob: `POST /transactions/T1/approvers/approve` → approves.
4. Carol: `POST /transactions/T1/approvers/approve` → approves. (2 of 3 collected; Dave has not approved.)
5. Alice: `PATCH /transactions/T1/approvers/{treeApproverId}` with body `{ "threshold": 2 }`.
   - Service executes `updateTransactionApprover` → no status check → threshold updated to 2.
   - `emitTransactionUpdate` fires.
6. Chain scheduler re-evaluates T1: 2 approvals ≥ threshold 2 → status promoted to `WAITING_FOR_EXECUTION`.
7. T1 executes on Hedera without Dave's approval.

**Expected**: Step 5 should be rejected because T1 is not in `NEW` status.
**Actual**: Step 5 succeeds; the 3-of-3 governance requirement is silently reduced to 2-of-3 after the fact.

### Citations

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L366-395)
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

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L153-158)
```typescript
    const results = await processTransactionStatus(this.transactionRepo, this.transactionSignatureService, transactions);

    if (results.size > 0) {
      const events = Array.from(results.keys(), id => ({ entityId: id }));
      emitTransactionStatusUpdate(this.notificationsPublisher, events);
    }
```
