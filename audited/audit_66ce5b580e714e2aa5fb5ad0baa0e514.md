### Title
Transaction Creator Can Modify Approvers After Rejection, Bypassing Multi-Signature Approval Enforcement

### Summary
The `createTransactionApprovers`, `updateTransactionApprover`, and `removeTransactionApprover` operations perform no transaction-status check before mutating the approver set. A malicious transaction creator can remove a rejecting approver and substitute a new one after a rejection has been recorded, cycling through approvers until the transaction is approved. This is the direct analog of the external report's "accepting input after a critical state change" class: here the critical state is an approver's rejection decision, and the unchecked input is the creator's ability to restructure the approver tree at any lifecycle stage.

### Finding Description

**Root cause — `getCreatorsTransaction` checks identity only, never status**

`getCreatorsTransaction` is the sole gate used by all three mutation paths. It verifies that the caller is the transaction creator but performs no status check: [1](#0-0) 

**Path 1 — `createTransactionApprovers` (POST `/transactions/:id/approvers`)**

The function calls `getCreatorsTransaction` and then proceeds to insert new approver records with zero status validation: [2](#0-1) 

The unit-test fixture for this function explicitly uses `TransactionStatus.EXPIRED` as the transaction state and the test still passes, confirming no status guard exists: [3](#0-2) 

**Path 2 — `removeTransactionApprover` (DELETE `/transactions/:id/approvers/:id`)**

The controller calls `getCreatorsTransaction` (identity only) and then delegates to `removeTransactionApprover`, which also has no status check: [4](#0-3) [5](#0-4) 

**Path 3 — `updateTransactionApprover` (PATCH `/transactions/:id/approvers/:id`)**

Same pattern — `getCreatorsTransaction` is called inside the transaction block, no status guard: [6](#0-5) 

**Contrast with `approveTransaction`**, which correctly enforces status: [7](#0-6) 

The approval action is gated; the approver-set mutation actions are not.

**Side-effect that amplifies the impact — automatic threshold reduction on removal**

When a child approver is removed, `updateTransactionApprover` silently lowers the parent threshold to match the new child count: [8](#0-7) 

Removing one rejecting approver from a 2-of-2 tree automatically converts it to a 1-of-1 tree, so the remaining approver's prior approval alone satisfies the new threshold.

### Impact Explanation

The multi-signature approval workflow exists to ensure that a transaction cannot be submitted to the Hedera network without the consent of all designated approvers. By removing a rejecting approver and optionally adding a compliant one, the transaction creator can:

1. Nullify any rejection decision made by a legitimate approver.
2. Reduce the effective approval threshold by exploiting the automatic threshold-reduction logic.
3. Cycle through approvers until the transaction reaches `WAITING_FOR_EXECUTION`, at which point the chain service submits it to Hedera.

The entire organizational approval control is rendered ineffective for any creator willing to act maliciously.

### Likelihood Explanation

The attacker is the transaction creator — a normal authenticated user with no elevated privileges. The attack requires only standard API calls (`DELETE` then `POST` on `/transactions/:id/approvers`) that are part of the documented workflow. No leaked credentials, no admin access, and no race condition are required. The creator has a clear motive: they want their transaction submitted despite a rejection. Likelihood is **medium-high**.

### Recommendation

Add a status guard at the top of `createTransactionApprovers`, `updateTransactionApprover`, and `removeTransactionApprover` (or inside `getCreatorsTransaction` when called from these paths) that rejects modifications once the transaction has left the `NEW` or `WAITING_FOR_SIGNATURES` states. Specifically, approver-set mutations should be forbidden when the status is `WAITING_FOR_EXECUTION`, `EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `REJECTED`, or `ARCHIVED`. Mirror the pattern already used in `approveTransaction`:

```typescript
if (!['NEW', 'WAITING_FOR_SIGNATURES'].includes(transaction.status)) {
  throw new BadRequestException('Approvers cannot be modified after the transaction has progressed');
}
```

### Proof of Concept

**Setup**: Organization with users Creator, Alice, Bob. Transaction T requires Alice's approval (threshold 1-of-1).

1. Creator submits `POST /transactions` → transaction T created, status `NEW`.
2. Creator submits `POST /transactions/T/approvers` with `{ userId: Alice }` → Alice is the sole approver.
3. Alice calls `POST /transactions/T/approvers/approve` with `approved: false` → Alice rejects; status transitions away from `WAITING_FOR_SIGNATURES`.
4. Creator calls `DELETE /transactions/T/approvers/<alice_approver_id>` → succeeds (no status check); Alice's rejection record is soft-deleted.
5. Creator calls `POST /transactions/T/approvers` with `{ userId: Bob }` → Bob is now the sole approver; status re-enters `WAITING_FOR_SIGNATURES`.
6. Bob (or a colluding account) calls `POST /transactions/T/approvers/approve` with `approved: true` → transaction moves to `WAITING_FOR_EXECUTION`.
7. Chain service submits T to Hedera — Alice's rejection has been completely bypassed.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-241)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);

    const approvers: TransactionApprover[] = [];
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L583-588)
```typescript
    /* Checks if the transaction is requires approval */
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.spec.ts (L332-346)
```typescript
  describe('createTransactionApprovers', () => {
    const transaction = {
      id: 1,
      creatorKey: { userId: user.id },
      status: TransactionStatus.EXPIRED,
      mirrorNetwork: 'testnet',
    };

    beforeEach(() => {
      jest.resetAllMocks();

      dataSource.manager.findOne.mockResolvedValueOnce(transaction);

      mockTransaction();
    });
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
