### Title
Transaction Creator Can Bypass Multi-Signature Approval Threshold by Removing Approvers After Votes Are Cast

### Summary
The `removeTransactionApprover` and `updateTransactionApprover` endpoints perform no check on the transaction's current status before allowing the creator to mutate the live approver tree. A malicious transaction creator can remove unapproved approvers (or detach children from a threshold node, which auto-reduces the threshold) after some approvals have already been cast, causing the transaction to satisfy its approval requirement with fewer signatures than originally intended.

### Finding Description

**Vulnerability type:** Dynamic threshold manipulation (state-transition integrity failure)

**Root cause — no status guard on approver mutation:**

`removeTransactionApprover` in the controller calls only `getCreatorsTransaction`, which exclusively checks creator identity and never inspects `transaction.status`: [1](#0-0) 

`getCreatorsTransaction` itself: [2](#0-1) 

`removeTransactionApprover` in the service also performs no status check: [3](#0-2) 

`updateTransactionApprover` has the same gap — it calls `getCreatorsTransaction` but never checks whether the transaction is still in a pre-approval state: [4](#0-3) 

**Built-in threshold auto-reduction makes exploitation trivial:**

When a child approver is detached from its parent (via `updateTransactionApprover` with `dto.listId = null`), the parent's threshold is automatically lowered if it would exceed the remaining child count: [5](#0-4) 

**Exploit path (concrete):**

1. Creator creates a transaction and sets up a threshold node: `threshold=2`, children = `[UserA, UserB, UserC]`.
2. `UserA` calls `approveTransaction` — their approval is recorded.
3. Creator calls `PATCH /transactions/:id/approvers/:nodeId` with `{ listId: null }` to detach `UserB` from the threshold node. The service automatically reduces `threshold` from `2` to `1` (line 423–427 above) because `newParentApproversLength (1) < parent.threshold (2)`.
4. The threshold node now reads `threshold=1` with `[UserC]` as its only child, and `UserA`'s approval (already stored) satisfies it.
5. `emitTransactionStatusUpdate` fires, the chain service re-evaluates, and the transaction advances to execution with only 1 of the originally required 2 approvals.

Alternatively, the creator can call `DELETE /transactions/:id/approvers/:id` to hard-remove unapproved approvers directly, shrinking the pool until the already-cast approvals meet the threshold.

### Impact Explanation

The multi-signature approval system is the primary organizational control preventing a single actor from unilaterally executing a Hedera transaction. Bypassing it allows the transaction creator to execute arbitrary Hedera transactions (fund transfers, account updates, etc.) with fewer approvals than the organization mandated. In a financial or governance context this is a critical integrity failure — the entire purpose of the approval workflow is defeated.

### Likelihood Explanation

The attacker is the transaction creator — a normal authenticated user with no special privileges. The exploit requires only standard API calls (`PATCH` or `DELETE` on approvers) that are already part of the documented workflow. No cryptographic break, no admin access, and no race condition is required. Any creator who wants to bypass an approval they cannot obtain can execute this deterministically.

### Recommendation

Add a status guard in `getCreatorsTransaction` (or as a dedicated check at the top of `removeTransactionApprover` and `updateTransactionApprover`) that rejects mutations when the transaction is in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` status. Approver-tree modifications should only be permitted while the transaction is in a draft/pre-signature state (e.g., `WAITING_FOR_SIGNATURES` before any approvals have been recorded, or a dedicated `DRAFT` status). Once any approver has signed, the tree must be frozen.

### Proof of Concept

```
# Setup
POST /transactions                          → creates tx (id=1), status=WAITING_FOR_SIGNATURES
POST /transactions/1/approvers              → threshold=2, children=[UserA, UserB, UserC]

# UserA approves
POST /transactions/1/approvers/approve      → UserA signs, approved=true stored

# Creator detaches UserB (auto-reduces threshold 2→1)
PATCH /transactions/1/approvers/:userB_id   → body: { "listId": null }
# Service executes lines 418-427: newParentApproversLength=1 < threshold=2 → threshold updated to 1

# Result: threshold node now has threshold=1, UserA already approved → quorum met
# emitTransactionStatusUpdate fires → chain service advances transaction to execution
# Transaction executes on Hedera with only 1 of the originally required 2 approvals
```

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
