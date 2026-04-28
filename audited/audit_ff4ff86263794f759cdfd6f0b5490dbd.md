### Title
Transaction Creator Can Modify Approval Rules Mid-Lifecycle, Bypassing Multi-Party Governance

### Summary
The `updateTransactionApprover`, `createTransactionApprovers`, and `removeTransactionApprover` methods in `ApproversService` allow the transaction creator to modify the approval threshold, replace approvers, or remove approvers at any point during the transaction lifecycle — including after approvals have already been recorded. There is no guard on the transaction's current status in any of these mutation paths. A malicious creator can lower the required threshold after partial approval, replace a rejecting approver to nullify their rejection, or remove approvers entirely, bypassing the intended multi-party governance requirement.

### Finding Description

**Root cause:** `updateTransactionApprover`, `createTransactionApprovers`, and `removeTransactionApprover` in `back-end/apps/api/src/transactions/approvers/approvers.service.ts` each verify only that the calling user is the transaction creator (`getCreatorsTransaction`). None of them check the transaction's current `status` before mutating the approver tree. [1](#0-0) 

The only authorization check performed is: [2](#0-1) 

No status guard exists — compare this to `approveTransaction`, which correctly rejects calls when the transaction is not in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`: [3](#0-2) 

**Threshold mutation path:** The creator can lower the threshold of an existing approver tree node at any time: [4](#0-3) 

**Approver replacement path:** Replacing a `userId` clears the existing `signature`, `userKeyId`, and `approved` fields — nullifying a prior rejection or approval: [5](#0-4) 

**Removal path:** The controller calls `getCreatorsTransaction` then `removeTransactionApprover` with no status check: [6](#0-5) [7](#0-6) 

### Impact Explanation

The approval system is a governance gate for multi-party transaction authorization. A transaction creator can:

1. **Lower the threshold after partial approval** — e.g., set up a 3-of-5 approval requirement, wait for 2 approvals, then `PATCH /transactions/:id/approvers/:nodeId` with `{threshold: 2}`, making the transaction immediately satisfy its own approval requirement with fewer approvers than originally required.

2. **Nullify a rejection** — if an approver submits `approved: false`, the creator can replace that approver's `userId` (clearing `signature`, `approved`, `userKeyId`), then assign a cooperative user, bypassing the rejection entirely.

3. **Remove all approvers** — the creator can `DELETE /transactions/:id/approvers/:id` for every approver node, eliminating the approval requirement entirely while the transaction is in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`.

This breaks the integrity of the multi-party approval model, which is the primary governance control for high-value Hedera network operations (e.g., system file updates, node management).

### Likelihood Explanation

The attacker is the transaction creator — a normal authenticated user with no special privileges beyond having created the transaction. The attack requires only valid API calls to `PATCH /transactions/:transactionId/approvers/:id` or `DELETE /transactions/:transactionId/approvers/:id`. No cryptographic material, admin access, or leaked secrets are needed. The endpoint is reachable by any verified user who creates a transaction.

### Recommendation

Add a transaction status guard at the start of `updateTransactionApprover`, `createTransactionApprovers`, and `removeTransactionApprover`. Approver structure mutations should only be permitted when the transaction is in a pre-active state (e.g., `NEW`), and must be rejected once the transaction has reached `WAITING_FOR_SIGNATURES`, `WAITING_FOR_EXECUTION`, or any terminal state:

```typescript
// In getCreatorsTransaction or at the top of each mutating method:
const IMMUTABLE_STATUSES = [
  TransactionStatus.WAITING_FOR_SIGNATURES,
  TransactionStatus.WAITING_FOR_EXECUTION,
  TransactionStatus.EXECUTED,
  TransactionStatus.EXPIRED,
  TransactionStatus.FAILED,
  TransactionStatus.CANCELED,
  TransactionStatus.ARCHIVED,
];
if (IMMUTABLE_STATUSES.includes(transaction.status)) {
  throw new BadRequestException('Approver structure cannot be modified after signing has begun');
}
```

### Proof of Concept

**Threshold bypass:**
1. Creator creates a transaction and sets up a 3-of-5 threshold approver tree via `POST /transactions/:id/approvers`.
2. Two approvers call `POST /transactions/:id/approvers/approve` — both approve.
3. Creator calls `PATCH /transactions/:id/approvers/:treeNodeId` with body `{"threshold": 2}`.
4. The approval requirement is now satisfied with only 2 approvals. The transaction proceeds without the originally required 3rd, 4th, and 5th approvals.

**Rejection nullification:**
1. Creator sets up a 1-of-1 approver (single required approver, User B).
2. User B calls `POST /transactions/:id/approvers/approve` with `approved: false` (rejection).
3. Creator calls `PATCH /transactions/:id/approvers/:approverId` with body `{"userId": <User C id>}` — this clears User B's rejection (`signature`, `approved`, `userKeyId` set to `undefined`).
4. User C (cooperative) approves. The rejection is gone; the transaction proceeds. [8](#0-7) [9](#0-8)

### Citations

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L500-516)
```typescript
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
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L533-543)
```typescript
  /* Removes the transaction approver by id */
  async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);

    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const result = await this.removeNode(approver.id);

    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);

    return result;
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
