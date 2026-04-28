### Title
Transaction Creator Can Manipulate Approver Tree After Approvals Are Submitted, Bypassing Multi-Approval Enforcement

### Summary
The `createTransactionApprovers`, `updateTransactionApprover`, and `removeTransactionApprover` operations in `approvers.service.ts` and `approvers.controller.ts` gate access solely on creator identity via `getCreatorsTransaction`, with no check on the transaction's current status. A malicious transaction creator can therefore remove rejecting approvers, lower approval thresholds, or inject new approvers at any point during the active approval window (`WAITING_FOR_SIGNATURES` / `WAITING_FOR_EXECUTION`), retroactively satisfying the threshold and forcing the transaction through without the required approvals.

### Finding Description

**Root cause — `getCreatorsTransaction` has no status guard**

`getCreatorsTransaction` is the sole authorization gate used by all three mutating approver operations: [1](#0-0) 

It checks only that the caller owns the transaction's creator key. There is no check on `transaction.status`. This function is invoked by:

1. `createTransactionApprovers` — line 239
2. `updateTransactionApprover` — line 394
3. `removeTransactionApprover` via the controller — line 108 [2](#0-1) 

The service-level `removeTransactionApprover` also performs no status check: [3](#0-2) 

And `updateTransactionApprover` allows threshold reduction with no status guard: [4](#0-3) 

**Contrast with `approveTransaction`**, which correctly enforces a status check before accepting an approval: [5](#0-4) 

The approval submission path is guarded; the approver-tree mutation path is not.

**End-to-end exploit flow**

1. Creator creates a transaction and sets up an approver tree: threshold = 3, approvers = [A, B, C, D, E].
2. Transaction enters `WAITING_FOR_SIGNATURES`.
3. Approvers A and B submit approvals (`approved = true`). Approver C submits a rejection (`approved = false`).
4. Creator calls `DELETE /transactions/:txId/approvers/:C_id` — removes the rejecting approver. No status check blocks this.
5. Creator calls `PATCH /transactions/:txId/approvers/:treeId` with `{ threshold: 2 }` — lowers the required threshold from 3 to 2. No status check blocks this.
6. `emitTransactionStatusUpdate` is fired by `removeTransactionApprover`, triggering a re-evaluation of the approval state. The tree now has threshold = 2 and two `approved = true` entries — the threshold is satisfied.
7. Transaction advances to execution without the originally required 3-of-5 approval quorum.

Alternatively, the creator can call `createTransactionApprovers` to inject a new approver entry for themselves (or a colluding user) after the window opens, then immediately approve it, inflating the "approved" count — a direct analog to the stake-accumulation pattern in the external report.

### Impact Explanation

The multi-approval mechanism is the primary trust control for high-value or sensitive Hedera transactions in organization mode. Bypassing it allows a single user (the creator) to execute any transaction unilaterally, regardless of the approval policy configured. This constitutes a critical integrity failure: the approval quorum can be reduced to 1 at will, or rejections can be silently erased, with no audit trail distinguishing a legitimate approval from a manipulated one.

### Likelihood Explanation

The attacker is the transaction creator — a normal, unprivileged user role reachable by any registered organization member. No leaked credentials, admin keys, or race conditions are required. The three API endpoints (`POST`, `PATCH`, `DELETE` on `/transactions/:id/approvers`) are standard REST calls documented in the codebase. The attack is deterministic and repeatable on every transaction the attacker creates. [6](#0-5) 

### Recommendation

Add a status guard inside `getCreatorsTransaction` (or at the top of each mutating operation) that rejects modifications when the transaction is in any active approval state:

```typescript
// In getCreatorsTransaction, after the creator check:
const lockedStatuses = [
  TransactionStatus.WAITING_FOR_SIGNATURES,
  TransactionStatus.WAITING_FOR_EXECUTION,
  TransactionStatus.EXECUTED,
  TransactionStatus.FAILED,
  TransactionStatus.EXPIRED,
  TransactionStatus.CANCELED,
  TransactionStatus.ARCHIVED,
];
if (lockedStatuses.includes(transaction.status)) {
  throw new BadRequestException('Approver tree cannot be modified once the transaction is active');
}
```

This mirrors the pattern already used in `approveTransaction` and ensures the approver tree is immutable once the approval window opens.

### Proof of Concept

**Preconditions**: Authenticated as the creator of transaction ID `42`. Approver tree has `treeNodeId = 10` (threshold = 3, children = [A, B, C]). Approver C (id = 15) has submitted `approved = false`.

```
# Step 1 — Remove the rejecting approver (no status check blocks this)
DELETE /transactions/42/approvers/15
Authorization: Bearer <creator_jwt>
→ 200 OK

# Step 2 — Lower the threshold to match existing approvals
PATCH /transactions/42/approvers/10
Authorization: Bearer <creator_jwt>
Content-Type: application/json
{ "threshold": 2 }
→ 201 OK

# Result: transaction now has threshold=2, two approved=true entries.
# emitTransactionStatusUpdate fires → processTransactionStatus re-evaluates
# → transaction advances to WAITING_FOR_EXECUTION without the required 3-of-3 quorum.
``` [7](#0-6) [8](#0-7)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L61-133)
```typescript
  @ApiResponse({
    status: 200,
    type: Boolean,
  })
  @Post('/approve')
  @OnlyOwnerKey<ApproverChoiceDto>('userKeyId')
  approveTransaction(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() body: ApproverChoiceDto,
  ): Promise<boolean> {
    return this.approversService.approveTransaction(body, transactionId, user);
  }

  /* Get all approvers for the given transaction */
  @ApiOperation({
    summary: 'Get all transaction approvers for a transaction',
    description:
      'Get the transaction approvers for the given transaction id. The result will be array of approvers that may be trees',
  })
  @ApiResponse({
    status: 200,
    type: [TransactionApproverDto],
  })
  @Get()
  getTransactionApproversByTransactionId(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
  ): Promise<TransactionApprover[]> {
    return this.approversService.getVerifiedApproversByTransactionId(transactionId, user);
  }

  /* Remove transaction approver or a tree by id of the root approver */
  @ApiOperation({
    summary: 'Removes transaction approver',
    description: 'Removes transaction approver by id.',
  })
  @ApiResponse({
    status: 200,
    type: Boolean,
  })
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

  /* Updates the transaction approver */
  @ApiOperation({
    summary: 'Update a transaction appover',
    description:
      'Update the transaction approver with the provided information for the given transaction approver id.',
  })
  @ApiResponse({
    status: 201,
    type: TransactionApproverDto,
  })
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
