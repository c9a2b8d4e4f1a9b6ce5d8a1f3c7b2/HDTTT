Based on my investigation of the codebase, I found a valid analog vulnerability.

---

### Title
Approver Modification Operations Lack Transaction Status Checks, Allowing Creator to Bypass Multi-Party Approval Requirements

### Summary
The approver management endpoints (`createTransactionApprovers`, `updateTransactionApprover`, `removeTransactionApprover`) enforce only a creator-identity check but perform no transaction-status check. A malicious transaction creator can add, remove, or lower the threshold of approvers on a transaction that is already in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` state, effectively bypassing the multi-party approval requirement that the approver system is designed to enforce.

### Finding Description

The `approveTransaction` method correctly guards against acting on a transaction in the wrong state: [1](#0-0) 

However, the three approver-management operations contain no equivalent status guard:

**`createTransactionApprovers`** — only calls `getCreatorsTransaction` (creator identity check), then proceeds to insert new approvers with no status check: [2](#0-1) 

**`updateTransactionApprover`** — only calls `getCreatorsTransaction` inside the transaction block, then allows threshold or userId changes with no status check: [3](#0-2) 

**`removeTransactionApprover`** (controller) — calls `getCreatorsTransaction` then immediately removes the approver with no status check: [4](#0-3) 

The service-level `removeTransactionApprover` itself has no authorization or status check at all: [5](#0-4) 

The valid transaction statuses that should block approver modification are defined as: [6](#0-5) 

### Impact Explanation

A transaction creator can:
1. Create a transaction requiring N approvals (e.g., 3-of-5).
2. Wait for N-1 approvers to sign (e.g., 2 of 3 required approvals collected, transaction still in `WAITING_FOR_SIGNATURES`).
3. Call `PATCH /transactions/:transactionId/approvers/:id` to lower the threshold from 3 to 2, or call `DELETE /transactions/:transactionId/approvers/:id` to remove the remaining unapproved approver.
4. The transaction now satisfies the (manipulated) approval requirement and advances to `WAITING_FOR_EXECUTION` with fewer legitimate approvals than originally required.

This completely undermines the multi-party approval invariant: the creator can unilaterally reduce the approval bar mid-flight, making the approver system ineffective as a trust control.

### Likelihood Explanation

The attacker is a **legitimate, authenticated transaction creator** — no privilege escalation or credential theft is required. The attack path uses only documented API endpoints (`PATCH` and `DELETE` on `/transactions/:transactionId/approvers/:id`) with a valid JWT. Any organization user who creates transactions can exploit this.

### Recommendation

Add a transaction-status guard at the start of `createTransactionApprovers`, `updateTransactionApprover`, and `removeTransactionApprover` (or in the controller before delegating). The guard should reject modifications when the transaction is in any state other than `NEW` (or a designated "draft" state before approval collection begins):

```typescript
if (
  transaction.status !== TransactionStatus.NEW &&
  transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES
) {
  throw new BadRequestException('Cannot modify approvers: transaction approval is already in progress or complete');
}
```

Alternatively, lock approver modifications entirely once the first approval signature has been recorded.

### Proof of Concept

1. Authenticate as a creator user and create a transaction requiring a 3-of-3 approver threshold.
2. Have two of the three approvers call `POST /transactions/:id/approvers/approve` — transaction remains `WAITING_FOR_SIGNATURES`.
3. As the creator, call `PATCH /transactions/:id/approvers/:rootApproverId` with `{ "threshold": 2 }`.
4. Observe: the threshold is lowered to 2, the two existing approvals now satisfy the requirement, and the transaction advances to `WAITING_FOR_EXECUTION` — bypassing the third required approval entirely.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-244)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);

    const approvers: TransactionApprover[] = [];

    try {
      await this.dataSource.transaction(async transactionalEntityManager => {
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

**File:** front-end/src/shared/interfaces/organization/transactions/index.ts (L43-53)
```typescript
export enum TransactionStatus {
  NEW = 'NEW', // unused
  CANCELED = 'CANCELED',
  REJECTED = 'REJECTED',
  WAITING_FOR_SIGNATURES = 'WAITING FOR SIGNATURES',
  WAITING_FOR_EXECUTION = 'WAITING FOR EXECUTION',
  EXECUTED = 'EXECUTED',
  FAILED = 'FAILED',
  EXPIRED = 'EXPIRED',
  ARCHIVED = 'ARCHIVED',
}
```
