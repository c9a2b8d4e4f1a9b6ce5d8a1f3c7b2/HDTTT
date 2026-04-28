I have verified all the referenced code. Let me confirm each claim against the actual source.

All code references have been verified against the actual source. The vulnerability is confirmed.

---

# Audit Report

## Title
Approver Modification Operations Lack Transaction Status Checks, Allowing Creator to Bypass Multi-Party Approval Requirements

## Summary
The three approver-management endpoints (`createTransactionApprovers`, `updateTransactionApprover`, `removeTransactionApprover`) enforce only a creator-identity check via `getCreatorsTransaction` but perform no transaction-status check. A malicious transaction creator can add, remove, or lower the threshold of approvers on a transaction already in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` state, effectively bypassing the multi-party approval requirement the approver system is designed to enforce.

## Finding Description

**`approveTransaction`** correctly guards against acting on a transaction in the wrong state:

```
back-end/apps/api/src/transactions/approvers/approvers.service.ts, lines 584–588
``` [1](#0-0) 

The guard rejects any approval attempt unless the transaction is in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`.

**`createTransactionApprovers`** — only calls `getCreatorsTransaction` (creator identity check) at line 239, then proceeds to insert new approvers with no status check: [2](#0-1) 

**`updateTransactionApprover`** — only calls `getCreatorsTransaction` inside the transaction block at line 394, then allows threshold or `userId` changes with no status check: [3](#0-2) 

**`removeTransactionApprover`** (controller) — calls `getCreatorsTransaction` then immediately removes the approver with no status check: [4](#0-3) 

**`removeTransactionApprover`** (service) — has no authorization or status check at all; it only verifies the approver record exists: [5](#0-4) 

**`getCreatorsTransaction`** — only checks creator identity, never inspects `transaction.status`: [6](#0-5) 

The valid transaction statuses that should block approver modification are defined as: [7](#0-6) 

## Impact Explanation

A transaction creator can:
1. Create a transaction requiring N approvals (e.g., a 3-of-5 threshold tree).
2. Wait for N-1 approvers to submit their approval signatures — the transaction remains in `WAITING_FOR_SIGNATURES`.
3. Call `PATCH /transactions/:transactionId/approvers/:id` with `{ "threshold": 2 }` to lower the required threshold from 3 to 2, **or** call `DELETE /transactions/:transactionId/approvers/:id` to remove the one remaining unapproved approver.
4. The `emitTransactionStatusUpdate` fired by both operations triggers status recalculation. The transaction now satisfies the manipulated approval requirement and can advance to `WAITING_FOR_EXECUTION` with fewer legitimate approvals than originally required.

This completely undermines the multi-party approval invariant: the creator can unilaterally reduce the approval bar mid-flight, making the approver system ineffective as a trust control.

## Likelihood Explanation

The attacker is a **legitimate, authenticated transaction creator** — no privilege escalation or credential theft is required. The attack path uses only documented API endpoints (`PATCH` and `DELETE` on `/transactions/:transactionId/approvers/:id`) with a valid JWT. Any organization user who creates transactions can exploit this. The `removeTransactionApprover` service method additionally has no authorization check of its own, meaning any internal caller can remove approvers without any identity or status validation. [8](#0-7) 

## Recommendation

Add a transaction-status guard inside `getCreatorsTransaction` (or as a dedicated helper called by all three mutation paths) that throws a `BadRequestException` when the transaction is in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`. The guard should mirror the pattern already used in `approveTransaction`:

```typescript
if (
  transaction.status === TransactionStatus.WAITING_FOR_SIGNATURES ||
  transaction.status === TransactionStatus.WAITING_FOR_EXECUTION
) {
  throw new BadRequestException(ErrorCodes.OMTIP); // or a dedicated error code
}
```

Apply this check in:
- `createTransactionApprovers` — after the `getCreatorsTransaction` call at line 239.
- `updateTransactionApprover` — after the `getCreatorsTransaction` call at line 394.
- `removeTransactionApprover` (controller) — after the `getCreatorsTransaction` call at line 108, **and** also inside the service method itself so the check cannot be bypassed by future internal callers.

## Proof of Concept

```
# Step 1 – Creator creates a transaction with a 3-of-3 approval requirement
POST /transactions
Authorization: Bearer <creator_jwt>
{ ... }
# → transactionId = 42, approver tree root id = 7 (threshold=3, children ids 8,9,10)

# Step 2 – Two of three approvers submit approvals
POST /transactions/42/approvers/approve   (approver A)
POST /transactions/42/approvers/approve   (approver B)
# Transaction status: WAITING_FOR_SIGNATURES (1 approval still missing)

# Step 3 – Creator lowers threshold to 2 (already satisfied by A+B)
PATCH /transactions/42/approvers/7
Authorization: Bearer <creator_jwt>
{ "threshold": 2 }
# → HTTP 200, emitTransactionStatusUpdate fires

# Step 4 – Status recalculation advances transaction to WAITING_FOR_EXECUTION
# with only 2 of the original 3 required approvals collected.

# Alternative Step 3 – Creator removes the unapproved approver entirely
DELETE /transactions/42/approvers/10
Authorization: Bearer <creator_jwt>
# → HTTP 200, same outcome
```

Both `PATCH` and `DELETE` succeed because neither `updateTransactionApprover` nor `removeTransactionApprover` checks `transaction.status` before mutating the approver tree. [9](#0-8) [4](#0-3)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L367-395)
```typescript
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

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L46-56)
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
