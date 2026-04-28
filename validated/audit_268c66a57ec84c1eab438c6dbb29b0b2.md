All three exploit paths and their code references have been verified against the actual source. Here is the audit report.

---

Audit Report

## Title
Transaction Creator Can Manipulate Approval Outcome by Modifying Approver Structure After Votes Are Cast

## Summary
The transaction approval workflow allows the transaction creator to add, remove, or update approvers — including lowering thresholds — at any point during the transaction lifecycle, even after approvers have already cast their approval or rejection. The sole authorization gate, `getCreatorsTransaction`, checks only creator identity and never inspects the transaction's current status. This allows a malicious creator to nullify rejections, lower required thresholds after partial approval, or re-insert previously removed approvers with their approval pre-populated.

## Finding Description

**Root cause:** `getCreatorsTransaction` is the sole authorization gate for all three approver-mutation paths. It checks only that the caller is the transaction creator; it never inspects the transaction's current status. [1](#0-0) 

This function is called unconditionally by all three mutation paths:

**1. `createTransactionApprovers`** — adds new approvers with no status guard: [2](#0-1) 

**2. `updateTransactionApprover`** — changes threshold or reassigns approver user with no status guard: [3](#0-2) 

**3. `removeTransactionApprover` (controller)** — calls `getCreatorsTransaction` then immediately removes the approver: [4](#0-3) 

The `removeTransactionApprover` service method itself performs no authorization or status check at all: [5](#0-4) 

**Path A — Nullify a rejection (remove rejecting approver):**
- Transaction has 3 approvers, threshold = 2.
- Approvers A and B approve (`approved=true`), approver C rejects (`approved=false`).
- Creator calls `DELETE /transactions/:id/approvers/:cId`.
- Approver C's record is soft-deleted. The approval tree now shows 2-of-2 approved.
- `emitTransactionStatusUpdate` is triggered, which re-evaluates the transaction state.

**Path B — Lower threshold after partial approval:**
- Transaction has 3 approvers under a tree node with threshold = 3 (unanimous required).
- Approvers A and B approve; C has not yet.
- Creator calls `PATCH /transactions/:id/approvers/:treeId` with `{ threshold: 2 }`.
- The threshold update is accepted with no status check: [6](#0-5) 

**Path C — Add a new approver who inherits an existing approval:**
When a new approver is added for a `userId` that already has an approval record for the transaction, the existing `signature`, `userKeyId`, and `approved` values are copied into the new approver record: [7](#0-6) 

This allows a creator to re-insert a previously removed approver with their approval pre-populated, or to restructure the tree to manufacture a passing state.

## Impact Explanation

A transaction creator (a normal authenticated user) can unilaterally override the approval decisions of other organization members after those decisions have been recorded. This breaks the core integrity guarantee of the multi-approver workflow: that a transaction cannot proceed without the required number of independent approvals. Concretely:

- A rejected transaction can be forced through by removing the rejecting approver.
- A transaction requiring unanimous consent can be executed with a subset of approvals by lowering the threshold.
- A previously removed approver's approval can be re-inserted into a new approver record, manufacturing a passing state.
- This can result in unauthorized Hedera transactions being submitted on behalf of the organization (fund transfers, account updates, file changes, etc.).

## Likelihood Explanation

- **Attacker profile:** The transaction creator — a normal authenticated user with no elevated privileges.
- **Preconditions:** The attacker must have created the transaction (standard workflow) and at least one approver must have cast a rejection or the threshold must be higher than the number of approvals received.
- **Effort:** Two standard API calls (one to approve as a colluding approver, one to delete the rejecting approver). No cryptographic bypass, no race condition, no special tooling required.
- **Detection difficulty:** The soft-delete of an approver record leaves a `deletedAt` timestamp, but there is no audit log or alert triggered when an approver is removed after votes are cast.

## Recommendation

1. **Add a status guard to `getCreatorsTransaction`** (or to each mutation path individually): reject any approver-structure modification if the transaction's status is not `NEW` or another pre-voting state. For example:
   ```typescript
   if (transaction.status !== TransactionStatus.NEW) {
     throw new BadRequestException('Cannot modify approvers after voting has begun');
   }
   ```
2. **Add the same guard to `removeTransactionApprover`** in the service layer, not just in the controller, since the service method currently performs no authorization or status check at all. [5](#0-4) 

3. **Disable approval-data inheritance** in `createTransactionApprovers` when the transaction is in an active voting state, or remove it entirely if there is no legitimate use case for pre-populating approval data on a newly added approver. [8](#0-7) 

## Proof of Concept

**Path A (nullify rejection):**
```
# Step 1: Approver C rejects the transaction
POST /transactions/42/approvers/approve
{ "userKeyId": 7, "signature": "...", "approved": false }

# Step 2: Creator removes approver C
DELETE /transactions/42/approvers/15
# → 200 OK, approver C soft-deleted, emitTransactionStatusUpdate fires
# → Approval tree now shows 2-of-2 approved
```

**Path B (lower threshold):**
```
# Step 1: Approvers A and B approve (2 of 3 required for unanimous)
POST /transactions/42/approvers/approve  (user A)
POST /transactions/42/approvers/approve  (user B)

# Step 2: Creator lowers threshold from 3 to 2
PATCH /transactions/42/approvers/8
{ "threshold": 2 }
# → 200 OK, threshold updated, tree now shows 2-of-3 satisfied
```

Both calls succeed because `getCreatorsTransaction` only verifies creator identity and never checks `transaction.status`. [9](#0-8)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L318-329)
```typescript
          if (typeof dtoApprover.userId === 'number') {
            const userApproverRecords = await this.getApproversByTransactionId(
              transactionId,
              dtoApprover.userId,
              transactionalEntityManager,
            );

            if (userApproverRecords.length > 0) {
              data.signature = userApproverRecords[0].signature;
              data.userKeyId = userApproverRecords[0].userKeyId;
              data.approved = userApproverRecords[0].approved;
            }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L367-394)
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
