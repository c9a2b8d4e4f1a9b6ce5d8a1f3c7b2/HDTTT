The code confirms the vulnerability. Here is the audit report:

---

Audit Report

## Title
Transaction Creator Can Delete Approvers Belonging to Any Other Transaction via Mismatched Authorization Check

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint authorizes the caller against `:transactionId` but then deletes the approver record identified by `:id` without verifying that approver belongs to `:transactionId`. Any verified user who has created at least one transaction can silently remove approvers from transactions they did not create.

## Finding Description

**Root cause — split authorization and action on different resources**

In `approvers.controller.ts`, the `removeTransactionApprover` handler performs two independent operations:

```typescript
await this.approversService.getCreatorsTransaction(transactionId, user); // checks ownership of transactionId
await this.approversService.removeTransactionApprover(id);               // deletes approver by id, no cross-check
``` [1](#0-0) 

Step 1 (`getCreatorsTransaction`) confirms the caller is the creator of the transaction whose ID appears in the URL path. Step 2 (`removeTransactionApprover`) deletes the approver record whose ID appears in the URL path. There is no check that the approver record belongs to the same transaction.

The service-level `removeTransactionApprover` only verifies the approver exists by ID:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  ...
}
``` [2](#0-1) 

**Contrast with `updateTransactionApprover`**, which correctly validates that the approver's root transaction matches the URL parameter before proceeding:

```typescript
const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
``` [3](#0-2) 

The `removeTransactionApprover` path is missing this cross-check entirely.

## Impact Explanation

An attacker can unilaterally remove any approver from any transaction in the organization. This directly undermines the multi-signature approval workflow: a transaction that required N-of-M approvals can have its approvers stripped, allowing it to proceed without the intended governance controls. This is an unauthorized state change with direct integrity impact on the transaction approval model.

## Likelihood Explanation

The attacker only needs to be a registered, verified organization user who has created at least one transaction — the lowest non-anonymous privilege level. Approver IDs are auto-incremented integers, making enumeration trivial. No admin access, leaked credentials, or privileged keys are required. The endpoint is reachable via standard HTTP.

## Recommendation

Apply the same cross-check used in `updateTransactionApprover` to the delete path. In `removeTransactionApprover` (or in the controller before calling it), resolve the root node of the approver and verify `rootNode.transactionId === transactionId` before proceeding with deletion:

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  const approver = await this.approversService.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  const rootNode = await this.approversService.getRootNodeFromNode(approver.id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to this transaction');

  await this.approversService.getCreatorsTransaction(transactionId, user);
  await this.approversService.removeTransactionApprover(id);
  return true;
}
```

Alternatively, pass `transactionId` into `removeTransactionApprover` in the service and perform the check there, mirroring the pattern already established in `updateTransactionApprover`. [4](#0-3) 

## Proof of Concept

1. Attacker (verified user) creates transaction **T1** — they are now its creator.
2. Attacker observes or enumerates approver IDs (sequential integers) to find approver record `id=42` belonging to victim transaction **T2** (created by another user).
3. Attacker sends:
   ```
   DELETE /transactions/{T1_id}/approvers/42
   ```
4. `getCreatorsTransaction(T1_id, attacker)` passes — attacker is creator of T1. [5](#0-4) 
5. `removeTransactionApprover(42)` executes — approver 42 (belonging to T2) is soft-deleted with no ownership check. [2](#0-1) 
6. T2's approval requirement is silently removed without the creator of T2 being involved.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L534-544)
```typescript
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
