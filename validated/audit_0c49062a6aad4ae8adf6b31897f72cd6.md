The vulnerability is confirmed by the actual code. Here is the audit report:

---

Audit Report

## Title
Any Authenticated Transaction Creator Can Delete Approvers Belonging to Other Users' Transactions

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint authorizes the request by verifying the caller owns the URL-supplied `transactionId`, but then deletes the approver record identified by `:id` without verifying that approver actually belongs to `transactionId`. An attacker who owns any transaction can use their own `transactionId` as a pass to delete approvers from any other transaction in the system.

## Finding Description

**Root cause — authorization decoupled from deletion in the controller:**

In `approvers.controller.ts` lines 102–113, `removeTransactionApprover` makes two independent calls:

```typescript
await this.approversService.getCreatorsTransaction(transactionId, user); // checks user owns transactionId
await this.approversService.removeTransactionApprover(id);               // deletes by id — no cross-check
``` [1](#0-0) 

`getCreatorsTransaction` only confirms the caller is the creator of the URL-supplied `transactionId`:

```typescript
if (transaction.creatorKey?.userId !== user.id)
  throw new UnauthorizedException('Only the creator of the transaction is able to modify it');
``` [2](#0-1) 

`removeTransactionApprover` then deletes the approver identified by `:id` with no check that it belongs to the authorized transaction:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  ...
}
``` [3](#0-2) 

**Contrast with `updateTransactionApprover`**, which correctly resolves the root node of the approver and verifies the caller owns *that* transaction — not just the URL parameter:

```typescript
const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
``` [4](#0-3) 

The delete path has no equivalent cross-check.

## Impact Explanation
An attacker can silently delete approvers from any transaction they do not own. This directly undermines the multi-signature approval workflow: required approvers can be stripped from a transaction, causing it to either auto-advance past the approval gate or become permanently stuck in an inconsistent state. This is an unauthorized state change with direct integrity impact on the transaction lifecycle.

## Likelihood Explanation
The attacker only needs to be a registered, verified user with at least one transaction of their own — the lowest privilege level in the system. Approver IDs are sequential integers, making enumeration trivial via `GET /transactions/:id/approvers`, which any verified user can call per `getVerifiedApproversByTransactionId`. [5](#0-4) 

## Recommendation
In `removeTransactionApprover` (controller), after fetching the approver by `:id`, resolve its root node via `getRootNodeFromNode` and assert that `rootNode.transactionId === transactionId` before proceeding with deletion — mirroring the pattern already used in `updateTransactionApprover`:

```typescript
@Delete('/:id')
async removeTransactionApprover(...) {
  await this.approversService.getCreatorsTransaction(transactionId, user);
  // ADD: verify the approver belongs to this transaction
  const rootNode = await this.approversService.getRootNodeFromNode(id);
  if (!rootNode || rootNode.transactionId !== transactionId)
    throw new UnauthorizedException('Approver does not belong to this transaction');
  await this.approversService.removeTransactionApprover(id);
  return true;
}
```

Alternatively, move the ownership cross-check into `removeTransactionApprover` in the service layer, accepting `transactionId` and `user` as parameters and replicating the `getRootNodeFromNode` + `getCreatorsTransaction` pattern from `updateTransactionApprover`. [1](#0-0) 

## Proof of Concept

1. Attacker registers and verifies an account; creates transaction `T_attacker` (any valid transaction). Attacker is now the creator of `T_attacker`.
2. Attacker enumerates approver IDs belonging to victim's transaction `T_victim` by calling `GET /transactions/T_victim/approvers` (accessible to any verified user). Identifies approver ID `X`.
3. Attacker sends: `DELETE /transactions/T_attacker/approvers/X`
4. Server executes `getCreatorsTransaction(T_attacker, attacker)` — passes, attacker owns `T_attacker`.
5. Server executes `removeTransactionApprover(X)` — fetches approver `X` (which belongs to `T_victim`), calls `removeNode(X.id)`, and deletes it. No ownership check is performed.
6. Approver `X` is permanently deleted from `T_victim` without the victim's knowledge. [3](#0-2)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L111-152)
```typescript
  async getVerifiedApproversByTransactionId(
    transactionId: number,
    user: User,
  ): Promise<TransactionApprover[]> {
    const transaction = await this.dataSource.manager.findOne(Transaction, {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user', 'observers', 'signers', 'signers.userKey'],
    });

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    const approvers = await this.getApproversByTransactionId(transactionId);

    const userKeysToSign = await userKeysRequiredToSign(
      transaction,
      user,
      this.transactionSignatureService,
      this.dataSource.manager,
    );

    if (
      [
        TransactionStatus.EXECUTED,
        TransactionStatus.EXPIRED,
        TransactionStatus.FAILED,
        TransactionStatus.CANCELED,
        TransactionStatus.ARCHIVED,
      ].includes(transaction.status)
    )
      return approvers;

    if (
      userKeysToSign.length === 0 &&
      transaction.creatorKey?.userId !== user.id &&
      !transaction.observers.some(o => o.userId === user.id) &&
      !transaction.signers.some(s => s.userKey?.userId === user.id) &&
      !approvers.some(a => a.userId === user.id)
    )
      throw new UnauthorizedException("You don't have permission to view this transaction");

    return approvers;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L386-394)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L640-641)
```typescript
    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to modify it');
```
