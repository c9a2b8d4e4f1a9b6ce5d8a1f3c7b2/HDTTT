Let me look at the controller more carefully and check if there's any cross-validation between the approver ID and the transaction ID.

The report's root-cause description is factually wrong in one critical place, but a real (and distinct) vulnerability does exist. Let me document it accurately.

The controller at line 108 **does** call `getCreatorsTransaction(transactionId, user)` — so the claim that "no ownership check is performed" is false. However, the check is against the URL's `transactionId`, not against the `transactionId` of the approver being deleted. The `updateTransactionApprover` service method explicitly cross-validates these at line 390 (`if (rootNode.transactionId !== transactionId)`), but `removeTransactionApprover` has no such cross-check. This is the real bug.

---

## Audit Report

## Title
Transaction Approver Deletion Lacks Cross-Transaction Ownership Binding

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies that the caller owns the transaction identified by the URL's `:transactionId`, but never verifies that the approver identified by `:id` actually belongs to that same transaction. Any user who is the creator of **any** transaction can therefore delete approvers belonging to **any other** transaction by supplying their own `transactionId` in the URL and a victim's approver `id` in the path.

## Finding Description

**Controller performs ownership check against the wrong resource.**

In `approvers.controller.ts`, the `removeTransactionApprover` handler calls `getCreatorsTransaction(transactionId, user)` to confirm the caller owns the transaction in the URL, then immediately calls `removeTransactionApprover(id)` with no further validation:

```typescript
// approvers.controller.ts lines 107-109
await this.approversService.getCreatorsTransaction(transactionId, user);
await this.approversService.removeTransactionApprover(id);
``` [1](#0-0) 

The service method `removeTransactionApprover` accepts only an approver `id`, fetches the record, and deletes it — with no check that `approver.transactionId` matches the `transactionId` the caller was authorized against:

```typescript
// approvers.service.ts lines 534-544
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(...);
  return result;
}
``` [2](#0-1) 

**Contrast with `updateTransactionApprover`, which correctly cross-validates.**

The sibling service method explicitly checks that the approver's root transaction matches the URL parameter before any mutation:

```typescript
// approvers.service.ts lines 389-394
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, ...);
``` [3](#0-2) 

This guard is entirely absent from the delete path.

**`getCreatorsTransaction` enforces creator identity but only for the supplied `transactionId`:** [4](#0-3) 

Because the `transactionId` passed to it is the URL parameter — not the approver's actual `transactionId` — the check is satisfied by the attacker's own transaction, not the victim's.

## Impact Explanation

An attacker who is the creator of any transaction can:
- Delete approvers from any other user's transaction, removing required signers from multi-signature workflows.
- Reduce the effective approval threshold below what the transaction creator intended, potentially allowing a transaction to advance to `WAITING_FOR_EXECUTION` with fewer approvals than required.
- Permanently corrupt the approval audit trail for transactions they do not own.
- In an organizational context (e.g., Hedera Council governance), strip approval requirements from high-value network transactions unilaterally.

## Likelihood Explanation

- **Precondition:** The attacker must be the creator of at least one transaction — a low bar achievable by any verified user.
- **Approver ID enumeration:** Approver IDs are sequential integers. The `GET /transactions/:id/approvers` endpoint is accessible to any verified user who can view a transaction, making enumeration straightforward.
- **Single request:** The attack is a single authenticated HTTP `DELETE` request.
- **No rate limiting** or anomaly detection is described for this endpoint.

## Recommendation

In the controller's `removeTransactionApprover` handler, after the ownership check, verify that the approver being deleted actually belongs to the authorized transaction before calling the service. The simplest fix mirrors what `updateTransactionApprover` already does in the service layer — resolve the approver's root `transactionId` and assert it equals the URL `transactionId`:

```typescript
// In the controller, after getCreatorsTransaction:
const approver = await this.approversService.getTransactionApproverById(id);
if (!approver) throw new NotFoundException();
const root = await this.approversService.getRootNodeFromNode(approver.id);
if (!root || root.transactionId !== transactionId)
  throw new UnauthorizedException('Approver does not belong to this transaction');
await this.approversService.removeTransactionApprover(id);
```

Alternatively, pass `transactionId` into `removeTransactionApprover` and perform the cross-check inside the service, consistent with how `updateTransactionApprover` is structured. [5](#0-4) 

## Proof of Concept

1. Attacker (user A) creates transaction **T1** and becomes its creator.
2. Victim (user B) creates transaction **T2** with approver record ID **42**.
3. Attacker discovers approver ID 42 via `GET /transactions/{T2_id}/approvers` (accessible to any verified user who can view T2, or by sequential enumeration).
4. Attacker sends:
   ```
   DELETE /transactions/{T1_id}/approvers/42
   Authorization: Bearer <attacker_jwt>
   ```
5. `getCreatorsTransaction(T1_id, attacker)` passes — attacker owns T1.
6. `removeTransactionApprover(42)` executes with no further check — approver 42 (belonging to T2) is soft-deleted.
7. T2's multi-signature approval workflow is silently corrupted.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L107-109)
```typescript
  ) {
    await this.approversService.getCreatorsTransaction(transactionId, user);
    await this.approversService.removeTransactionApprover(id);
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L640-641)
```typescript
    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to modify it');
```
