The claim requires careful verification. The report asserts there is **no ownership check at all**, but the controller code tells a different story — and reveals a more subtle (but still real) vulnerability.

**What the controller actually does:** [1](#0-0) 

```typescript
@Delete('/:id')
async removeTransactionApprover(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Param('id', ParseIntPipe) id: number,
) {
  await this.approversService.getCreatorsTransaction(transactionId, user); // checks ownership of :transactionId
  await this.approversService.removeTransactionApprover(id);               // deletes approver :id — no cross-check
  return true;
}
```

The controller **does** call `getCreatorsTransaction` — but only to verify the caller owns the transaction named in the **URL path** (`transactionId`). It never verifies that the approver `id` actually **belongs to that same transaction**.

**What the service does:** [2](#0-1) 

`removeTransactionApprover` only checks the approver exists, then deletes it — no cross-check against `transactionId`.

**Compare with `updateTransactionApprover`**, which explicitly guards against this: [3](#0-2) 

```typescript
const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
```

`updateTransactionApprover` verifies the approver's root transaction matches the URL's `transactionId` **and** that the user owns it. `removeTransactionApprover` does neither.

**The real exploit (IDOR):**

An attacker who owns transaction A can call:
```
DELETE /transactions/A/approvers/<approver_id_from_transaction_B>
```
- `getCreatorsTransaction(A, user)` passes — attacker owns A.
- `removeTransactionApprover(<id_from_B>)` deletes the victim's approver with no further check.

This is a classic Insecure Direct Object Reference. The report's framing that there is "no ownership check at all" is inaccurate — there is a check, but it is decoupled from the resource being mutated. The vulnerability is real regardless.

---

Audit Report

## Title
IDOR in `removeTransactionApprover`: Approver ID Not Bound to Verified Transaction

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller owns the transaction identified by `:transactionId`, but never verifies that the approver identified by `:id` belongs to that same transaction. Any authenticated user who owns at least one transaction can delete approvers from any other user's transaction by supplying their own `transactionId` in the URL and a victim's approver `id`.

## Finding Description

The controller calls `getCreatorsTransaction(transactionId, user)` to confirm the caller owns the transaction in the URL path, then immediately calls `removeTransactionApprover(id)` with the approver ID from the path: [4](#0-3) 

The service method `removeTransactionApprover` accepts only `id: number`, fetches the approver, and deletes it without any cross-check against the `transactionId` that was verified: [2](#0-1) 

The sibling method `updateTransactionApprover` correctly guards against this by resolving the approver's root node and asserting `rootNode.transactionId !== transactionId` before proceeding: [3](#0-2) 

This cross-check is entirely absent from the delete path.

## Impact Explanation

1. **Unauthorized approver removal**: An attacker can remove approvers from transactions they do not own, corrupting the multi-signature approval workflow of other users.
2. **Threshold reduction**: Removing a child approver from a threshold node may auto-decrement the parent's threshold (as seen in `updateTransactionApprover`'s `newParentApproversLength < parent.threshold` logic), allowing a transaction to reach `WAITING_FOR_EXECUTION` with fewer approvals than the creator intended.
3. **Denial of approval workflow**: Repeated deletion of approvers can permanently prevent a transaction from collecting required approvals.
4. **Spurious status events**: `emitTransactionStatusUpdate` fires unconditionally after deletion, triggering downstream recalculation against a now-invalid approver tree. [5](#0-4) 

## Likelihood Explanation

- **Precondition**: The attacker must be an authenticated, verified user and must own at least one transaction (to pass the `getCreatorsTransaction` check on their own `transactionId`).
- **Discovery**: Approver IDs are sequential integers returned in API responses. Any participant (observer, signer, approver) on any transaction can enumerate IDs.
- **Trigger**: A single `DELETE /transactions/<attacker_owned_tx_id>/approvers/<victim_approver_id>` request.

No privileged role, leaked credentials, or special tooling is required.

## Recommendation

In the controller's `removeTransactionApprover` handler, after verifying ownership of `transactionId`, resolve the approver's root transaction and assert it matches the verified `transactionId` before deletion — mirroring the pattern already used in `updateTransactionApprover`:

```typescript
// After getCreatorsTransaction(transactionId, user):
const approver = await this.approversService.getTransactionApproverById(id);
if (!approver) throw new NotFoundException();
const rootNode = await this.approversService.getRootNodeFromNode(approver.id);
if (!rootNode || rootNode.transactionId !== transactionId)
  throw new UnauthorizedException('Approver does not belong to this transaction');
await this.approversService.removeTransactionApprover(id);
```

Alternatively, move this cross-check into `removeTransactionApprover` itself (accepting `transactionId` and `user` as parameters, as `updateTransactionApprover` does) so the authorization cannot be bypassed regardless of how the service is called.

## Proof of Concept

1. Attacker (user A) creates transaction **TxA** and notes its `transactionId` (e.g., `10`).
2. Victim (user B) creates transaction **TxB** with approvers. Attacker observes or enumerates an approver ID belonging to TxB (e.g., approver `id = 99`).
3. Attacker sends:
   ```
   DELETE /transactions/10/approvers/99
   Authorization: Bearer <attacker_jwt>
   ```
4. `getCreatorsTransaction(10, userA)` passes — attacker owns TxA.
5. `removeTransactionApprover(99)` fetches approver 99 (belonging to TxB), finds it exists, and soft-deletes it.
6. `emitTransactionStatusUpdate` fires for TxB's ID, corrupting its approval state.

Approver 99 on TxB is permanently deleted without user B's knowledge or consent.

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
