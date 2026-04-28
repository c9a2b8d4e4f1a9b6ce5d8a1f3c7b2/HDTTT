### Title
Cross-Transaction Approver Removal via Missing Transaction Ownership Validation in `removeTransactionApprover`

### Summary
The `removeTransactionApprover` endpoint authorizes the caller by verifying they are the creator of the `transactionId` supplied in the URL, but then removes the approver record identified by the separate `id` path parameter without verifying that approver actually belongs to the authorized transaction. Any authenticated user who has created at least one transaction can therefore delete approvers from transactions they do not own, bypassing the multi-signature approval requirement for those transactions.

### Finding Description

**Vulnerability class:** Authorization bypass — state-mutation function does not validate that the target object belongs to the authorized resource (direct analog to the external report's "swap without checking if the reserve allows it").

**Root cause — controller:** [1](#0-0) 

```
@Delete('/:id')
async removeTransactionApprover(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Param('id', ParseIntPipe) id: number,
) {
    await this.approversService.getCreatorsTransaction(transactionId, user); // ← authorizes on URL transactionId
    await this.approversService.removeTransactionApprover(id);               // ← removes by approver id, no cross-check
    return true;
}
```

**Root cause — service:** [2](#0-1) 

`removeTransactionApprover` fetches the approver by `id` and deletes it. It never asserts that `approver.transactionId` equals the `transactionId` that was authorized in the controller.

**Contrast with the correctly-guarded sibling function** `updateTransactionApprover`, which explicitly rejects mismatched ownership: [3](#0-2) 

```typescript
if (rootNode.transactionId !== transactionId)
    throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
```

That guard is entirely absent from `removeTransactionApprover`.

**Exploit flow:**

1. Attacker (Alice) registers and creates transaction T1 — she is its creator.
2. Victim (Bob) creates transaction T2 with a required approver tree (e.g., 2-of-3 threshold). Approver records receive sequential integer IDs; Alice can enumerate them.
3. Alice calls:
   ```
   DELETE /transactions/{T1.id}/approvers/{approver_id_from_T2}
   ```
4. `getCreatorsTransaction(T1.id, Alice)` passes — Alice is creator of T1.
5. `removeTransactionApprover(approver_id_from_T2)` executes with no further check, deleting the approver from T2.
6. T2's approval tree is now corrupted: a required approver is gone, the threshold may be silently auto-reduced, and the transaction can proceed without the intended signatures.

### Impact Explanation

- **Unauthorized state mutation**: An attacker with no relationship to a target transaction can delete its approvers, undermining the multi-signature security model.
- **Approval threshold bypass**: Removing approvers from a threshold tree triggers automatic threshold reduction (visible in `updateTransactionApprover` lines 423–428), meaning a 2-of-3 requirement can be silently degraded to 1-of-2 or lower.
- **Transaction integrity**: Transactions that require organizational approval can be pushed toward execution without the required signatures, constituting unauthorized movement of value on the Hedera network.

### Likelihood Explanation

- Requires only a valid JWT (any registered, verified user).
- The attacker must have created at least one transaction (trivially achievable).
- Approver IDs are sequential database integers — enumerable without any special knowledge.
- No rate-limiting or anomaly detection is visible on this endpoint.
- The attack is a single authenticated HTTP request.

### Recommendation

Inside `removeTransactionApprover` (or in the controller before delegating), assert that the resolved approver's root transaction matches the authorized `transactionId`:

```typescript
async removeTransactionApprover(id: number, expectedTransactionId: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    // Resolve root to get the owning transactionId
    const root = await this.getRootNodeFromNode(approver.id);
    if (!root || root.transactionId !== expectedTransactionId)
        throw new UnauthorizedException('Approver does not belong to the specified transaction');

    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
    return result;
}
```

This mirrors the guard already present in `updateTransactionApprover`.

### Proof of Concept

**Preconditions:**
- Two registered users: Alice (attacker) and Bob (victim).
- Alice has created transaction T1 (any valid transaction).
- Bob has created transaction T2 with a 2-of-3 approver tree; one approver record has `id = 42`.

**Steps:**
```
# Alice authenticates and obtains JWT
POST /auth/login  →  { token: "alice_jwt" }

# Alice deletes Bob's approver from T2 using her own T1 as the authorization anchor
DELETE /transactions/{T1.id}/approvers/42
Authorization: Bearer alice_jwt

# Expected (correct) response: 403 Unauthorized
# Actual response: 200 OK — approver 42 deleted from T2
```

**Outcome:** Bob's transaction T2 now has a corrupted approval tree. If the deleted approver was the only remaining required signer, the transaction may advance to `WAITING_FOR_EXECUTION` with fewer signatures than the policy required. [1](#0-0) [2](#0-1) [4](#0-3)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L389-394)
```typescript
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
