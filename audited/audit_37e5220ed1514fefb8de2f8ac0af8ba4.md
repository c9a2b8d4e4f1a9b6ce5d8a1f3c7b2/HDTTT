### Title
Missing Caller Ownership Validation in `removeTransactionApprover` Allows Any Authenticated User to Remove Approvers from Arbitrary Transactions

### Summary
In `back-end/apps/api/src/transactions/approvers/approvers.service.ts`, the `removeTransactionApprover` function accepts only an approver `id` and performs no check that the calling user is the creator of the associated transaction. The sibling function `updateTransactionApprover` explicitly calls `getCreatorsTransaction` to enforce ownership, but `removeTransactionApprover` carries no equivalent guard. Any authenticated, non-admin user can delete approvers from transactions they do not own, dismantling the multi-signature governance structure of those transactions.

### Finding Description
**Root cause — inconsistent ownership enforcement between update and remove paths:**

`updateTransactionApprover` (line 367) accepts a `user: User` parameter and explicitly calls `getCreatorsTransaction` at line 394 to verify the caller owns the transaction before mutating state. [1](#0-0) 

`removeTransactionApprover` (line 534) accepts only `id: number` — no `user` parameter, no ownership check — and proceeds directly to `removeNode` and a status-update emission. [2](#0-1) 

The function signature itself proves the omission: the service layer has no mechanism to enforce that the caller owns the transaction, because the caller's identity is never passed in.

**Exploit flow:**

1. Attacker registers as a normal user (no admin required).
2. Attacker learns or enumerates a `TransactionApprover.id` belonging to a transaction created by another user (IDs are sequential integers).
3. Attacker calls the DELETE approver endpoint with that ID.
4. `removeTransactionApprover(id)` fetches the approver, calls `removeNode`, and emits a status-update notification — all without ever checking whether the attacker owns the parent transaction.
5. The required approver is gone; the transaction's approval threshold may now be satisfiable without the intended signers.

### Impact Explanation
Removing an approver from another user's transaction directly undermines the multi-signature governance model. An attacker can:
- Strip required approvers from a high-value transaction, reducing the effective signing threshold.
- Force a transaction into `WAITING_FOR_EXECUTION` prematurely by eliminating blocking approvers.
- Corrupt the approval tree of any transaction whose approver IDs are discoverable, causing irreversible state changes (soft-deleted approver nodes cannot be trivially restored).

This is an **unauthorized state change** with direct impact on transaction integrity and governance.

### Likelihood Explanation
- Precondition: a valid, verified user account — obtainable by any registrant.
- No admin, no leaked credentials, no privileged role required.
- `TransactionApprover` IDs are sequential integers; enumeration is trivial.
- The attack is a single authenticated HTTP DELETE request.

Likelihood is **high**.

### Recommendation
Add a `user: User` parameter to `removeTransactionApprover` and call `getCreatorsTransaction` (or an equivalent ownership check) before invoking `removeNode`, mirroring the pattern already used in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, user: User): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Verify the caller owns the transaction
  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);
  await this.getCreatorsTransaction(rootNode.transactionId, user);

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

Update the controller and all call sites to pass the authenticated user.

### Proof of Concept

1. Register two accounts: `victim` (creates a transaction with approvers) and `attacker` (normal user).
2. `victim` creates a transaction and adds an approver; note the returned `TransactionApprover.id` (e.g., `42`).
3. `attacker` authenticates and sends:
   ```
   DELETE /transactions/{transactionId}/approvers/42
   Authorization: Bearer <attacker_token>
   ```
4. **Expected (secure):** `401 Unauthorized` — attacker does not own the transaction.
5. **Actual (vulnerable):** `200 OK` — approver `42` is deleted from `victim`'s transaction without any ownership check, as confirmed by the absence of a `user` parameter in `removeTransactionApprover` at line 534. [2](#0-1)

### Citations

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L534-543)
```typescript
  async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);

    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const result = await this.removeNode(approver.id);

    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);

    return result;
```
