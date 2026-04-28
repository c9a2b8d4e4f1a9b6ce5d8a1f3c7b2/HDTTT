### Title
Any Authenticated User Can Remove Approvers from Transactions They Do Not Own

### Summary
`removeTransactionApprover` in `approvers.service.ts` accepts only an approver `id` and performs no ownership check against the calling user. Any authenticated user can delete an approver belonging to a transaction they did not create, bypassing the multi-signature workflow invariant. This is the direct analog of the external report's pattern: a state-mutating function that validates entity existence but omits the critical authorization/ownership guard before committing the mutation.

### Finding Description

`updateTransactionApprover` (the sibling write path) accepts a `user: User` parameter and explicitly calls `getCreatorsTransaction` to verify the caller owns the transaction before proceeding: [1](#0-0) 

`removeTransactionApprover`, however, accepts only `id: number`. There is no `user` parameter and no ownership check anywhere in the function body: [2](#0-1) 

The function checks that the approver row exists (`if (!approver) throw`), then unconditionally removes the node and emits a `emitTransactionStatusUpdate` event carrying the victim transaction's ID. Because the service never receives the caller's identity, no controller-level guard can compensate — the service layer simply has no slot to enforce ownership.

The observers controller pattern confirms that JWT guards (`JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard`) only assert that the caller is a verified, non-blacklisted user — they do not assert resource ownership: [3](#0-2) 

An attacker who is a legitimate authenticated user can therefore call `DELETE /transactions/:transactionId/approvers/:id` with any approver `id` they enumerate or guess, and the service will remove it without checking whether the caller created the parent transaction.

### Impact Explanation

Removing an approver from a transaction the attacker does not own:

1. **Reduces the required signature threshold** — if a threshold-based approver list had `N` children and the attacker removes one, the parent node's threshold may be auto-decremented (see `newParentApproversLength < parent.threshold` logic in `updateTransactionApprover`), allowing the transaction to reach `WAITING_FOR_EXECUTION` with fewer real approvals than the creator intended.
2. **Corrupts the approval state** — the `emitTransactionStatusUpdate` event is fired unconditionally, causing downstream notification and status-recalculation logic to run against a now-invalid approver tree.
3. **Denial of approval workflow** — a malicious user can repeatedly delete approvers, permanently preventing a transaction from collecting the required approvals. [4](#0-3) 

### Likelihood Explanation

- **Precondition**: The attacker must be an authenticated, verified user — a normal product account, no privileged role required.
- **Discovery**: Approver IDs are sequential integers returned in API responses visible to any participant of a transaction. An attacker who is an observer or signer on one transaction can enumerate IDs for approvers on other transactions.
- **Trigger**: A single authenticated `DELETE` request to the approvers endpoint with a valid approver `id` belonging to another user's transaction.

No special tooling, leaked credentials, or privileged access is required.

### Recommendation

Add a `user: User` parameter to `removeTransactionApprover` and call `getCreatorsTransaction` (or the equivalent ownership guard) before executing the removal, mirroring the pattern already used in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, user: User): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  const rootNode = await this.getRootNodeFromNode(approver.id);
  if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

  // Verify the caller owns the transaction
  await this.getCreatorsTransaction(rootNode.transactionId, user);

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

Update the controller to pass `@GetUser() user: User` to the service call.

### Proof of Concept

**Setup:**
- User A creates a transaction with an approver list requiring User B and User C.
- User D is a separate authenticated user with no relationship to the transaction.

**Attack steps:**
1. User D authenticates and obtains a JWT.
2. User D observes or guesses the approver ID (e.g., `id = 42`) from any API response that leaks approver IDs.
3. User D sends:
   ```
   DELETE /transactions/1/approvers/42
   Authorization: Bearer <User D's token>
   ```
4. `removeTransactionApprover(42)` is called. The approver exists, so the existence check passes. No ownership check runs. The approver is deleted and `emitTransactionStatusUpdate` fires.

**Expected (broken) outcome:** User B's approver entry is removed from User A's transaction. The transaction's approval threshold may be silently decremented, allowing it to proceed with one fewer required signature than the creator intended. [2](#0-1)

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

**File:** back-end/apps/api/src/transactions/observers/observers.controller.ts (L27-31)
```typescript
@ApiTags('Transaction Observers')
@Controller('transactions/:transactionId?/observers')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
@Serialize(TransactionObserverDto)
export class ObserversController {
```
