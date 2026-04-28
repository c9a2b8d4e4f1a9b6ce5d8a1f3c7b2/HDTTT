### Title
Any Authenticated User Can Delete Any Transaction Approver Without Ownership Check

### Summary
The `removeTransactionApprover` function in `approvers.service.ts` accepts only an approver `id` and performs no caller-identity or transaction-ownership check before deleting the record. Every sibling mutating function (`createTransactionApprovers`, `updateTransactionApprover`) enforces that the caller is the transaction creator via `getCreatorsTransaction`, but `removeTransactionApprover` omits this check entirely. Any verified, authenticated user can therefore delete approvers belonging to transactions they do not own, corrupting multi-signature approval workflows.

### Finding Description

**Root cause — missing user parameter and ownership guard in `removeTransactionApprover`:** [1](#0-0) 

The function signature is `removeTransactionApprover(id: number)`. It fetches the approver by ID, then immediately calls `removeNode` with no check that the calling user owns the parent transaction.

**Contrast with `updateTransactionApprover`, which correctly enforces ownership:** [2](#0-1) 

`updateTransactionApprover` takes a `user: User` argument and calls `getCreatorsTransaction(rootNode.transactionId, user, ...)` before any mutation. `removeTransactionApprover` has no `user` parameter at all, so the service layer is structurally incapable of performing this check regardless of what the controller passes.

**`createTransactionApprovers` also enforces ownership:** [3](#0-2) 

The pattern is consistent across create and update — only delete is missing the guard.

**Controller-level guards are insufficient:** The controller uses `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`, which only confirm the caller is a valid, verified user. They do not enforce resource ownership. [4](#0-3) 

**Exploit flow:**
1. Attacker registers and verifies an account (standard user, no admin required).
2. Attacker learns or enumerates a `TransactionApprover` ID belonging to another user's transaction (IDs are sequential integers).
3. Attacker sends `DELETE /transactions/{transactionId}/approvers/{id}` with their own JWT.
4. `removeTransactionApprover(id)` executes, deletes the approver record, and emits a status update — no ownership check is performed.

### Impact Explanation

Deleting an approver from another user's transaction:
- Removes a required signer from a multi-signature workflow, potentially reducing the threshold below the intended security level.
- Can allow a transaction to advance to `WAITING_FOR_EXECUTION` or be executed with fewer approvals than the creator required.
- Permanently corrupts the approval audit trail for that transaction.
- In an organizational context (Hedera Council use case), this could allow an attacker to unilaterally strip approval requirements from high-value network transactions.

### Likelihood Explanation

- Precondition: attacker needs only a valid, verified account — the lowest privilege level in the system.
- Approver IDs are sequential integers, trivially enumerable via the `GET /transactions/{id}/approvers` endpoint (which is accessible to any verified user who can view the transaction).
- No rate limiting or anomaly detection is described for this endpoint.
- The attack is a single authenticated HTTP request.

### Recommendation

Add a `user: User` parameter to `removeTransactionApprover` and call `getCreatorsTransaction` (or an equivalent ownership assertion) before invoking `removeNode`, mirroring the pattern already used in `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, user: User): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Resolve root to get the owning transactionId
  const root = await this.getRootNodeFromNode(approver.id);
  if (!root) throw new BadRequestException(ErrorCodes.RANF);

  // Enforce that the caller is the transaction creator
  await this.getCreatorsTransaction(root.transactionId, user);

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
  return result;
}
```

Update the controller to pass the authenticated user to this call.

### Proof of Concept

**Setup:**
- User A creates a transaction with two required approvers (User B and User C).
- Attacker (User D) is a separate verified account.

**Steps:**
1. Attacker authenticates: `POST /auth/login` → receives JWT.
2. Attacker lists approvers for User A's transaction: `GET /transactions/42/approvers` → receives `[{id: 7, userId: B}, {id: 8, userId: C}]`.
3. Attacker sends: `DELETE /transactions/42/approvers/7` with their own JWT.
4. `removeTransactionApprover(7)` is called with no user check.
5. Approver record `id=7` (User B's approval requirement) is deleted from the database.
6. The transaction now only requires User C's approval, bypassing the intended 2-of-2 requirement.

**Expected result (correct behavior):** `403 Forbidden` — caller is not the transaction creator.
**Actual result:** `200 OK` — approver deleted. [1](#0-0)

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

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L37-41)
```typescript
@ApiTags('Transaction Signers')
@Controller('transactions/:transactionId?/signers')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class SignersController {
  constructor(private signaturesService: SignersService) {}
```
