### Title
`createTransactionApprovers`, `removeTransactionApprover`, and `updateTransactionApprover` Lack Transaction Status Guards, Allowing Approval-State Manipulation on Already-Approved Transactions

### Summary
`ApproversService` in `approvers.service.ts` exposes three mutating functions — `createTransactionApprovers`, `removeTransactionApprover`, and `updateTransactionApprover` — that modify a transaction's approval structure without checking the transaction's current status. A transaction creator (a normal, unprivileged user) can invoke these endpoints on a transaction that is already in `WAITING_FOR_EXECUTION` (all approvals met, ready to execute), causing the status to be re-evaluated and potentially reverting the transaction back to `WAITING_FOR_SIGNATURES`, indefinitely blocking execution.

### Finding Description

**Root cause — missing status guard in all three mutating approver functions:**

`createTransactionApprovers` calls `getCreatorsTransaction` only to verify the caller is the creator; it performs no status check: [1](#0-0) 

`removeTransactionApprover` only checks that the approver record exists: [2](#0-1) 

`updateTransactionApprover` similarly delegates to `getCreatorsTransaction` with no status guard: [3](#0-2) 

`getCreatorsTransaction` only enforces creator identity, never the transaction's lifecycle state: [4](#0-3) 

**Contrast with functions that do enforce status:** `approveTransaction` and `uploadSignatureMaps` both explicitly reject calls when the transaction is not in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`: [5](#0-4) [6](#0-5) 

The three mutating approver functions have no equivalent guard.

**Exploit path — blocking execution of an already-approved transaction:**

1. Creator submits a transaction; it collects all required approvals and transitions to `WAITING_FOR_EXECUTION`.
2. Creator calls `POST /transactions/:transactionId/approvers` (`createTransactionApprovers`) to inject a new approver (e.g., a user who will never approve).
3. `emitTransactionStatusUpdate` is called at the end of `createTransactionApprovers`: [7](#0-6) 

4. `processTransactionStatus` re-evaluates the approval tree; the new approver has not signed, so the threshold is no longer met, and the transaction reverts to `WAITING_FOR_SIGNATURES`.
5. The creator can repeat this indefinitely, permanently preventing execution.

The controller entry point for removal confirms no status check is added there either: [8](#0-7) 

### Impact Explanation

A transaction creator — a normal, unprivileged user — can:
- Permanently block execution of a transaction that all required approvers have already signed off on, by injecting a new approver who will never approve.
- Retroactively remove an approver whose signature pushed the transaction over the threshold, reverting it to `WAITING_FOR_SIGNATURES`.
- Modify the approval tree of a transaction in a terminal state (`EXECUTED`, `CANCELED`, `FAILED`), corrupting the audit trail.

The first two scenarios constitute a targeted, repeatable denial-of-execution attack against any transaction the attacker created, regardless of how many other users have already approved it.

### Likelihood Explanation

The attacker precondition is only that the attacker is the creator of the target transaction — a role any registered user can hold. No privileged access, leaked credentials, or external dependencies are required. The attack is a single authenticated API call (`POST /transactions/:id/approvers`) with a valid JWT. It is trivially repeatable.

### Recommendation

Add a transaction status guard at the top of `createTransactionApprovers`, `removeTransactionApprover`, and `updateTransactionApprover` (or inside `getCreatorsTransaction`) that rejects calls when the transaction is not in a mutable state. For example:

```typescript
if (
  transaction.status !== TransactionStatus.NEW &&
  transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES
) {
  throw new BadRequestException('Cannot modify approvers: transaction is not in a modifiable state');
}
```

This mirrors the guard already present in `approveTransaction` and `validateTransactionStatus`.

### Proof of Concept

**Preconditions:** Two registered users — Alice (creator) and Bob (approver). Transaction T requires Bob's approval.

1. Alice creates transaction T; Bob approves it; T transitions to `WAITING_FOR_EXECUTION`.
2. Alice sends:
   ```
   POST /transactions/T/approvers
   Authorization: Bearer <alice_jwt>
   { "approversArray": [{ "userId": <carol_id> }] }
   ```
   where Carol is a user who will never approve.
3. `createTransactionApprovers` succeeds (no status check), inserts Carol as a new approver, and calls `emitTransactionStatusUpdate`.
4. `processTransactionStatus` re-evaluates: Carol has not approved → threshold not met → T reverts to `WAITING_FOR_SIGNATURES`.
5. Alice repeats step 2 with a fresh user each time Bob re-approves, permanently preventing execution.

**Expected (correct) behavior:** Step 2 should return HTTP 400 because T is in `WAITING_FOR_EXECUTION` and its approval structure must not be mutable at that point.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L358-358)
```typescript
      emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transactionId  }]);
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L583-588)
```typescript
    /* Checks if the transaction is requires approval */
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);
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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L201-215)
```typescript
  private validateTransactionStatus(transaction: Transaction): string | null {
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    ) {
      return ErrorCodes.TNRS;
    }

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    if (isExpired(sdkTransaction)) {
      return ErrorCodes.TE;
    }

    return null;
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
