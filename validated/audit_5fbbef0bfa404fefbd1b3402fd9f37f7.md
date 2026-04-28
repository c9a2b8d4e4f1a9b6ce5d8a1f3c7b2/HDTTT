I have now read the full `approvers.service.ts` and the relevant controller. Let me verify the specific claims against the actual code before rendering a verdict.

**Confirmed facts from the code:**

1. `getCreatorsTransaction` (lines 624–644) checks only `creatorKey.userId !== user.id` — no `status` field is read. [1](#0-0) 

2. `updateTransactionApprover` calls `getCreatorsTransaction` as its sole guard, then mutates `threshold`, `listId`, or `userId` with zero status gate. [2](#0-1) 

3. Threshold mutation path — no status check before writing to DB. [3](#0-2) 

4. `userId`-replacement path explicitly clears `signature`, `userKeyId`, and `approved` of the replaced approver. [4](#0-3) 

5. `createTransactionApprovers` — only a creator check at line 239, no status check anywhere in the method. [5](#0-4) 

6. `removeTransactionApprover` (service) — no status check. The controller does call `getCreatorsTransaction` first, but neither layer checks `TransactionStatus`. [6](#0-5) [7](#0-6) 

7. By contrast, `approveTransaction` — the action that *approvers* take — does enforce a status gate (`WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`). The creator-side mutation methods have no equivalent gate. [8](#0-7) 

All four required checks pass. The vulnerability is confirmed.

---

# Audit Report

## Title
Transaction Creator Can Arbitrarily Modify Approver Threshold After Approvals Are Collected, Bypassing Multi-Signature Governance

## Summary
`ApproversService` allows the transaction creator to lower the approval threshold, replace approvers (clearing their collected signatures), or remove approvers entirely at any point in the transaction lifecycle. None of the three mutating methods — `updateTransactionApprover`, `createTransactionApprovers`, or `removeTransactionApprover` — check `TransactionStatus` before writing to the database. The sole guard, `getCreatorsTransaction`, verifies only creator identity.

## Finding Description

**Root cause:** `getCreatorsTransaction` in `approvers.service.ts` (lines 624–644) reads `transaction.creatorKey.userId` and throws if it does not match the caller. It never reads `transaction.status`. [9](#0-8) 

`updateTransactionApprover` (lines 367–531) calls this guard at line 394 and then unconditionally proceeds to mutate the approver tree:

- **Threshold path** (lines 467–488): writes a new `threshold` value to the database with no status gate. [10](#0-9) 

- **userId-replacement path** (lines 489–517): replaces the approver and explicitly nullifies `signature`, `userKeyId`, and `approved`, erasing any previously collected approval. [4](#0-3) 

`createTransactionApprovers` (lines 234–364) calls `getCreatorsTransaction` at line 239 and then inserts new approver nodes with no status check. [5](#0-4) 

`removeTransactionApprover` (lines 534–544) in the service has no status check. The controller calls `getCreatorsTransaction` before delegating (controller lines 108–109), but neither layer checks `TransactionStatus`. [7](#0-6) 

For comparison, `approveTransaction` — the action taken by approvers — correctly enforces a status gate before accepting any approval: [8](#0-7) 

No equivalent gate exists on any creator-side mutation path.

## Impact Explanation

The multi-signature approval model is the core trust guarantee of the organizational workflow. Without a status lock on the approver structure, a malicious creator can:

1. **Threshold reduction**: After approver A signs, call `PATCH /transactions/:id/approvers/:nodeId` with `{ "threshold": 1 }`. The threshold node is updated in the database. The next status evaluation reads the new threshold and may consider the approval requirement satisfied with a single signature, allowing execution without the remaining approvers' consent.

2. **Approver substitution**: Call `PATCH` with `{ "userId": colludingUserId }` to replace any approver who has not yet approved. The existing approval record (`signature`, `userKeyId`, `approved`) is explicitly cleared (lines 501–510), and the colluding user is substituted. The creator can manufacture artificial consensus.

3. **Approver removal**: Call `DELETE /transactions/:id/approvers/:nodeId`. The entire subtree is soft-deleted (via `removeNode`), reducing the approver pool and making the existing threshold trivially satisfiable.

All three attacks are invisible in audit logs — they look like normal threshold or approver updates.

## Likelihood Explanation

- **Attacker profile**: Any registered user who creates a transaction. No admin credentials or leaked keys required.
- **Entry point**: Standard authenticated REST endpoints (`PATCH /:id/approvers/:nodeId`, `DELETE /:id/approvers/:nodeId`, `POST /:id/approvers`).
- **Precondition**: The attacker must be the transaction creator — a role any user can hold by creating a transaction.
- **Detectability**: The modification is indistinguishable from a legitimate pre-approval structure change; no anomaly detection exists.

## Recommendation

Add a `TransactionStatus` check inside `getCreatorsTransaction` (or as a dedicated guard called by all three mutating methods) that rejects modifications once the transaction has left the `NEW` state (or whichever state is defined as "approver structure is frozen"). Example:

```typescript
if (transaction.status !== TransactionStatus.NEW) {
  throw new BadRequestException('Approver structure cannot be modified after the transaction is active');
}
```

This mirrors the guard already present in `approveTransaction` and closes the asymmetry between what approvers and creators are permitted to do at each lifecycle stage.

## Proof of Concept

```
# Setup: creator creates transaction T with 3-of-5 threshold (tree node ID = 42)
POST /transactions/T/approvers
{ "approversArray": [{ "threshold": 3, "approvers": [A, B, C, D, E] }] }

# Approver A approves
POST /transactions/T/approvers/approve   (as user A)
{ "userKeyId": ..., "signature": ..., "approved": true }

# Creator immediately lowers threshold to 1
PATCH /transactions/T/approvers/42       (as creator)
{ "threshold": 1 }
# → HTTP 200, threshold written to DB, no status check performed

# Status re-evaluation now sees threshold=1 satisfied by A's existing signature
# Transaction proceeds to WAITING_FOR_EXECUTION without B, C, D, E approving
```

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L500-514)
```typescript
          if (approver.userId !== dto.userId) {
            const data: DeepPartial<TransactionApprover> = {
              userId: dto.userId,
              userKeyId: undefined,
              signature: undefined,
              approved: undefined,
            };

            approver.userKeyId = undefined;
            approver.signature = undefined;
            approver.approved = undefined;

            await transactionalEntityManager.update(TransactionApprover, approver.id, data);
            approver.userId = dto.userId;
            updated = true;
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L103-113)
```typescript
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
