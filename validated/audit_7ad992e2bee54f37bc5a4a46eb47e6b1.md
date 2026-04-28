### Title
Transaction Creator Can Modify Approver Structure After Approvals Are Given, Invalidating Multi-Signature Integrity

### Summary
The transaction creator can add, remove, or replace approvers and change approval thresholds at any time — including while the transaction is in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` status — with no status-based guard. This allows a malicious creator to invalidate existing approvals, evict approvers who rejected the transaction, or lower the threshold to bypass the intended multi-signature requirement. This is the direct analog of the external report's "admin front-running" class: a privileged role (the creator) can silently change the rules of a pending action after other parties have already acted.

---

### Finding Description

**Root cause — `getCreatorsTransaction` has no status check:** [1](#0-0) 

`getCreatorsTransaction` is the sole authorization gate for all three approver-mutation operations. It only verifies that `transaction.creatorKey?.userId === user.id`. It never inspects `transaction.status`. Any transaction status — including `WAITING_FOR_SIGNATURES` and `WAITING_FOR_EXECUTION` — passes through.

**All three mutation paths rely on this gate:**

1. **Create approvers** — `createTransactionApprovers` calls `getCreatorsTransaction` as its only guard: [2](#0-1) 

2. **Update approver** — `updateTransactionApprover` calls `getCreatorsTransaction` inside the DB transaction, with no status check: [3](#0-2) 

3. **Remove approver** — the controller calls `getCreatorsTransaction` then immediately removes: [4](#0-3) 

**Approval state is silently wiped on userId update:**

When the creator replaces an approver's `userId`, the existing `signature`, `userKeyId`, and `approved` fields are explicitly cleared: [5](#0-4) 

**Threshold can be lowered at any time:** [6](#0-5) 

---

### Impact Explanation

The multi-signature approval workflow's integrity guarantee is broken. Concrete outcomes:

- **Approval erasure**: Creator replaces Approver A (who already approved) with a new user, clearing A's recorded signature and `approved` flag. The transaction reverts to needing fresh approvals.
- **Rejection bypass**: Approver B rejects the transaction. Creator removes B and adds a colluding user C, who then approves. The rejection is silently discarded.
- **Threshold manipulation**: Creator lowers the threshold from 3-of-5 to 1-of-5 after only one approval is collected, causing the transaction to immediately satisfy the approval requirement without the originally-agreed quorum.
- **Approver removal after approval**: Creator removes all approvers who have approved, then re-adds them, resetting the approval state and forcing re-approval indefinitely (DoS against execution).

---

### Likelihood Explanation

- **Attacker profile**: Any authenticated user who has created a transaction. No admin, no leaked credentials, no privileged keys required.
- **Entry point**: Standard REST API endpoints `POST /transactions/:id/approvers`, `PATCH /transactions/:id/approvers/:id`, `DELETE /transactions/:id/approvers/:id` — all reachable by any authenticated creator.
- **Trigger**: The creator simply calls these endpoints while the transaction is in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`. No race condition or timing dependency is required; the window is the entire active lifetime of the transaction.

---

### Recommendation

Add a status guard inside `getCreatorsTransaction` (or at the top of each mutation function) that rejects modifications when the transaction has already entered an active approval phase:

```typescript
const IMMUTABLE_STATUSES = [
  TransactionStatus.WAITING_FOR_SIGNATURES,
  TransactionStatus.WAITING_FOR_EXECUTION,
  TransactionStatus.EXECUTED,
  TransactionStatus.CANCELED,
  TransactionStatus.EXPIRED,
  TransactionStatus.FAILED,
];

if (IMMUTABLE_STATUSES.includes(transaction.status)) {
  throw new BadRequestException('Approver structure cannot be modified after the transaction has entered signing phase');
}
```

This mirrors the time-lock recommendation in the external report: once approvers have been notified and may have acted, the rules governing their participation must be frozen.

---

### Proof of Concept

**Setup**: Organization with users Alice (creator), Bob, Carol, Dave.

1. Alice creates a transaction with approvers Bob, Carol, Dave and threshold 2-of-3.
2. Bob approves the transaction (`POST /transactions/1/approvers/approve`). Bob's `approved=true`, `signature=<sig>` are stored.
3. Carol rejects the transaction. Carol's `approved=false` is stored.
4. Alice calls `PATCH /transactions/1/approvers/<carol_approver_id>` with body `{ "userId": <eve_id> }`.
   - Carol's rejection is wiped (`approved=undefined`, `signature=undefined`).
   - Eve is now an approver with no recorded choice.
5. Alice calls `PATCH /transactions/1/approvers/<dave_approver_id>` with body `{ "threshold": 1 }` on the parent tree node, lowering the required threshold to 1-of-3.
6. Eve approves. The transaction now satisfies the (manipulated) threshold with only Bob's original approval + Eve's new approval, bypassing Carol's rejection and the original 2-of-3 quorum.

**Expected result**: The approval workflow completes with a quorum that was never agreed upon by the approvers, violating the integrity guarantee of the multi-signature system.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L393-394)
```typescript
        /* Verifies that the user is the creator of the transaction */
        await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L479-488)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L500-516)
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

            return approver;
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L623-644)
```typescript
  /* Get the transaction by id and verifies that the user is the creator */
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
