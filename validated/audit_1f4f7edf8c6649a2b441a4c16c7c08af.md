### Title
Transaction Approver Structure Can Be Modified Mid-Approval, Allowing Creator to Bypass Approval Threshold

### Summary
The `createTransactionApprovers` and `updateTransactionApprover` functions in the back-end API do not check the transaction's current status before modifying the approver tree. A transaction creator — a normal authenticated user — can add, remove, or restructure approvers and thresholds on a transaction that is already in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` state. This allows the creator to retroactively lower the approval threshold after insufficient approvals have been collected, forcing the transaction to execute without the originally required consent.

### Finding Description

**Root cause:** `getCreatorsTransaction` — the only guard called by both `createTransactionApprovers` and `updateTransactionApprover` — checks only that the caller is the transaction creator. It performs no status check. [1](#0-0) 

`createTransactionApprovers` delegates entirely to this guard: [2](#0-1) 

`updateTransactionApprover` does the same inside its database transaction: [3](#0-2) 

Neither function checks whether the transaction is in `NEW`, `WAITING_FOR_SIGNATURES`, or `WAITING_FOR_EXECUTION` before mutating the approver tree. The threshold update path is equally unguarded: [4](#0-3) 

By contrast, `approveTransaction` — the function that records a user's approval — correctly enforces a status guard: [5](#0-4) 

The approver structure is the sole mechanism governing whether the chain service considers a transaction ready for execution. The chain service's scheduler evaluates collected approvals against the live approver tree at execution time: [6](#0-5) 

**Exploit flow:**

1. Creator creates a transaction and sets an approver tree with threshold `2 of 3`.
2. Transaction moves to `WAITING_FOR_SIGNATURES`.
3. Only one of the three approvers approves — threshold not met.
4. Creator calls `PATCH /transactions/:transactionId/approvers/:id` with `{ "threshold": 1 }`, lowering the threshold to `1 of 3`.
5. The chain service's next scheduler tick evaluates the live approver tree, finds threshold satisfied, and advances the transaction to `WAITING_FOR_EXECUTION` and then executes it on Hedera.

The inverse is also possible: after all required approvals are collected, the creator adds a new approver who has not yet approved, stalling execution indefinitely.

### Impact Explanation

The multi-signature approval workflow is the primary governance control for organization-mode transactions. Bypassing it allows the transaction creator to execute arbitrary Hedera transactions (HBAR transfers, account updates, file updates, etc.) without the consent of the required approvers. This constitutes unauthorized state change and potential unauthorized movement of assets on the Hedera network. Severity is high because the approval structure is the only barrier between a pending transaction and on-chain execution.

### Likelihood Explanation

The attacker is the transaction creator — any authenticated organization user. No privileged credentials are required. The attack requires only two sequential API calls: one to create/submit the transaction and one to update the approver threshold. The endpoint is reachable by any user who can create transactions in organization mode. The window of opportunity is the entire duration the transaction is in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`.

### Recommendation

Add a status guard inside `getCreatorsTransaction` (or at the entry of `createTransactionApprovers` and `updateTransactionApprover`) that rejects modifications when the transaction is not in `NEW` status:

```typescript
if (transaction.status !== TransactionStatus.NEW) {
  throw new BadRequestException('Approver structure cannot be modified after signing has begun');
}
```

This mirrors the fix applied in the referenced Bancor report: snapshot (or lock) the governing parameters at the point the operation begins, and reject any attempt to change them mid-flight.

### Proof of Concept

**Preconditions:** Two users exist — Alice (creator) and Bob/Carol/Dave (approvers). Alice creates a transaction with threshold `2 of 3`.

```
POST /transactions
→ { id: 42, status: "WAITING FOR SIGNATURES" }

POST /transactions/42/approvers
→ approver tree: threshold=2, approvers=[Bob, Carol, Dave]
  root approver id: 7
```

**Step 1 — Bob approves (1 of 2 required):**
```
POST /transactions/42/approve
{ userKeyId: ..., signature: ..., approved: true }
```

**Step 2 — Alice lowers threshold to 1 (while status is still WAITING FOR SIGNATURES):**
```
PATCH /transactions/42/approvers/7
{ "threshold": 1 }
→ 200 OK  ← no status check, succeeds
```

**Step 3 — Chain scheduler runs:**
The scheduler reads the live approver tree, sees threshold=1, finds Bob's approval satisfies it, advances the transaction to `WAITING_FOR_EXECUTION`, and submits it to Hedera — without Carol's or Dave's consent. [7](#0-6)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-240)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);

```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L367-395)
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

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L130-158)
```typescript
  /* Checks if the signers are enough to sign the transactions and update their statuses */
  async updateTransactions(from: Date, to?: Date) {
    //Get the transaction, creatorKey, groupItem, and group. We need the group info upfront
    //in order to determine if the group needs to be processed together
    const transactions = await this.transactionRepo.find({
      where: {
        status: In([
          TransactionStatus.WAITING_FOR_SIGNATURES,
          TransactionStatus.WAITING_FOR_EXECUTION,
        ]),
        validStart: to ? Between(from, to) : MoreThan(from),
      },
      relations: {
        creatorKey: true,
        groupItem: {
          group: true,
        },
      },
      order: {
        validStart: 'ASC',
      },
    });

    const results = await processTransactionStatus(this.transactionRepo, this.transactionSignatureService, transactions);

    if (results.size > 0) {
      const events = Array.from(results.keys(), id => ({ entityId: id }));
      emitTransactionStatusUpdate(this.notificationsPublisher, events);
    }
```
