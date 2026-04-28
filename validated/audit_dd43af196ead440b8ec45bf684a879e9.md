Audit Report

## Title
Transaction Creator Can Modify Approver Structure After Signatures Are Collected, Bypassing Multi-Sig Threshold

## Summary
The `createTransactionApprovers`, `updateTransactionApprover`, and `removeTransactionApprover` endpoints perform no check on the transaction's current status before mutating the approver tree. Any authenticated transaction creator can lower the approval threshold or remove signed approvers after other parties have already committed their signatures, silently bypassing the intended multi-signature requirement.

## Finding Description

The root cause is `getCreatorsTransaction`, the sole authorization gate used by all three approver-mutation paths. It only verifies that the caller is the transaction creator — it never inspects `transaction.status`: [1](#0-0) 

All three mutation paths delegate to this function and add no status guard of their own:

- **`createTransactionApprovers`** — calls `getCreatorsTransaction` at line 239 then proceeds unconditionally: [2](#0-1) 

- **`removeTransactionApprover` (controller)** — calls `getCreatorsTransaction` then removes the approver with no status check: [3](#0-2) 

- **`updateTransactionApprover`** — calls `getCreatorsTransaction` inside the DB transaction but never checks status: [4](#0-3) 

By contrast, `approveTransaction` — the path used by approvers — does enforce a status check, confirming the pattern is intentional for approvers but was simply omitted for the creator's mutation paths: [5](#0-4) 

## Impact Explanation

The Hedera Transaction Tool's core security guarantee is that a transaction cannot be submitted to the Hedera network unless the configured set of approvers has signed off. Bypassing the threshold check breaks this guarantee entirely. For Hedera Council use cases — where transactions may govern network-level parameters — this means a single compromised or malicious creator account can unilaterally execute transactions that were designed to require consensus from multiple independent parties.

## Likelihood Explanation

The attacker is any authenticated user who created a transaction. No admin credentials, no leaked keys, and no external access are required. The API endpoint is reachable over standard HTTP with a valid JWT. The window of opportunity is the entire `WAITING_FOR_SIGNATURES` / `WAITING_FOR_EXECUTION` period, which can last hours or days in practice.

## Recommendation

Add a status guard at the top of each of the three mutation paths (or inside `getCreatorsTransaction` itself) that rejects requests when the transaction is not in `NEW` status. For example:

```typescript
// In getCreatorsTransaction, after fetching the transaction:
if (transaction.status !== TransactionStatus.NEW) {
  throw new BadRequestException('Approver structure cannot be modified after signing has begun');
}
```

Alternatively, restrict mutations to only `NEW` status in each individual service method (`createTransactionApprovers`, `updateTransactionApprover`, `removeTransactionApprover`) to allow finer-grained control per operation.

## Proof of Concept

1. Creator submits a transaction with a threshold-3-of-3 approver tree (all three council members must sign). Transaction enters `WAITING_FOR_SIGNATURES`.
2. Approver A and Approver B sign. Two of three required signatures are collected.
3. Creator calls `PATCH /transactions/:id/approvers/:nodeId` with `{ "threshold": 2 }`. The request passes through `updateTransactionApprover` → `getCreatorsTransaction` (only checks creator identity) with no status check blocking it. [6](#0-5) 
4. The threshold node is updated to 2-of-3 in the database.
5. The scheduler's `processTransactionStatus` re-evaluates the tree, finds 2 signatures satisfy the new threshold-2 requirement, and advances the transaction to `WAITING_FOR_EXECUTION`. [7](#0-6) 
6. The transaction is executed on-chain without Approver C's signature, bypassing the original 3-of-3 requirement.

The same primitive can be used to remove a signed approver from the tree via `DELETE /transactions/:id/approvers/:nodeId`, or to inject a new approver controlled by the creator after legitimate approvers have already signed via `POST /transactions/:id/approvers`.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L583-588)
```typescript
    /* Checks if the transaction is requires approval */
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);
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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L118-155)
```typescript
export async function processTransactionStatus(
  transactionRepo: Repository<Transaction>,
  transactionSignatureService: TransactionSignatureService,
  transactions: Transaction[],
): Promise<Map<number, TransactionStatus>> {
  const statusChanges = new Map<number, TransactionStatus>();

  // Group intended updates by [newStatus, oldStatus] so we can bulk update
  // only rows that still have the expected current status
  const updatesByStatus = new Map<string, { newStatus: TransactionStatus, oldStatus: TransactionStatus, ids: number[] }>();

  for (const transaction of transactions) {
    if (!transaction) continue;

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    const signatureKey = await transactionSignatureService.computeSignatureKey(transaction);
    const isAbleToSign = hasValidSignatureKey(
      [...sdkTransaction._signerPublicKeys],
      signatureKey
    );

    let newStatus = TransactionStatus.WAITING_FOR_SIGNATURES;

    if (isAbleToSign) {
      const collatedTx = await smartCollate(transaction, signatureKey);
      if (collatedTx !== null) {
        newStatus = TransactionStatus.WAITING_FOR_EXECUTION;
      }
    }

    if (transaction.status !== newStatus) {
      const key = `${transaction.status}->${newStatus}`;
      if (!updatesByStatus.has(key)) {
        updatesByStatus.set(key, { newStatus, oldStatus: transaction.status, ids: [] });
      }
      updatesByStatus.get(key)!.ids.push(transaction.id);
    }
  }
```
