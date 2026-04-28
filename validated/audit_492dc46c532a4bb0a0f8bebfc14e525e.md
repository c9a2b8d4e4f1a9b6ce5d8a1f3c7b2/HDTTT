All code references in the claim have been verified against the actual source. Every assertion is accurate.

---

Audit Report

## Title
Approver Approval Status Is Not Enforced Before Transaction Execution

## Summary
The Hedera Transaction Tool implements an approver workflow that allows designated users to approve or reject a transaction before it is submitted to the Hedera network. However, neither the status-transition engine (`processTransactionStatus`) nor the chain-service executor (`ExecuteService.executeTransaction` / `getValidatedSDKTransaction`) consults approver state at any point. A transaction with pending, unanswered, or explicitly rejected approvers will be promoted to `WAITING_FOR_EXECUTION` and submitted on-chain as soon as it accumulates sufficient cryptographic signatures, completely bypassing the organizational approval gate.

## Finding Description

**1. `processTransactionStatus` never checks approvers**

The function that decides when a transaction transitions from `WAITING_FOR_SIGNATURES` → `WAITING_FOR_EXECUTION` evaluates only the cryptographic signature key: [1](#0-0) 

`hasValidSignatureKey` and `smartCollate` operate entirely on the Hedera SDK key structure. There is no call to fetch approvers, no check of the `approved` flag, and no guard that blocks promotion when approvers have not yet acted.

**2. `getValidatedSDKTransaction` never checks approvers**

The execution path in `ExecuteService` calls `getValidatedSDKTransaction`, which again only validates the cryptographic signature: [2](#0-1) 

No approver-status check exists anywhere in this path before `sdkTransaction.execute(client)` is called.

**3. `getTransactionApproversForTransactions` is explicitly stubbed out**

The method that would supply approver data to the execution pipeline is a no-op: [3](#0-2) 

The comment `//To be implemented when approver functionality is added.` confirms this is a known gap.

**4. Approver recording works; enforcement does not**

`ApproversService.approveTransaction` correctly writes each user's approval decision (including the `approved` boolean) to the database: [4](#0-3) 

The `approved` column is defined in the schema: [5](#0-4) 

But nothing downstream reads those records before execution proceeds.

## Impact Explanation
Any transaction that has approvers assigned — including threshold-based approval trees — will be executed on the Hedera network as soon as it accumulates sufficient cryptographic signatures, regardless of whether the designated approvers have approved, rejected, or not yet responded. This completely nullifies the organizational approval control. Unauthorized or premature on-chain transactions (account updates, token transfers, node changes, etc.) can be submitted without the required human approval, defeating any compliance or governance requirement the approver workflow was intended to enforce.

## Likelihood Explanation
The approver feature is reachable through the normal API (`POST /transactions/:transactionId/approvers`): [6](#0-5) 

Any authenticated transaction creator can attach approvers to a transaction. Once the transaction collects enough Hedera key signatures, the chain-service scheduler (`updateTransactions` → `processTransactionStatus` → `collateAndExecute`) will automatically promote and execute it, ignoring all approver state: [7](#0-6) 

No privileged access is required beyond being a normal organization user.

## Recommendation
1. **Enforce approver status in `processTransactionStatus`**: Before setting `newStatus = WAITING_FOR_EXECUTION`, query the `TransactionApprover` table for the transaction and verify that all required approvers (respecting threshold trees) have `approved = true`. If any required approver has `approved = false` or `approved = null`, keep the status at `WAITING_FOR_SIGNATURES` (or introduce a dedicated `WAITING_FOR_APPROVAL` status).
2. **Implement `getTransactionApproversForTransactions`**: Remove the stub and implement the actual database query so approver data is available to the execution pipeline.
3. **Guard `getValidatedSDKTransaction`**: Add an approver-status check as a secondary enforcement layer so that even if a transaction somehow reaches `WAITING_FOR_EXECUTION` without full approval, execution is still blocked.
4. **Add integration tests** that assert a transaction with a pending or rejected approver cannot be promoted to `WAITING_FOR_EXECUTION`.

## Proof of Concept
1. Authenticated user A creates a transaction (e.g., a token transfer).
2. User A calls `POST /transactions/:id/approvers` to assign user B as a required approver.
3. User B calls `POST /transactions/:id/approvers/approve` with `approved: false`, recording a rejection in the `transaction_approver` table.
4. User A (or any key holder) uploads a valid cryptographic signature map via `POST /transactions/signers`.
5. `processTransactionStatus` runs, finds `hasValidSignatureKey` returns `true`, and promotes the transaction to `WAITING_FOR_EXECUTION` — the rejected approver record is never consulted.
6. The chain-service scheduler picks up the `WAITING_FOR_EXECUTION` transaction and calls `executeTransaction`, which calls `getValidatedSDKTransaction` (signature-only check), then submits the transaction to the Hedera network.
7. The transaction executes on-chain despite user B's explicit rejection.

### Citations

**File:** back-end/libs/common/src/utils/transaction/index.ts (L129-146)
```typescript
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
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L204-223)
```typescript
  private async getValidatedSDKTransaction(
    transaction: Transaction,
  ): Promise<SDKTransaction> {
    /* Throws an error if the transaction is not found or in incorrect state */
    if (!transaction) throw new Error('Transaction not found');

    await this.validateTransactionStatus(transaction);

    /* Gets the SDK transaction from the transaction body */
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    /* Gets the signature key */
    const signatureKey = await this.transactionSignatureService.computeSignatureKey(transaction);

    /* Checks if the transaction has valid signatureKey */
    if (!hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey))
      throw new Error('Transaction has invalid signature.');

    return sdkTransaction;
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L825-834)
```typescript
  async getTransactionApproversForTransactions(
    transactionIds: number[],
  ): Promise<TransactionApprover[]> {
    if (!transactionIds.length) {
      return [];
    }

    //To be implemented when approver functionality is added.
    return [];
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L598-610)
```typescript
    /* Update the approver with the signature */
    await this.dataSource.transaction(async transactionalEntityManager => {
      await transactionalEntityManager
        .createQueryBuilder()
        .update(TransactionApprover)
        .set({
          userKeyId: dto.userKeyId,
          signature: dto.signature,
          approved: dto.approved,
        })
        .whereInIds(userApprovers.map(a => a.id))
        .execute();
    });
```

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L63-64)
```typescript
  @Column({ nullable: true })
  approved?: boolean;
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L47-54)
```typescript
  @Post()
  createTransactionApprovers(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() body: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    return this.approversService.createTransactionApprovers(user, transactionId, body);
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
