### Title
Approver Threshold Not Decremented When Child Approver Is Removed, Permanently Blocking Transaction Approval

### Summary
The `TransactionApprover` tree structure stores a `threshold` value on parent nodes that must be satisfied for a transaction to advance to `WAITING_FOR_EXECUTION`. When a child approver node is removed via `removeTransactionApprover`, the parent node's `threshold` is never decremented. If the threshold was set equal to the original child count, removing even one child makes the threshold permanently unsatisfiable, locking the transaction in `WAITING_FOR_SIGNATURES` until it expires.

### Finding Description

The system enforces at creation and update time that `threshold ≤ children.length`: [1](#0-0) 

The same guard exists when updating a threshold: [2](#0-1) 

However, `removeTransactionApprover` calls `removeNode`, which soft-deletes the target node and all its descendants via a recursive SQL query, but **never touches the parent node's `threshold` column**: [3](#0-2) [4](#0-3) 

**Concrete scenario:**

1. Creator builds an approver tree: parent node with `threshold = 3`, children A, B, C.
2. Creator removes child A (e.g., user left the organization). `removeNode` soft-deletes A; parent still has `threshold = 3`.
3. Only B and C remain. Even if both approve, the threshold of 3 can never be reached.
4. `processTransactionStatus` evaluates whether enough approvals exist; the condition is never satisfied.
5. The transaction stays in `WAITING_FOR_SIGNATURES` until its `validStart` expires. [5](#0-4) 

### Impact Explanation

A transaction whose approver threshold becomes unsatisfiable is permanently blocked from reaching `WAITING_FOR_EXECUTION`. The chain service's scheduler will never execute it: [6](#0-5) 

The transaction will expire, wasting any fees already paid and failing the business operation the transaction was meant to perform. In a multi-signature organizational workflow this is a meaningful operational DoS.

### Likelihood Explanation

Removing an approver is a routine operation (user leaves an organization, key is compromised). The DELETE endpoint is exposed and accessible to the transaction creator: [7](#0-6) 

No warning is emitted to the creator that the parent threshold is now unsatisfiable after the removal. The creator must manually discover the inconsistency and issue a separate threshold-update call, which many users will not do.

### Recommendation

In `removeTransactionApprover` (or inside `removeNode`), after soft-deleting the child, query the parent node (the node whose `id = deletedNode.listId`) and, if the remaining non-deleted child count is now less than the parent's `threshold`, automatically decrement `threshold` to `remainingChildren.length` (or reject the removal with an informative error requiring the caller to lower the threshold first).

### Proof of Concept

```
1. POST /transactions/:id/approvers
   Body: { approversArray: [{ threshold: 3, approvers: [
     { userId: 1 }, { userId: 2 }, { userId: 3 }
   ]}]}
   → parent approver created with threshold=3, children A(userId=1), B(userId=2), C(userId=3)

2. DELETE /transactions/:id/approvers/:childA_id
   → removeNode soft-deletes child A; parent threshold remains 3

3. Users 2 and 3 both call POST /transactions/:id/approvers/:id/approve
   → only 2 approvals recorded; threshold=3 never reached

4. processTransactionStatus never transitions the transaction to WAITING_FOR_EXECUTION

5. Transaction expires in WAITING_FOR_SIGNATURES → operational DoS
``` [8](#0-7)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L204-231)
```typescript
  /* Soft deletes approvers' tree */
  async removeNode(listId: number): Promise<void> {
    if (!listId || typeof listId !== 'number') return null;

    await this.repo.query(
      `
      with recursive approversToDelete AS
        (
          select "id", "listId", "deletedAt"
          from transaction_approver
          where "id" = $1
  
            union all
              select transaction_approver."id", transaction_approver."listId", transaction_approver."deletedAt"
              from transaction_approver, approversToDelete     
              where approversToDelete."id" = transaction_approver."listId"
      
        )
      update transaction_approver
      set "deletedAt" = now()
      from approversToDelete
      where approversToDelete."id" = transaction_approver."listId" or transaction_approver."id" = $1;
    `,
      [listId],
    );

    // notifyTransactionAction(this.notificationsService);
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L302-307)
```typescript
          /* Check if the approver threshold is less or equal to the number of approvers */
          if (
            dtoApprover.approvers &&
            (dtoApprover.threshold > dtoApprover.approvers.length || dtoApprover.threshold === 0)
          )
            throw new Error(this.THRESHOLD_LESS_OR_EQUAL_APPROVERS(dtoApprover.approvers.length));
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L472-477)
```typescript
          /* Check if the approver threshold is less or equal to the number of approvers */
          if (
            approver.approvers &&
            (dto.threshold > approver.approvers.length || dto.threshold === 0)
          )
            throw new Error(this.THRESHOLD_LESS_OR_EQUAL_APPROVERS(approver.approvers.length));
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L546-621)
```typescript
  /* Approves a transaction */
  async approveTransaction(
    dto: ApproverChoiceDto,
    transactionId: number,
    user: User,
  ): Promise<boolean> {
    /* Get all the approvers */
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);

    /* If user is approver, filter the records that belongs to the user */
    const userApprovers = approvers.filter(a => a.userId === user.id);

    /* Check if the user is an approver */
    if (userApprovers.length === 0)
      throw new UnauthorizedException('You are not an approver of this transaction');

    /* Check if the user has already approved the transaction */
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);

    /* Ensures the user keys are passed */
    await attachKeys(user, this.dataSource.manager);
    if (user.keys.length === 0) return false;

    const signatureKey = user.keys.find(key => key.id === dto.userKeyId);

    /* Gets the public key that the signature belongs to */
    const publicKey = PublicKey.fromString(signatureKey?.publicKey);

    /* Get the transaction body */
    const transaction = await this.dataSource.manager.findOne(Transaction, {
      where: { id: transactionId },
      relations: { creatorKey: true, observers: true },
    });

    /* Check if the transaction exists */
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    /* Checks if the transaction is requires approval */
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    /* Verify the signature matches the transaction */
    if (
      !verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTransaction, dto.signature, publicKey)
    )
      throw new BadRequestException(ErrorCodes.SNMP);

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

    const notificationEvent = [{ entityId: transaction.id }];

    if (!dto.approved || userApprovers.every(a => a.approved)) {
      emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
    } else {
      emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
    }

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

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L130-160)
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

    return transactions;
```

**File:** back-end/apps/api/src/transactions/observers/observers.controller.ts (L97-103)
```typescript
  @Delete('/:id')
  removeTransactionObserver(
    @GetUser() user: User,
    @Param('id', ParseIntPipe) id: number,
  ): Promise<boolean> {
    return this.observersService.removeTransactionObserver(id, user);
  }
```
