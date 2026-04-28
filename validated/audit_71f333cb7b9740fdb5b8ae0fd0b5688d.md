All six code references in the claim were verified against the actual source. Every assertion holds. The vulnerability is in scope per `SECURITY.md` (it is not a best-practice note, not theoretical — the test suite proves the path is reachable, and no excluded category applies).

---

Audit Report

## Title
Approver State Mutations Permitted on Terminal-State Transactions

## Summary
`createTransactionApprovers`, `updateTransactionApprover`, and `removeTransactionApprover` all use `getCreatorsTransaction()` as their sole authorization gate. That function verifies ownership only — it never inspects `TransactionStatus`. A transaction creator can therefore add, modify, or delete approvers on transactions that are already in terminal states (`EXECUTED`, `CANCELED`, `EXPIRED`, `FAILED`, `ARCHIVED`), retroactively corrupting the approval audit trail that the multi-signature workflow depends on.

## Finding Description

**Root cause — `getCreatorsTransaction` has no status guard.**
The function fetches the transaction, asserts `creatorKey.userId === user.id`, and returns. There is no comparison against `TransactionStatus`. [1](#0-0) 

**`createTransactionApprovers` delegates entirely to this gate.**
Line 239 calls `await this.getCreatorsTransaction(transactionId, user)` and then unconditionally proceeds to insert new `TransactionApprover` rows regardless of the transaction's current status. [2](#0-1) 

**The test suite confirms this is reachable on `EXPIRED` transactions.**
The fixture transaction is explicitly set to `status: TransactionStatus.EXPIRED`, and the test asserts that `dataSource.manager.insert` is called and `emitTransactionStatusUpdate` fires — meaning the operation succeeds on a terminal-state transaction. [3](#0-2) 

**`removeTransactionApprover` in the controller uses the same unguarded gate.**
`getCreatorsTransaction` is called on line 108, then `removeTransactionApprover` soft-deletes the approver node on line 109 with no status check between them. [4](#0-3) 

**`updateTransactionApprover` has the same gap.**
The only authorization check inside the transaction block is `getCreatorsTransaction` at line 394, which does not inspect status. [5](#0-4) 

**Contrast with `approveTransaction`, which does guard status correctly.**
The approval action itself explicitly rejects any transaction not in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`, but the structural management of the approver tree has no equivalent guard. [6](#0-5) 

## Impact Explanation

This is a multi-signature transaction management system where the approval tree is the authoritative record of who was required to authorize a transaction. Allowing a creator to mutate that tree after a transaction reaches a terminal state means:

1. **Audit trail erasure**: A creator can call `DELETE /transactions/:id/approvers/:approverId` on an already-executed transaction, removing the record of who was required to sign. This undermines the non-repudiation guarantee of the multi-sig workflow.
2. **Retroactive approval tree rewriting**: A creator can add new approvers or change existing ones on an executed transaction, making the historical record inconsistent with what was actually enforced at execution time.
3. **Spurious notifications**: `emitTransactionStatusUpdate` fires on every successful mutation, sending notifications to users about transactions that are already in terminal states. [7](#0-6) 

## Likelihood Explanation

The attacker precondition is minimal: any authenticated, verified user who created at least one transaction. The exploit path is a standard authenticated API call (`POST /transactions/:id/approvers`, `DELETE /transactions/:id/approvers/:id`, or `PATCH /transactions/:id/approvers/:id`) with a terminal-state transaction ID. No privilege escalation, no leaked secrets, and no race condition is required. The test suite itself demonstrates the path is exercised and passes. [8](#0-7) 

## Recommendation

Add a terminal-state guard inside `getCreatorsTransaction` (or as a dedicated helper called immediately after it) that throws a `BadRequestException` when the transaction's status is one of `EXECUTED`, `CANCELED`, `EXPIRED`, `FAILED`, or `ARCHIVED`. This single fix covers all three mutation paths because they all funnel through `getCreatorsTransaction`.

```typescript
const TERMINAL_STATUSES = [
  TransactionStatus.EXECUTED,
  TransactionStatus.CANCELED,
  TransactionStatus.EXPIRED,
  TransactionStatus.FAILED,
  TransactionStatus.ARCHIVED,
];

// Inside getCreatorsTransaction, after the ownership check:
if (TERMINAL_STATUSES.includes(transaction.status))
  throw new BadRequestException('Cannot modify approvers of a terminal-state transaction');
``` [1](#0-0) 

## Proof of Concept

The existing test suite already demonstrates the exploit path without any modification:

1. The `createTransactionApprovers` describe block sets `status: TransactionStatus.EXPIRED` on the fixture transaction.
2. The test `'should create basic transaction approver'` calls `service.createTransactionApprovers(user, transactionId, dto)` against that expired transaction.
3. The test asserts `expect(dataSource.manager.insert).toHaveBeenCalled()` and `expect(emitTransactionStatusUpdate).toHaveBeenCalled()` — both pass, confirming the insert succeeds on a terminal-state transaction.

For a live exploit, an attacker who is the creator of any transaction that has reached `EXECUTED` status issues:

```
POST /transactions/42/approvers
Authorization: Bearer <creator-jwt>
Content-Type: application/json

{ "approversArray": [{ "userId": 99 }] }
```

The call succeeds, inserting a new `TransactionApprover` row for `userId: 99` on the already-executed transaction, rewriting the historical approval record. [9](#0-8)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L376-395)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L583-589)
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.spec.ts (L332-372)
```typescript
  describe('createTransactionApprovers', () => {
    const transaction = {
      id: 1,
      creatorKey: { userId: user.id },
      status: TransactionStatus.EXPIRED,
      mirrorNetwork: 'testnet',
    };

    beforeEach(() => {
      jest.resetAllMocks();

      dataSource.manager.findOne.mockResolvedValueOnce(transaction);

      mockTransaction();
    });

    it('should create basic transaction approver', async () => {
      const transactionId = 1;
      const dto: CreateTransactionApproversArrayDto = {
        approversArray: [
          {
            userId: 1,
          },
        ],
      };

      approversRepo.count.mockResolvedValueOnce(0);
      dataSource.manager.count.calledWith(User, expect.anything()).mockResolvedValueOnce(1);
      jest.spyOn(service, 'getApproversByTransactionId').mockResolvedValueOnce([]);
      dataSource.manager.findOne.mockResolvedValueOnce(transaction);

      await service.createTransactionApprovers(user, transactionId, dto);

      expect(dataSource.manager.create).toHaveBeenCalledWith(TransactionApprover, {
        userId: 1,
        transactionId: transaction.id,
        threshold: null,
      });
      expect(dataSource.manager.insert).toHaveBeenCalled();
      expect(emitTransactionStatusUpdate).toHaveBeenCalledWith(notificationsPublisher, [{ entityId: transactionId  }]);
    });
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
