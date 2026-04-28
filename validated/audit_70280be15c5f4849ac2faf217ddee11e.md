Audit Report

## Title
Approvers and Observers Can Be Added to Terminal-State Transactions Without Status Validation

## Summary
`createTransactionApprovers` and `createTransactionObservers` perform no check on the transaction's current status before mutating the database. A transaction creator can add approvers or observers to a transaction already in a terminal state (`CANCELED`, `EXECUTED`, `FAILED`, `EXPIRED`, `ARCHIVED`, `REJECTED`), corrupting the approver/observer history and triggering spurious downstream notification events.

## Finding Description

**Root cause — `getCreatorsTransaction` has no status guard**

`createTransactionApprovers` delegates its entire authorization check to `getCreatorsTransaction`: [1](#0-0) 

`getCreatorsTransaction` only verifies existence and creator identity; it never reads or validates `transaction.status`: [2](#0-1) 

After inserting the approvers, `emitTransactionStatusUpdate` is unconditionally fired for the (potentially already-finished) transaction: [3](#0-2) 

The same pattern exists in `createTransactionObservers`: creator identity is checked but transaction status is never validated before persisting new observer records, and `emitTransactionUpdate` is then fired unconditionally: [4](#0-3) 

**The test suite itself confirms the bug**

The unit tests for `createTransactionApprovers` set the mock transaction to `TransactionStatus.EXPIRED` and assert that approver creation *succeeds* — there is no test that expects a rejection for terminal-state transactions: [5](#0-4) 

**Contrast with correct guards elsewhere**

`approveTransaction` explicitly rejects non-active statuses before writing: [6](#0-5) 

`cancelTransactionWithOutcome` and `archiveTransaction` in `transactions.service.ts` both gate on `cancelableStatuses` / active statuses before writing: [7](#0-6) [8](#0-7) [9](#0-8) 

The `terminalStatuses` array that should block further mutation is already defined in `TransactionsService` but is never consulted by the approver or observer services: [10](#0-9) 

The `TransactionStatus` enum defines all terminal states: [11](#0-10) 

## Impact Explanation

- **Database state corruption**: `TransactionApprover` and `TransactionObserver` rows are permanently written for transactions that have already concluded. `cancelTransaction` only sets the status field and does not purge related approver/observer records, so there is no cleanup path.
- **Spurious downstream events**: `emitTransactionStatusUpdate` (for approvers) and `emitTransactionUpdate` (for observers) are published for finished transactions, causing the notifications service (`ReceiverService.processTransactionStatusUpdateNotifications`) to process events that should never occur, potentially producing incorrect in-app notifications or UI state for all participants. [12](#0-11) 
- **Audit-trail integrity**: The approver/observer history for a finished transaction becomes unreliable, undermining the trust model of the multi-signature coordination workflow.

## Likelihood Explanation

The attacker precondition is simply being the creator of any transaction — a normal, unprivileged product role. No special keys, credentials, or internal access are required. The trigger is a standard authenticated API call to `POST /transactions/:id/approvers` or `POST /transactions/:id/observers`. The scenario can occur by mistake (creator adds an approver after canceling) or deliberately. [13](#0-12) [14](#0-13) 

## Recommendation

Add a terminal-status guard immediately after the creator check in both `createTransactionApprovers` and `createTransactionObservers`. The `terminalStatuses` list already exists in `TransactionsService`; the same set should be enforced in the approver and observer services:

In `approvers.service.ts`, after line 239 (`await this.getCreatorsTransaction(...)`), add:
```typescript
if (terminalStatuses.includes(transaction.status)) {
  throw new BadRequestException('Cannot modify approvers of a transaction in a terminal state');
}
```

Apply the same guard in `observers.service.ts` after the creator-identity check (line 44–45), using the same terminal-status set (`EXECUTED`, `EXPIRED`, `FAILED`, `CANCELED`, `ARCHIVED`, `REJECTED`).

## Proof of Concept

1. Creator submits a transaction; it reaches `CANCELED` (or `EXECUTED`, `FAILED`, etc.).
2. Creator calls `POST /transactions/:id/approvers` with a valid `CreateTransactionApproversArrayDto`.
3. `createTransactionApprovers` calls `getCreatorsTransaction` — passes, because the user is the creator and the transaction exists.
4. No status check occurs; new `TransactionApprover` rows are inserted into the database for the finished transaction.
5. `emitTransactionStatusUpdate` fires, causing the notification service to process a status-change event for a transaction already in a terminal state.
6. The same flow applies to `POST /transactions/:id/observers` via `createTransactionObservers`.

The existing unit test suite confirms this: the `createTransactionApprovers` test fixture explicitly uses `TransactionStatus.EXPIRED` and asserts successful insertion with no rejection. [5](#0-4)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L356-359)
```typescript
      });

      emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transactionId  }]);
    } catch (error) {
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

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L37-68)
```typescript
    const transaction = await this.entityManager.findOne(Transaction, {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user', 'observers'],
    });

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to delete it');

    const observers: TransactionObserver[] = [];

    for (const userId of dto.userIds) {
      if (!transaction.observers.some(o => o.userId === userId)) {
        const observer = this.repo.create({ userId, transactionId, role: Role.FULL });
        observers.push(observer);
      }
    }

    if (observers.length === 0) {
      return [];
    }

    try {
      const result = await this.repo.save(observers);

      emitTransactionUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);

      return result;
    } catch (error) {
      throw new BadRequestException(error.message);
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L92-105)
```typescript
  private readonly cancelableStatuses = [
    TransactionStatus.NEW,
    TransactionStatus.WAITING_FOR_SIGNATURES,
    TransactionStatus.WAITING_FOR_EXECUTION,
  ];

  private readonly terminalStatuses = [
    TransactionStatus.EXECUTED,
    TransactionStatus.EXPIRED,
    TransactionStatus.FAILED,
    TransactionStatus.CANCELED,
    TransactionStatus.ARCHIVED,
    TransactionStatus.REJECTED,
  ];
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L659-671)
```typescript
  async cancelTransactionWithOutcome(
    id: number,
    user: User,
  ): Promise<CancelTransactionOutcome> {
    const transaction = await this.getTransactionForCreator(id, user);

    if (transaction.status === TransactionStatus.CANCELED) {
      return CancelTransactionOutcome.ALREADY_CANCELED;
    }

    if (!this.cancelableStatuses.includes(transaction.status)) {
      throw new BadRequestException(ErrorCodes.OTIP);
    }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L708-718)
```typescript
  async archiveTransaction(id: number, user: User): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);

    if (
      ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
        transaction.status,
      ) &&
      !transaction.isManual
    ) {
      throw new BadRequestException(ErrorCodes.OMTIP);
    }
```

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L46-56)
```typescript
export enum TransactionStatus {
  NEW = 'NEW', // unused
  CANCELED = 'CANCELED',
  REJECTED = 'REJECTED',
  WAITING_FOR_SIGNATURES = 'WAITING FOR SIGNATURES',
  WAITING_FOR_EXECUTION = 'WAITING FOR EXECUTION',
  EXECUTED = 'EXECUTED',
  FAILED = 'FAILED',
  EXPIRED = 'EXPIRED',
  ARCHIVED = 'ARCHIVED',
}
```

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L1016-1078)
```typescript
  async processTransactionStatusUpdateNotifications(events: NotificationEventDto[]) {
    const ctx = await this.prepareEventContext(events, true);
    if (!ctx) return;

    const {
      cache,
      keyCache,
      transactionMap,
      approversMap,
      deletionNotifications,
      inAppNotifications,
      emailNotifications,
      inAppReceiverIds,
      emailReceiverIds,
      affectedUsers,
    } = ctx;

    // Process each event
    for (const { entityId: transactionId } of events) {
      const transaction = transactionMap.get(transactionId);
      if (!transaction) {
        console.warn(`Transaction ${transactionId} not found, skipping status-update notifications`);
        continue;
      }
      const approvers = approversMap.get(transactionId) || [];

      if (transaction.deletedAt && transaction.status !== TransactionStatus.CANCELED) {
        console.error(
          `Soft-deleted transaction ${transactionId} has unexpected status: ${transaction.status} (expected CANCELED)`
        );
        transaction.status = TransactionStatus.CANCELED;
      }

      const syncType = this.getInAppNotificationType(transaction.status);
      const emailType = this.getEmailNotificationType(transaction.status);

      // Single transaction for both notification types
      await this.entityManager.transaction(async entityManager => {
        await this.handleTransactionStatusUpdateNotifications(
          entityManager,
          transaction,
          approvers,
          syncType,
          emailType,
          cache,
          keyCache,
          deletionNotifications,
          inAppNotifications,
          inAppReceiverIds,
          emailNotifications,
          emailReceiverIds,
          affectedUsers,
          transactionId,
        );
      });
    }

    // Send all notifications in batch
    await this.sendDeletionNotifications(deletionNotifications);
    await this.sendInAppNotifications(inAppNotifications, inAppReceiverIds);
    await this.sendEmailNotifications(emailNotifications, emailReceiverIds);
    await this.sendNotifyClients(affectedUsers, TRANSACTION_EVENT_TYPE.STATUS_UPDATE);
  }
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

**File:** back-end/apps/api/src/transactions/observers/observers.controller.ts (L43-50)
```typescript
  @Post()
  createTransactionObserver(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() body: CreateTransactionObserversDto,
  ): Promise<TransactionObserver[]> {
    return this.observersService.createTransactionObservers(user, transactionId, body);
  }
```
