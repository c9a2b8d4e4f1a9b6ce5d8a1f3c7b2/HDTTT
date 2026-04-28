All technical claims in the report are verified against the actual code. Here is the audit:

---

Audit Report

## Title
Transaction Creator Can Forcibly Assign Any User as Observer Without Consent, With No Victim Self-Removal Path

## Summary
Any authenticated transaction creator can add arbitrary registered users as `Role.FULL` observers on their transaction without the target user's knowledge or consent. The victim immediately receives in-app and email notifications, gains forced visibility into all transaction data, and has no mechanism to remove themselves — only the creator can remove observers.

## Finding Description

**Root cause — no consent check on observer creation:**

`ObserversService.createTransactionObservers` accepts an arbitrary list of `userIds` from the creator and persists them as observers with `Role.FULL` without any check that the target users have agreed to participate.

The only authorization gate (line 44) verifies that the *caller* is the transaction creator. There is no gate on whether the *target* user consents. Every `userId` in `dto.userIds` that is not already an observer is unconditionally persisted: [1](#0-0) 

**Immediate notification side-effect:**

After saving, `emitTransactionUpdate` is called, which triggers the notification pipeline. The victim is immediately notified in-app and, depending on their preferences, by email: [2](#0-1) 

The notification service includes `observerUserIds` in its receiver computation for every subsequent transaction status change (EXECUTED, EXPIRED, CANCELLED, READY\_FOR\_EXECUTION, etc.): [3](#0-2) 

**Victim cannot remove themselves — only the creator can:**

`getUpdateableObserver`, called by both `updateTransactionObserver` and `removeTransactionObserver`, enforces that only the transaction creator may modify or delete an observer record: [4](#0-3) 

**`Role.FULL` gives the victim complete visibility into all transaction data:** [5](#0-4) 

**Exposed API surface:**

The endpoint is authenticated but imposes no restriction beyond "caller is creator": [6](#0-5) 

## Impact Explanation

1. **Forced state change without consent** — any authenticated user can permanently attach any other registered user to their transaction as a `FULL` observer. The victim's account state is mutated without their knowledge.
2. **Persistent notification spam** — the victim receives in-app indicators and email notifications for every status transition of the transaction with no way to opt out.
3. **Forced data exposure** — the victim gains unwanted visibility into the full transaction, including transaction bytes, signers, and approver details (`Role.FULL`).
4. **No self-remediation path** — the victim cannot remove themselves. They are permanently enrolled until the creator chooses to remove them.

## Likelihood Explanation

- **Attacker preconditions:** only a valid JWT (any registered user). No admin or privileged role required.
- **Victim discovery:** user IDs are sequential integers and can be obtained through other API responses (e.g., signer lists on shared transactions).
- **Trigger:** a single authenticated `POST /transactions/{id}/observers` call with the victim's `userId` in the body.
- **Realistic scenario:** a malicious organization member creates a transaction and bulk-adds all other users as observers, flooding them with notifications and exposing sensitive transaction data.

## Recommendation

1. **Add a consent/invitation mechanism:** Instead of immediately persisting the observer record, create a pending invitation that the target user must accept before being enrolled.
2. **Allow self-removal:** Modify `getUpdateableObserver` (or add a separate `removeSelf` path) to permit the observer themselves to call `DELETE /transactions/:transactionId/observers/:id` for their own record.
3. **Validate target user existence before adding:** Confirm the `userId` in `dto.userIds` corresponds to a real, active user in the same organization before persisting.

## Proof of Concept

```
# Attacker (user A, creator of transaction 42) adds victim (user B, id=7) as observer
POST /transactions/42/observers
Authorization: Bearer <attacker_jwt>
Content-Type: application/json

{ "userIds": [7] }

# Response: 201 Created — victim is now a FULL observer
# Victim immediately receives in-app notification
# Victim cannot call DELETE /transactions/42/observers/<observer_id> — returns 401
# Only attacker (creator) can remove the observer record
``` [7](#0-6) [8](#0-7)

### Citations

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L32-69)
```typescript
  async createTransactionObservers(
    user: User,
    transactionId: number,
    dto: CreateTransactionObserversDto,
  ): Promise<TransactionObserver[]> {
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
  }
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L133-141)
```typescript
  async removeTransactionObserver(id: number, user: User): Promise<boolean> {
    const observer = await this.getUpdateableObserver(id, user);

    await this.repo.remove(observer);

    emitTransactionUpdate(this.notificationsPublisher, [{ entityId: observer.transactionId }]);

    return true;
  }
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L144-160)
```typescript
  private async getUpdateableObserver(id: number, user: User): Promise<TransactionObserver> {
    const observer = await this.repo.findOneBy({ id });

    if (!observer) throw new BadRequestException(ErrorCodes.ONF);

    const transaction = await this.entityManager.findOne(Transaction, {
      where: { id: observer.transactionId },
      relations: ['creatorKey', 'creatorKey.user'],
    });

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to update it');

    return observer;
  }
```

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L217-244)
```typescript
    switch (newIndicatorType) {
      case NotificationType.TRANSACTION_APPROVAL_REJECTION:
      case NotificationType.TRANSACTION_INDICATOR_REJECTED:
        return [creatorId, ...approversUserIds, ...observerUserIds];

      case NotificationType.TRANSACTION_APPROVED:
      case NotificationType.TRANSACTION_INDICATOR_APPROVE:
        return approversShouldChooseUserIds;

      case NotificationType.TRANSACTION_WAITING_FOR_SIGNATURES:
      case NotificationType.TRANSACTION_WAITING_FOR_SIGNATURES_REMINDER:
      case NotificationType.TRANSACTION_WAITING_FOR_SIGNATURES_REMINDER_MANUAL:
      case NotificationType.TRANSACTION_INDICATOR_SIGN:
        return requiredUserIds;

      case NotificationType.TRANSACTION_READY_FOR_EXECUTION:
      case NotificationType.TRANSACTION_INDICATOR_EXECUTABLE:
      case NotificationType.TRANSACTION_EXECUTED:
      case NotificationType.TRANSACTION_INDICATOR_EXECUTED:
      case NotificationType.TRANSACTION_INDICATOR_FAILED:
      case NotificationType.TRANSACTION_EXPIRED:
      case NotificationType.TRANSACTION_INDICATOR_EXPIRED:
      case NotificationType.TRANSACTION_INDICATOR_ARCHIVED:
        return [creatorId, ...approversUserIds, ...observerUserIds, ...requiredUserIds];

      case NotificationType.TRANSACTION_CANCELLED:
      case NotificationType.TRANSACTION_INDICATOR_CANCELLED:
        return [...approversUserIds, ...observerUserIds, ...requiredUserIds];
```

**File:** back-end/libs/common/src/database/entities/transaction-observer.entity.ts (L13-17)
```typescript
export enum Role {
  APPROVER = 'APPROVER', // Can only observe the approver interactions
  STATUS = 'STATUS', // Can only observe the status of the transaction
  FULL = 'FULL', // Can observe all information of the transaction
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
