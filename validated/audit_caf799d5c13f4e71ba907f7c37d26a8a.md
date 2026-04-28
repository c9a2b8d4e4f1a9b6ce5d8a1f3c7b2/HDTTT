### Title
Duplicate `userIds` in `createTransactionObservers` bypass in-loop deduplication, enabling duplicate observer records or denial of observer creation

### Summary
`ObserversService.createTransactionObservers` checks for duplicate observers only against the database-loaded `transaction.observers` snapshot, not against the local accumulator being built within the same call. When a caller submits a `userIds` array containing the same user ID more than once (e.g., `[5, 5]`), both entries pass the guard and two `TransactionObserver` records for the same user are queued for insertion. This is the same vulnerability class as the external report: an array setter that lacks intra-array duplicate detection.

### Finding Description

**Root cause — `observers.service.ts` lines 49–54:**

```typescript
for (const userId of dto.userIds) {
  if (!transaction.observers.some(o => o.userId === userId)) {
    const observer = this.repo.create({ userId, transactionId, role: Role.FULL });
    observers.push(observer);
  }
}
```

`transaction.observers` is the DB snapshot loaded once at line 37–40. The guard on line 50 is evaluated against that static snapshot on every iteration. The local `observers` accumulator is never consulted. Therefore, if `dto.userIds = [5, 5]` and user 5 is not yet an observer, both iterations pass the guard and two identical `TransactionObserver` objects are pushed into `observers`.

**DTO — `create-transaction-observers.dto.ts` lines 1–7:**

```typescript
export class CreateTransactionObserversDto {
  @IsArray()
  @IsNumber({}, { each: true })
  @ArrayMinSize(1)
  userIds: number[];
}
```

No `@ArrayUnique()` or equivalent decorator is present. The DTO accepts `[5, 5]` as valid input.

**Persistence — line 61:**

```typescript
const result = await this.repo.save(observers);
```

TypeORM's `save()` is called with the duplicate-containing array. Two outcomes are possible:

1. **No unique DB constraint on `(transactionId, userId)`**: both records are inserted, creating duplicate `TransactionObserver` rows. Downstream code that maps `transaction.observers` to user IDs (e.g., `transaction.observers.map(o => o.userId)` in `receiver.service.ts` line 141) will return `[5, 5]`, producing duplicate entries in notification recipient arrays before the `new Set()` dedup at line 342 of `receiver.service.ts` can collapse them. Any code path that does not apply `Set` dedup (e.g., raw `observerUserIds` spread at lines 220, 240, 244 of `receiver.service.ts`) will send duplicate notifications.

2. **Unique DB constraint exists**: `repo.save()` throws, caught at line 66 and re-thrown as `BadRequestException`. The entire batch fails — including any legitimately new, non-duplicate user IDs in the same call. A transaction creator who accidentally or intentionally includes a duplicate cannot add any observers in that request. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation

**Path A (no unique constraint):** Duplicate `TransactionObserver` rows are persisted. The notification receiver pipeline in `receiver.service.ts` spreads `observerUserIds` directly into recipient arrays (lines 220, 240, 244) without deduplication at that stage. A user with two observer records receives two notification receiver entries, causing duplicate in-app and email notifications for every subsequent transaction event. This is a state-integrity and notification-spam impact.

**Path B (unique constraint):** Any call containing a duplicate `userId` fails entirely with HTTP 400, silently dropping all legitimate additions in the same request. A malicious transaction creator can exploit this to prevent observers from being added in a single call (though they can retry without duplicates). [4](#0-3) [5](#0-4) 

### Likelihood Explanation

The entry point is `POST /transactions/:transactionId/observers`, reachable by any authenticated, verified user who is the creator of a transaction. No privileged system role is required. The attacker-controlled input is the `userIds` JSON array in the request body. Sending `{"userIds": [5, 5]}` is trivially constructed. The likelihood is low for accidental occurrence but straightforward for intentional exploitation. [6](#0-5) 

### Recommendation

Deduplicate `dto.userIds` before the loop, or check the local accumulator in addition to the DB snapshot:

```typescript
// Option 1: deduplicate input at entry
const uniqueUserIds = [...new Set(dto.userIds)];

for (const userId of uniqueUserIds) {
  if (!transaction.observers.some(o => o.userId === userId)) {
    ...
  }
}
```

Alternatively, add `@ArrayUnique()` from `class-validator` to `CreateTransactionObserversDto.userIds` to reject duplicate-containing requests at the validation layer before they reach the service. [2](#0-1) 

### Proof of Concept

**Preconditions:** Attacker is authenticated as the creator of transaction ID `42`. User ID `7` is not yet an observer.

**Request:**
```http
POST /transactions/42/observers
Authorization: Bearer <creator_jwt>
Content-Type: application/json

{"userIds": [7, 7]}
```

**Expected (correct) behavior:** One `TransactionObserver` record created for user 7.

**Actual behavior (no unique constraint):** Two `TransactionObserver` records created for user 7 on transaction 42. Subsequent notification events for transaction 42 will produce two `NotificationReceiver` rows for user 7 (one per observer record), resulting in duplicate notifications.

**Actual behavior (unique constraint):** HTTP 400 returned; zero observer records created, including for any valid non-duplicate user IDs that may have been included in the same call. [7](#0-6) [8](#0-7)

### Citations

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L47-54)
```typescript
    const observers: TransactionObserver[] = [];

    for (const userId of dto.userIds) {
      if (!transaction.observers.some(o => o.userId === userId)) {
        const observer = this.repo.create({ userId, transactionId, role: Role.FULL });
        observers.push(observer);
      }
    }
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L60-68)
```typescript
    try {
      const result = await this.repo.save(observers);

      emitTransactionUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);

      return result;
    } catch (error) {
      throw new BadRequestException(error.message);
    }
```

**File:** back-end/apps/api/src/transactions/dto/create-transaction-observers.dto.ts (L1-7)
```typescript
import { ArrayMinSize, IsArray, IsNumber } from 'class-validator';

export class CreateTransactionObserversDto {
  @IsArray()
  @IsNumber({}, { each: true })
  @ArrayMinSize(1)
  userIds: number[];
```

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L140-167)
```typescript
    const signerUserIds = transaction.signers.map(s => s.userId);
    const observerUserIds = transaction.observers.map(o => o.userId);
    const requiredUserIds = await this.getUsersIdsRequiredToSign(entityManager, transaction, keyCache);

    const approversUserIds = approvers.map(a => a.userId);
    const approversGaveChoiceUserIds = approvers
      .filter(a => a.approved !== null)
      .map(a => a.userId)
      .filter(Boolean);
    const approversShouldChooseUserIds = [
      TransactionStatus.WAITING_FOR_EXECUTION,
      TransactionStatus.WAITING_FOR_SIGNATURES,
    ].includes(transaction.status)
      ? approvers
        .filter(a => a.approved === null)
        .map(a => a.userId)
        .filter(Boolean)
      : [];

    const participants = [
      ...new Set([
        creatorId,
        ...signerUserIds,
        ...observerUserIds,
        ...approversUserIds,
        ...requiredUserIds,
      ].filter(Boolean)),
    ];
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

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L298-318)
```typescript
  private async createNotificationReceivers(
    entityManager: EntityManager,
    notification: Notification,
    newReceiverIds: number[],
  ) {
    if (newReceiverIds.length === 0) return [];

    const type = NOTIFICATION_CHANNELS[notification.type];

    return entityManager.save(
      NotificationReceiver,
      newReceiverIds.map(userId => ({
        notificationId: notification.id,
        userId,
        isRead: false,
        isInAppNotified: type.inApp ? false : null,
        isEmailSent: type.email ? false : null,
        notification,
      })),
    );
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
