### Title
Wrong NATS Event Emitted in `approveTransaction`: Approval Always Fires `emitTransactionUpdate` Instead of `emitTransactionStatusUpdate`

### Summary
In `approvers.service.ts`, the `approveTransaction` function decides which NATS event to publish based on a stale in-memory check (`userApprovers.every(a => a.approved)`) that is structurally guaranteed to be `false` at the point of evaluation. As a result, every successful approval emits `emitTransactionUpdate` (the lightweight "data refresh" event) instead of `emitTransactionStatusUpdate` (the full notification pipeline event). The rejection path is unaffected. This is a direct analog to the external report's wrong-event-emission class.

### Finding Description

**Root cause — stale in-memory array used after DB write**

`approveTransaction` in `back-end/apps/api/src/transactions/approvers/approvers.service.ts`:

1. Fetches `userApprovers` from the DB (line 553–556). [1](#0-0) 

2. Guards against double-submission: throws if `userApprovers.every(a => a.signature)` (line 563). Because `approved` and `signature` are always written together, this guard guarantees that at least one record in `userApprovers` has `approved: null` at this point. [2](#0-1) 

3. Writes `approved: dto.approved` to the DB for all `userApprovers` records (lines 599–610). The in-memory `userApprovers` array is **never refreshed**. [3](#0-2) 

4. Evaluates the branching condition (line 614):
   ```typescript
   if (!dto.approved || userApprovers.every(a => a.approved)) {
     emitTransactionStatusUpdate(...);   // full pipeline
   } else {
     emitTransactionUpdate(...);         // lightweight ping only
   }
   ``` [4](#0-3) 

**Why `userApprovers.every(a => a.approved)` is structurally always `false` on the approval path:**

- The guard at step 2 ensures at least one record had `approved: null` (no signature) before the write.
- The in-memory array still reflects that pre-write state.
- Therefore `every(a => a.approved)` evaluates against stale `null` values → always `false`.

**Resulting branch evaluation:**

| `dto.approved` | `!dto.approved` | `every(a=>a.approved)` | Condition | Event emitted |
|---|---|---|---|---|
| `true` (approve) | `false` | always `false` | `false` | `emitTransactionUpdate` ← **wrong** |
| `false` (reject) | `true` | always `false` | `true` | `emitTransactionStatusUpdate` ← correct |

**Downstream effect — what each event does:**

`emitTransactionUpdate` → `TRANSACTION_UPDATE` subject → `processTransactionUpdateNotifications`:
- Only computes affected user IDs and sends a WebSocket ping (`TRANSACTION_EVENT_TYPE.UPDATE`) to refresh the client UI.
- Does **not** delete old in-app indicator notifications.
- Does **not** create new in-app indicator notifications.
- Does **not** send email notifications. [5](#0-4) 

`emitTransactionStatusUpdate` → `TRANSACTION_STATUS_UPDATE` subject → `processTransactionStatusUpdateNotifications`:
- Deletes stale in-app indicators, creates new ones, sends email notifications, and sends the WebSocket ping. [6](#0-5) 

The two NATS subjects are distinct constants: [7](#0-6) 

The consumer routes them to entirely different handlers: [8](#0-7) 

### Impact Explanation

Every time any approver approves a transaction:
- In-app notification indicators (`TRANSACTION_INDICATOR_SIGN`, `TRANSACTION_INDICATOR_EXECUTABLE`, etc.) are never updated — old stale indicators remain, new ones are never created.
- Email notifications (`TRANSACTION_WAITING_FOR_SIGNATURES`, `TRANSACTION_READY_FOR_EXECUTION`, etc.) are never dispatched.
- Signers, observers, and the creator receive only a silent UI-refresh WebSocket ping, not the actionable notification they depend on to know the transaction is ready for their next step.

The rejection path correctly fires `emitTransactionStatusUpdate`, so the asymmetry is: approvals are silently under-notified while rejections are correctly notified.

### Likelihood Explanation

This fires on **every** approval call — no special conditions required. Any authenticated approver submitting `dto.approved = true` through the normal API endpoint triggers the wrong event. The bug is deterministic and 100% reproducible.

### Recommendation

Replace the stale in-memory check with a check on the value being written:

```typescript
// Before (buggy — checks pre-write in-memory state, always false on approval path)
if (!dto.approved || userApprovers.every(a => a.approved)) {

// After — emit status update for both approval and rejection; they both
// represent a meaningful state change that the full notification pipeline must handle
emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
```

Or, if partial-approval semantics (multiple approver records per user) genuinely require distinguishing "all records now approved" from "some still pending", re-fetch the records after the write before evaluating the condition.

### Proof of Concept

1. Create a transaction requiring approval (`status = WAITING_FOR_SIGNATURES`).
2. As an approver, call `POST /transactions/:id/approvers/approve` with `{ approved: true, signature: <valid>, userKeyId: <id> }`.
3. Observe that `emitTransactionUpdate` is published to `notifications.queue.transaction.update` (not `notifications.queue.transaction.status-update`).
4. Confirm in the notifications service that `processTransactionUpdateNotifications` runs — only a WebSocket `transactions:action` ping with `eventType: 'update'` is sent.
5. Confirm that no in-app indicator notifications are created or deleted, and no email is dispatched.
6. Repeat with `approved: false` (rejection) — observe that `emitTransactionStatusUpdate` fires correctly and the full pipeline runs.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L553-556)
```typescript
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);

    /* If user is approver, filter the records that belongs to the user */
    const userApprovers = approvers.filter(a => a.userId === user.id);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L562-563)
```typescript
    /* Check if the user has already approved the transaction */
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L614-618)
```typescript
    if (!dto.approved || userApprovers.every(a => a.approved)) {
      emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
    } else {
      emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
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

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L1080-1109)
```typescript
  async processTransactionUpdateNotifications(events: NotificationEventDto[]) {
    const ctx = await this.prepareEventContext(events);
    if (!ctx) return;

    const {
      keyCache,
      transactionMap,
      approversMap,
      affectedUsers,
    } = ctx;

    // Process each event
    for (const { entityId: transactionId } of events) {
      const transaction = transactionMap.get(transactionId);
      if (!transaction) continue;
      const approvers = approversMap.get(transactionId) || [];

      const syncType = this.getInAppNotificationType(transaction.status);

      if (syncType) {
        const receiverIds = await this.getNotificationReceiverIds(this.entityManager, transaction, syncType, approvers, keyCache);
        const groupId = transaction.groupItem?.groupId;
        receiverIds.forEach(id => {
          this.addAffectedUser(affectedUsers, id, transactionId, groupId);
        });
      }
    }

    await this.sendNotifyClients(affectedUsers, TRANSACTION_EVENT_TYPE.UPDATE);
  }
```

**File:** back-end/libs/common/src/constants/eventPatterns.ts (L2-3)
```typescript
export const TRANSACTION_STATUS_UPDATE = 'notifications.queue.transaction.status-update';
export const TRANSACTION_UPDATE = 'notifications.queue.transaction.update';
```

**File:** back-end/apps/notifications/src/receiver/receiver-consumer.service.ts (L39-51)
```typescript
      {
        subject: TRANSACTION_STATUS_UPDATE,
        dtoClass: NotificationEventDto,
        handler: async (data: NotificationEventDto[]) => {
          await this.receiverService.processTransactionStatusUpdateNotifications(data);
        },
      },
      {
        subject: TRANSACTION_UPDATE,
        dtoClass: NotificationEventDto,
        handler: async (data: NotificationEventDto[]) => {
          await this.receiverService.processTransactionUpdateNotifications(data);
        },
```
