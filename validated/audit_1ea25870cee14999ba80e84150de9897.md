### Title
`createTransactionApprovers` Emits Spurious Status-Update Notification on Empty `approversArray` Input

### Summary

`ApproversService.createTransactionApprovers` accepts an empty `approversArray` because `CreateTransactionApproversArrayDto` lacks an `@ArrayMinSize(1)` guard on that field. When the array is empty the inner `for` loop is skipped, no database state changes, yet `emitTransactionStatusUpdate` fires unconditionally. This is the direct analog of the BlockhashRegistry bug: an empty collection bypasses the loop, nothing changes, but a downstream event is emitted as if it did.

### Finding Description

**Root cause — missing array-size guard in the DTO**

`CreateTransactionApproversArrayDto` validates `approversArray` with `@IsArray()` and `@ValidateNested({ each: true })` but has no `@ArrayMinSize(1)`: [1](#0-0) 

An empty array `[]` satisfies both decorators and passes NestJS validation without error.

**Service-level no-op with unconditional event emission**

Inside `createTransactionApprovers`, the loop over `dto.approversArray` is skipped when the array is empty, so no `TransactionApprover` rows are inserted. Immediately after the (now-empty) database transaction block, `emitTransactionStatusUpdate` is called unconditionally: [2](#0-1) 

**Contrast with the correctly-guarded observers path**

`ObserversService.createTransactionObservers` performs the same pattern but correctly returns early and never emits when the effective change set is empty: [3](#0-2) 

**Downstream notification pipeline**

`emitTransactionStatusUpdate` publishes to the `TRANSACTION_STATUS_UPDATE` NATS subject: [4](#0-3) 

The notifications service consumes this subject and fans out in-app and email notifications to every observer, signer, and approver of the transaction: [5](#0-4) 

### Impact Explanation

A transaction creator can repeatedly `POST /transactions/:id/approvers` with `{"approversArray":[]}`. Each call:

1. Passes DTO validation.
2. Executes a database transaction that does nothing.
3. Publishes a `TRANSACTION_STATUS_UPDATE` NATS event.
4. Causes the notification service to delete existing notification indicators, recreate them, and dispatch in-app and email notifications to every user associated with the transaction.

This is a notification-spam / DoS vector against all observers, signers, and approvers of any transaction the attacker created. At scale it can exhaust NATS throughput, flood user inboxes, and degrade the notification service.

### Likelihood Explanation

The attacker only needs to be a registered, verified user who has created at least one transaction — the normal baseline for any organization member. No elevated privileges are required. The endpoint is reachable over standard HTTPS. The empty-array payload is trivial to craft and can be sent in a tight loop.

### Recommendation

1. Add `@ArrayMinSize(1)` to `approversArray` in `CreateTransactionApproversArrayDto`, mirroring the guard already present on the nested `approvers` field:

```typescript
export class CreateTransactionApproversArrayDto {
  @IsArray()
  @ArrayMinSize(1)          // ← add this
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionApproverDto)
  approversArray: CreateTransactionApproverDto[];
}
``` [1](#0-0) 

2. As a defence-in-depth measure, move `emitTransactionStatusUpdate` inside a guard that checks `approvers.length > 0` before emitting, matching the pattern used in `ObserversService`: [3](#0-2) 

### Proof of Concept

```
POST /transactions/42/approvers
Authorization: Bearer <valid-jwt-of-transaction-creator>
Content-Type: application/json

{"approversArray":[]}
```

**Expected (correct) behaviour:** HTTP 400 — array must contain at least one item.

**Actual behaviour:** HTTP 201 — no approvers are created, but `TRANSACTION_STATUS_UPDATE` is published to NATS, triggering email and in-app notifications to every user associated with transaction 42. Repeating this request in a loop spams all associated users and loads the notification pipeline with no legitimate state change.

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts (L25-29)
```typescript
export class CreateTransactionApproversArrayDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionApproverDto)
  approversArray: CreateTransactionApproverDto[];
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L353-358)
```typescript
        for (const approver of dto.approversArray) {
          await createApprover(approver);
        }
      });

      emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transactionId  }]);
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L56-63)
```typescript
    if (observers.length === 0) {
      return [];
    }

    try {
      const result = await this.repo.save(observers);

      emitTransactionUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);
```

**File:** back-end/libs/common/src/utils/client/index.ts (L24-30)
```typescript
export const emitTransactionStatusUpdate = async (
  publisher: NatsPublisherService,
  dtos: NotificationEventDto[],
) => {
  const result = await publisher.publish(TRANSACTION_STATUS_UPDATE, dtos);
  if (!result?.success) logPublishFailure(TRANSACTION_STATUS_UPDATE, result?.response);
};
```

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L1016-1077)
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
```
