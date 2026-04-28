Audit Report

## Title
`createTransactionApprovers` Emits Spurious Status-Update Notification on Empty `approversArray` Input

## Summary
`ApproversService.createTransactionApprovers` accepts an empty `approversArray` because `CreateTransactionApproversArrayDto` lacks an `@ArrayMinSize(1)` guard. When the array is empty, the inner loop is skipped, no database state changes, yet `emitTransactionStatusUpdate` fires unconditionally. This allows any transaction creator to spam NATS status-update events and trigger downstream notification fan-out with zero actual state change.

## Finding Description

**Root cause — missing array-size guard in the DTO**

`CreateTransactionApproversArrayDto` validates `approversArray` with only `@IsArray()` and `@ValidateNested({ each: true })`, with no `@ArrayMinSize(1)`: [1](#0-0) 

An empty array `[]` satisfies both decorators and passes NestJS validation without error. Note that the nested `CreateTransactionApproverDto.approvers` field *does* carry `@ArrayMinSize(1)` (line 18), so the inner DTO is correctly guarded — only the outer wrapper is not. [2](#0-1) 

**Service-level no-op with unconditional event emission**

Inside `createTransactionApprovers`, the for-loop over `dto.approversArray` is skipped entirely when the array is empty, so no `TransactionApprover` rows are inserted. Immediately after the (now-empty) database transaction block, `emitTransactionStatusUpdate` is called unconditionally: [3](#0-2) 

**Contrast with the correctly-guarded observers path**

`ObserversService.createTransactionObservers` performs the same pattern but correctly returns early and never emits when the effective change set is empty: [4](#0-3) 

**Downstream notification pipeline**

`emitTransactionStatusUpdate` publishes to the `TRANSACTION_STATUS_UPDATE` NATS subject: [5](#0-4) 

The notifications service consumes this subject and, for each event, deletes existing notification indicators and recreates them, dispatching in-app and email notifications to every observer, signer, and approver of the transaction: [6](#0-5) 

## Impact Explanation
A transaction creator can repeatedly `POST /transactions/:id/approvers` with `{"approversArray":[]}`. Each call:
1. Passes DTO validation.
2. Executes a database transaction that does nothing.
3. Publishes a `TRANSACTION_STATUS_UPDATE` NATS event.
4. Causes the notification service to delete existing notification indicators, recreate them, and dispatch in-app and email notifications to every user associated with the transaction.

This is a notification-spam / DoS vector against all observers, signers, and approvers of any transaction the attacker created. At scale it can exhaust NATS throughput, flood user inboxes, and degrade the notification service.

## Likelihood Explanation
The attacker only needs to be a registered, verified user who has created at least one transaction — the normal baseline for any organization member. No elevated privileges are required. The endpoint is reachable over standard HTTPS via `POST /transactions/:id/approvers`. The empty-array payload is trivial to craft and can be sent in a tight loop.

## Recommendation
Apply `@ArrayMinSize(1)` to the `approversArray` field in `CreateTransactionApproversArrayDto`, mirroring the guard already present on the nested `approvers` field:

```typescript
// back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts
export class CreateTransactionApproversArrayDto {
  @IsArray()
  @ArrayMinSize(1)                      // add this
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionApproverDto)
  approversArray: CreateTransactionApproverDto[];
}
```

As a defense-in-depth measure, also add a service-level guard analogous to the one in `ObserversService.createTransactionObservers` — return early (or skip the emit) when `dto.approversArray` is empty, so that a missing DTO guard cannot cause spurious events.

## Proof of Concept
```http
POST /transactions/1/approvers HTTP/1.1
Authorization: Bearer <valid_creator_token>
Content-Type: application/json

{"approversArray":[]}
```

Expected (correct) behavior: `400 Bad Request` — array must contain at least one element.

Actual behavior: `201 Created`, empty response body, and a `TRANSACTION_STATUS_UPDATE` NATS event is published, triggering full notification fan-out to all users associated with transaction `1`. Repeating this request in a loop produces unbounded notification spam with no rate limiting at the DTO or service layer.

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts (L17-22)
```typescript
  @IsArray()
  @ArrayMinSize(1)
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionApproverDto)
  approvers?: CreateTransactionApproverDto[];
```

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

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L763-789)
```typescript
      if (syncType) {
        const deletedReceiverIds = await this.deleteExistingIndicators(entityManager, transaction);

        deletedReceiverIds.forEach(({ userId, receiverId }) => {
          if (!deletionNotifications[userId]) {
            deletionNotifications[userId] = [];
          }
          deletionNotifications[userId].push(receiverId);
          this.addAffectedUser(affectedUsers, userId, transactionId, groupId);
        });

        const newReceivers = await this.createNotificationWithReceivers(
          entityManager,
          transaction,
          approvers,
          syncType,
          additionalData,
          cache,
          keyCache,
        );

        newReceivers.forEach(nr => {
          if (!inAppNotifications[nr.userId]) inAppNotifications[nr.userId] = [];
          inAppNotifications[nr.userId].push(nr);
          inAppReceiverIds.push(nr.id);
          this.addAffectedUser(affectedUsers, nr.userId, transactionId, groupId);
        });
```
