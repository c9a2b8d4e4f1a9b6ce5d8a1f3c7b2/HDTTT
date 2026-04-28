### Title
Debounce Starvation in `DebouncedNotificationBatcher` Causes Silent Notification Message Loss

### Summary
The `DebouncedNotificationBatcher.add()` method continuously renews the `flushKey` TTL on every incoming message, preventing the debounce flush from firing. When the `batchKey` (which holds the actual messages) expires after `maxFlushMS`, the keyevent-triggered `flush()` call finds an empty Redis list and silently discards all accumulated notifications. An attacker who can continuously trigger transaction status updates can exploit this to permanently suppress notifications for targeted users.

### Finding Description
In `DebouncedNotificationBatcher.add()`, two Redis keys govern flushing:

- `batchKey` — a Redis list holding the queued messages. Its TTL is set to `maxFlushMS` **only when the first message is added** (line 70–72). It is never renewed.
- `flushKey` — a sentinel key whose expiry triggers the actual flush via a keyevent subscription. Its TTL is reset to `delayMs` on **every** subsequent `add()` call (line 83). [1](#0-0) 

The intended design is:
1. `flushKey` expires after `delayMs` of inactivity → flush fires, `batchKey` still alive → messages retrieved and delivered.
2. `batchKey` expires after `maxFlushMS` as a hard deadline → flush fires as a safety net.

The flaw is in step 2. When `batchKey` expires, the keyevent fires and `processExpiration` → `flush()` is called: [2](#0-1) 

Inside `flush()`, `lrange(batchKey, 0, -1)` is called on the **already-expired** key. Redis returns an empty list. The early-return guard at line 102–104 silently exits, and all accumulated messages are permanently lost with no error, no retry, and no log. [3](#0-2) 

The `maxBatchSize` guard (line 75–78) only protects against a single burst exceeding the batch limit; it does not protect against a sustained low-rate stream that keeps `flushKey` alive past `maxFlushMS`. [4](#0-3) 

### Impact Explanation
Notification messages queued in the batcher are silently dropped. The `ReceiverService` emits notifications for every transaction status transition (WAITING\_FOR\_SIGNATURES, WAITING\_FOR\_EXECUTION, EXECUTED, FAILED, EXPIRED, CANCELLED). [5](#0-4) 

Dropped notifications mean users never receive in-app or email alerts about transactions they are required to sign or approve. In an organization multi-signature workflow, this can stall transactions past their `validStart` window, causing them to expire without execution.

### Likelihood Explanation
Any authenticated user can create transactions in the system. The notification pipeline is triggered automatically by the `TransactionSchedulerService` cron jobs (running as frequently as every 10 seconds) and by the `ExecuteService`. [6](#0-5) 

An attacker creates a stream of transactions whose status transitions (e.g., NEW → WAITING\_FOR\_SIGNATURES → EXPIRED) fire at a rate faster than `delayMs` but below `maxBatchSize` per window. This keeps `flushKey` perpetually renewed. After `maxFlushMS` elapses, `batchKey` expires and all queued notifications for the targeted group key are dropped. The attacker repeats this to suppress notifications indefinitely.

### Recommendation
Do not rely on `batchKey` TTL expiry as a flush trigger. The `batchKey` should have **no TTL** (or a very long one), and the hard deadline should be implemented as a separate in-process timer that calls `flush()` directly before the data is gone. Alternatively, use a Redis `GETDEL` or `LMPOP` pattern so that the flush atomically retrieves and removes messages in a single operation, decoupled from key expiry.

### Proof of Concept

1. Attacker registers as an organization user and creates 500 transactions with `validStart` set 3 minutes in the future, all requiring the victim's signature.
2. The scheduler's `handleTransactionsBetweenNowAndAfterThreeMinutes` cron (every 10 s) fires, calling `processTransactionStatus` for all 500 transactions and emitting 500 `TRANSACTION_STATUS_UPDATE` NATS events.
3. `ReceiverService.processTransactionStatusUpdateNotifications` processes these events and calls `DebouncedNotificationBatcher.add()` 500 times in rapid succession for the victim's `groupKey`.
4. Each `add()` call renews `flushKey` TTL to `delayMs`. The flush never fires during the burst.
5. After `maxFlushMS` ms, `batchKey` expires. The keyevent fires, `flush()` is called, `lrange` returns `[]`, and all 500 notification messages are silently discarded.
6. The victim receives zero in-app or email notifications and does not sign the transactions, which expire. [7](#0-6) [6](#0-5)

### Citations

**File:** back-end/apps/notifications/src/utils/DebouncedNotificationBatcher.ts (L63-87)
```typescript
  async add(message: T, groupKey: string | number | null = null): Promise<void> {
    const groupKeyStr = groupKey === null ? this.GLOBAL_KEY : String(groupKey);
    const batchKey = `${this.batchKeyPrefix}${groupKeyStr}`;
    const flushKey = `${this.flushKeyPrefix}${groupKeyStr}`;

    // Add message to Redis list and set TTL for max flush delay
    const length = await this.pubClient.rpush(batchKey, JSON.stringify(message));
    if (length === 1) {
      await this.pubClient.pexpire(batchKey, this.maxFlushMS);
    }

    // If batch size reached, flush immediately, removing the flush key in the process
    if (length >= this.maxBatchSize) {
      await this.flush(groupKey);
      return;
    }

    // If flush key exists, renew expiration; otherwise, set it to trigger flush via keyevent
    const isFlushScheduled = await this.pubClient.get(flushKey);
    if (isFlushScheduled) {
      await this.pubClient.pexpire(flushKey, this.delayMs);
    } else {
      await this.pubClient.set(flushKey, '1', 'PX', this.delayMs);
    }
  }
```

**File:** back-end/apps/notifications/src/utils/DebouncedNotificationBatcher.ts (L95-113)
```typescript
  async flush(groupKey: string | number | null): Promise<void> {
    const groupKeyStr = groupKey === null ? this.GLOBAL_KEY : String(groupKey);
    const batchKey = `${this.batchKeyPrefix}${groupKeyStr}`;
    const flushKey = `${this.flushKeyPrefix}${groupKeyStr}`;

    // Retrieve all messages for the group
    const messages = await this.pubClient.lrange(batchKey, 0, -1);
    if (!messages || messages.length === 0) {
      return;
    }

    // Clear both the batch and flush keys
    await this.pubClient.del(batchKey);
    await this.pubClient.del(flushKey);

    // Parse messages and call the flush callback
    const parsedMessages = messages.map((msg) => JSON.parse(msg));
    await this.flushCallback(groupKey, parsedMessages);
  }
```

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L36-56)
```typescript
  // Mapping from transaction status to the in-app indicator notification type
  private static readonly IN_APP_NOTIFICATION_TYPES: Partial<Record<TransactionStatus, NotificationType>> = {
    [TransactionStatus.WAITING_FOR_SIGNATURES]: NotificationType.TRANSACTION_INDICATOR_SIGN,
    [TransactionStatus.WAITING_FOR_EXECUTION]: NotificationType.TRANSACTION_INDICATOR_EXECUTABLE,
    [TransactionStatus.EXECUTED]: NotificationType.TRANSACTION_INDICATOR_EXECUTED,
    [TransactionStatus.FAILED]: NotificationType.TRANSACTION_INDICATOR_FAILED,
    [TransactionStatus.EXPIRED]: NotificationType.TRANSACTION_INDICATOR_EXPIRED,
    [TransactionStatus.CANCELED]: NotificationType.TRANSACTION_INDICATOR_CANCELLED,
    [TransactionStatus.ARCHIVED]: NotificationType.TRANSACTION_INDICATOR_ARCHIVED,
  };

  // Mapping from transaction status to the email notification type
  private static readonly EMAIL_NOTIFICATION_TYPES: Partial<Record<TransactionStatus, NotificationType>> = {
    [TransactionStatus.WAITING_FOR_SIGNATURES]: NotificationType.TRANSACTION_WAITING_FOR_SIGNATURES,
    [TransactionStatus.WAITING_FOR_EXECUTION]: NotificationType.TRANSACTION_READY_FOR_EXECUTION,
    [TransactionStatus.EXECUTED]: NotificationType.TRANSACTION_EXECUTED,
    // [TransactionStatus.FAILED]: NotificationType.TRANSACTION_EXECUTED,
    // [TransactionStatus.REJECTED]: NotificationType.TRANSACTION_EXECUTED,
    [TransactionStatus.EXPIRED]: NotificationType.TRANSACTION_EXPIRED,
    [TransactionStatus.CANCELED]: NotificationType.TRANSACTION_CANCELLED,
  };
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L87-97)
```typescript
  @Cron(CronExpression.EVERY_10_SECONDS, {
    name: 'status_update_between_now_and_three_minutes',
  })
  async handleTransactionsBetweenNowAndAfterThreeMinutes() {
    const transactions = await this.updateTransactions(
      this.getThreeMinutesBefore(),
      this.getThreeMinutesLater(),
    );

    await this.prepareTransactions(transactions);
  }
```
