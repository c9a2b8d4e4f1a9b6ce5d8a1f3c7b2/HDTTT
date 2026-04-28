### Title
Permanent Notification Message Loss in `DebouncedNotificationBatcher.flush()` Due to Non-Atomic Delete-Before-Callback Pattern

### Summary
`DebouncedNotificationBatcher.flush()` deletes all batched messages from Redis **before** invoking the `flushCallback`. If the callback throws (or the process crashes between deletion and callback completion), the messages are permanently lost with no recovery path. Additionally, the Redis pub/sub `on('message')` handler that drives the flush is async with no error handling, meaning any exception in `processExpiration` becomes a silently swallowed unhandled promise rejection, leaving the lock unreleased and the batch unprocessed.

### Finding Description

**Root cause — non-atomic delete-then-callback in `flush()`:**

In `DebouncedNotificationBatcher.flush()`, the batch data is retrieved from Redis, then **both** the batch key and flush key are deleted, and only **after** deletion is the callback invoked: [1](#0-0) 

```
lrange  → del(batchKey) → del(flushKey) → flushCallback(...)
```

If `flushCallback` throws at line 112, the messages are already gone from Redis. There is no re-queue, no dead-letter store, and no retry.

**Root cause — no error handling in the `on('message')` async handler:**

The Redis keyspace-notification subscriber registers an async callback with no try/catch: [2](#0-1) 

If `processExpiration` throws (e.g., Redis connection error during the `SET NX` lock acquisition at line 48), the error becomes an unhandled promise rejection. The subscription itself continues, but:
- The specific batch is never flushed.
- The lock is never released (line 51 is never reached), blocking concurrent flushes for the lock's 1-second TTL. [3](#0-2) 

**Two concrete instantiations of this batcher exist:**

1. `WebsocketGateway` — drives real-time in-app notifications to connected Socket.io clients: [4](#0-3) 

2. `EmailService` — drives batched email delivery for transaction signing reminders: [5](#0-4) 

**Analogous pattern in `SchedulerService.addListener`:**

The same class of issue exists in the scheduler's Redis pub/sub listener. The async handler has no try/catch; if `handler(key)` throws (e.g., DB unavailable, NATS publish failure in `emitTransactionRemindSigners`), the Redis keyspace expiry event is consumed and gone — the transaction-signing reminder is permanently lost: [6](#0-5) [7](#0-6) 

### Impact Explanation

- **In-app and email notifications are permanently lost** when `flushCallback` fails after Redis deletion. There is no dead-letter queue, no persistence fallback, and no admin replay mechanism.
- **Transaction signing reminders are silently dropped** if `handleTransactionReminder` throws (DB or NATS outage), because the Redis keyspace notification is a one-time fire-and-forget event.
- In a multi-signature workflow, missed signing reminders mean transactions can stall indefinitely at `WAITING_FOR_SIGNATURES` status without signers being notified, blocking fund movement or governance actions.

### Likelihood Explanation

- The `EmailService.processMessages` callback has internal try/catch and is unlikely to propagate a throw. However, a transient Redis connection error during `del(batchKey)` or `del(flushKey)` (lines 107–108) can still leave the system in an inconsistent state.
- The `SchedulerService

### Citations

**File:** back-end/apps/notifications/src/utils/DebouncedNotificationBatcher.ts (L28-34)
```typescript
    this.subClient.on('message', async (_channel, message) => {
      if (message.startsWith(this.batchKeyPrefix)) {
        await this.processExpiration(message, this.batchKeyPrefix);
      } else if (message.startsWith(this.flushKeyPrefix)) {
        await this.processExpiration(message, this.flushKeyPrefix);
      }
    });
```

**File:** back-end/apps/notifications/src/utils/DebouncedNotificationBatcher.ts (L45-53)
```typescript
  private async processExpiration(message: string, keyPrefix: string): Promise<void> {
    const groupKey = message.slice(keyPrefix.length);
    const lockKey = `${keyPrefix}${groupKey}:lock`;
    const acquired = await this.pubClient.set(lockKey, '1', 'PX', 1000, 'NX');
    if (acquired) {
      await this.flush(groupKey === this.GLOBAL_KEY ? null : groupKey);
      await this.pubClient.del(lockKey);
    }
  }
```

**File:** back-end/apps/notifications/src/utils/DebouncedNotificationBatcher.ts (L100-112)
```typescript
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
```

**File:** back-end/apps/notifications/src/websocket/websocket.gateway.ts (L43-51)
```typescript
    this.batcher = new DebouncedNotificationBatcher(
      this.processMessages.bind(this),
      500,
      200,
      2000,
      this.configService.get('REDIS_URL'),
      'inapp-notifications',
    );
  }
```

**File:** back-end/apps/notifications/src/email/email.service.ts (L32-39)
```typescript
    this.batcher = new DebouncedNotificationBatcher(
      this.processMessages.bind(this),
      2000,
      200,
      10000,
      this.configService.get('REDIS_URL'),
      'emails',
    );
```

**File:** back-end/libs/common/src/scheduler/scheduler.service.ts (L29-37)
```typescript
  addListener(handler: (key: string) => void) {
    this.subClient.on('message', async (_channel, message) => {
      if (!message.startsWith(this.SCHEDULE_PREFIX)) {
        return;
      }
      const key = message.replace(this.SCHEDULE_PREFIX, '');

      await handler(key);
    });
```

**File:** back-end/apps/chain/src/transaction-reminder/reminder-handler.service.ts (L23-25)
```typescript
  onModuleInit() {
    this.schedulerService.addListener(this.handleTransactionReminder.bind(this));
  }
```
