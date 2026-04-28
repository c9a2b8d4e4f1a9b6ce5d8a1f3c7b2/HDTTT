Based on my review of the actual source code, all cited file paths, line numbers, and code patterns are confirmed. Here is my assessment:

---

Audit Report

## Title
Permanent Notification and Reminder Loss via Non-Atomic Delete-Before-Callback and Unhandled Async Pub/Sub Errors

## Summary
`DebouncedNotificationBatcher.flush()` deletes batched messages from Redis **before** invoking `flushCallback`, creating a window where messages are permanently lost if the callback fails. The Redis pub/sub `on('message')` handler driving the flush is async with no `try/catch`, meaning any exception in `processExpiration` becomes a silently swallowed unhandled promise rejection, leaving the lock unreleased. The same pattern exists in `SchedulerService.addListener`, where a thrown handler causes permanent loss of a transaction signing reminder.

## Finding Description

**Root cause 1 — Non-atomic delete-then-callback in `flush()`:**

In `DebouncedNotificationBatcher.flush()`, both the batch key and flush key are deleted from Redis **before** the callback is invoked: [1](#0-0) 

The sequence is:
```
lrange → del(batchKey) → del(flushKey) → flushCallback(...)
```

If `flushCallback` throws after line 108, the messages are already gone from Redis with no re-queue, dead-letter store, or retry path.

**Root cause 2 — No error handling in the `on('message')` async handler:** [2](#0-1) 

If `processExpiration` throws (e.g., a Redis connection error during the `SET NX` lock acquisition), the error becomes an unhandled promise rejection. The lock acquired at line 48 is never released via `del(lockKey)` at line 51: [3](#0-2) 

The lock does carry a 1-second TTL (`PX`, 1000), so it auto-expires — this partially mitigates the lock-stuck scenario, but the batch is still permanently lost.

**Root cause 3 — Same pattern in `SchedulerService.addListener`:** [4](#0-3) 

The async handler has no `try/catch`. If `handler(key)` throws (e.g., DB unavailable, NATS publish failure in `emitTransactionRemindSigners`), the Redis keyspace expiry event is consumed and gone — the transaction-signing reminder is permanently lost. [5](#0-4) 

**Two concrete instantiations of the batcher:**

- `WebsocketGateway` — `processMessages` has **no try/catch**; if `this.io` is not yet initialized (e.g., during startup before `afterInit` is called), `this.io.to(...).emit(...)` throws a `TypeError`, and the batch is lost: [6](#0-5) 

- `EmailService` — `processMessages` has internal per-group try/catch and `sendWithRetry` with 5 attempts, so it is unlikely to propagate a throw in practice: [7](#0-6) 

## Impact Explanation

- **In-app WebSocket notifications are permanently lost** if `WebsocketGateway.processMessages` throws after Redis deletion. There is no persistence fallback or replay mechanism.
- **Transaction signing reminders are silently dropped** if `handleTransactionReminder` throws (DB or NATS outage), because the Redis keyspace notification is a one-time fire-and-forget event. Transactions can stall indefinitely at `WAITING_FOR_SIGNATURES` without signers being notified.
- **Email notifications** are largely protected by internal error handling in `processMessages`, but a Redis connection error during `del(batchKey)` or `del(flushKey)` (lines 107–108) can still leave the system in an inconsistent state.

## Likelihood Explanation

- **`WebsocketGateway`**: `this.io.emit()` is synchronous and rarely throws in normal operation, but the absence of any error guard means any unexpected exception causes permanent message loss. Likelihood is low-to-medium.
- **`SchedulerService`**: A transient DB or NATS outage during `handleTransactionReminder` (which calls `emitTransactionRemindSigners`) will cause the reminder to be permanently dropped. In a distributed deployment, this is a realistic scenario. Likelihood is medium.
- **Redis connection errors** during `del()` operations are possible under network partitions and can leave the system in an inconsistent state regardless of callback error handling.

## Recommendation

1. **Reverse the order in `flush()`**: Call `flushCallback` first, then delete the keys only on success. Alternatively, use a Redis pipeline/transaction (`MULTI/EXEC`) or move messages to a "processing" key before deletion, re-queuing on callback failure.
2. **Wrap async pub/sub handlers in try/catch**: Both `DebouncedNotificationBatcher`'s `on('message')` handler and `SchedulerService.addListener`'s handler should catch errors, log them, and ensure the lock is released (e.g., via `finally`).
3. **Use `finally` for lock release in `processExpiration`**: Wrap `flush()` in try/finally to guarantee `del(lockKey)` is always called.
4. **Add error handling in `SchedulerService.addListener`**: Wrap `await handler(key)` in try/catch to prevent silent reminder loss.

## Proof of Concept

**Scenario — WebSocket notification loss:**
1. User triggers an action that queues a notification via `batcher.add(...)`.
2. The flush key expires; Redis publishes the keyspace event.
3. `processExpiration` acquires the lock and calls `flush()`.
4. `flush()` calls `del(batchKey)` and `del(flushKey)` — messages are gone from Redis.
5. `flushCallback` (`WebsocketGateway.processMessages`) is called while `this.io` is `null` (e.g., during a restart race condition) — throws `TypeError: Cannot read properties of null`.
6. The exception propagates through `flush()` → `processExpiration` → the async `on('message')` handler with no catch → unhandled promise rejection.
7. The notification is permanently lost; the user never receives it.

**Scenario — Transaction signing reminder loss:**
1. A transaction enters `WAITING_FOR_SIGNATURES`; `addReminder` sets a Redis key with a TTL.
2. The key expires; Redis publishes the keyspace event.
3. `SchedulerService`'s `on('message')` handler fires and calls `await handler(key)` (`handleTransactionReminder`).
4. `emitTransactionRemindSigners` fails due to a NATS broker outage — throws.
5. The exception propagates through the async handler with no catch → unhandled promise rejection.
6. The Redis keyspace event is consumed and will never fire again.
7. The transaction stalls indefinitely at `WAITING_FOR_SIGNATURES` with no signers notified.

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

**File:** back-end/apps/notifications/src/utils/DebouncedNotificationBatcher.ts (L107-112)
```typescript
    await this.pubClient.del(batchKey);
    await this.pubClient.del(flushKey);

    // Parse messages and call the flush callback
    const parsedMessages = messages.map((msg) => JSON.parse(msg));
    await this.flushCallback(groupKey, parsedMessages);
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

**File:** back-end/apps/notifications/src/websocket/websocket.gateway.ts (L93-110)
```typescript
  private async processMessages(groupKey: number | null, messages: NotificationMessage[]) {
    const groupedMessages = messages.reduce((map, msg) => {
      if (!map.has(msg.message)) {
        map.set(msg.message, []);
      }
      map.get(msg.message)!.push(...msg.content);
      return map;
    }, new Map<string, string[]>());

    for (const [message, content] of groupedMessages.entries()) {
      if (groupKey) {
        // Emit to specific user room, if the room doesn't exist, silent no-op
        this.io.to(roomKeys.USER_KEY(groupKey)).emit(message, content);
      } else {
        this.io.emit(message, content);
      }
    }
  };
```

**File:** back-end/apps/notifications/src/email/email.service.ts (L166-171)
```typescript
      try {
        await this.sendWithRetry(mailOptions);
      } catch (err) {
        console.error(`Failed to send email for type=${type} to ${groupKey}:`, err);
        // continue to next group; consider re-queueing or alerting for persistent failures
      }
```
