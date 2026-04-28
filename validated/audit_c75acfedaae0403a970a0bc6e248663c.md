### Title
Missing Lower-Bound Validation on `reminderMillisecondsBefore` Allows Redis Memory Exhaustion via Unbounded Key TTL

### Summary
The `CreateTransactionDto.reminderMillisecondsBefore` field accepts any number, including negative values, with no lower-bound constraint. When a negative value is supplied, the computed reminder timestamp (`validStart - reminderMillisecondsBefore`) resolves to a date far in the future, causing `SchedulerService.addReminder` to write a Redis key with an effectively infinite TTL. An authenticated user can repeatedly exploit this to accumulate non-expiring Redis keys and exhaust server memory.

### Finding Description

**Root cause — no `@Min` constraint on `reminderMillisecondsBefore`:**

`CreateTransactionDto` decorates the field with only `@IsOptional()` and `@IsNumber()`, imposing no lower bound. [1](#0-0) 

**Exploit path — negative value produces a far-future `remindAt`:**

In `createTransactions`, the reminder date is computed as:

```typescript
const remindAt = new Date(tx.validStart.getTime() - dto.reminderMillisecondsBefore);
``` [2](#0-1) 

The only guard before this line is `if (!dto.reminderMillisecondsBefore)`, which evaluates to `false` for any non-zero number — including negative numbers (truthy in JavaScript). So a value of `-9007199254740991` (`-Number.MAX_SAFE_INTEGER`) passes the guard and produces:

```
remindAt = validStart + 9007199254740991 ms  ≈  year ~285,000
```

**Sink — Redis key written with far-future `PXAT`:**

`SchedulerService.addReminder` writes the key unconditionally:

```typescript
await this.pubClient.set(key, key, 'PXAT', date.getTime());
``` [3](#0-2) 

Redis `PXAT` with a timestamp centuries in the future means the key **never expires** under normal operation. Each crafted transaction submission writes one such immortal key. The key name is derived from the transaction ID, so each new transaction creates a distinct key. [3](#0-2) 

### Impact Explanation

An authenticated user who submits many transactions with `reminderMillisecondsBefore: -<large_number>` causes Redis to accumulate non-expiring keys indefinitely. Redis is an in-memory store; unbounded key growth leads to:

- **Memory exhaustion** on the Redis instance, degrading or crashing the scheduler and notification subsystems for all organization users.
- **Service unavailability** for the Chain and Notifications microservices that depend on the same Redis instance for scheduling.

This is a persistent DoS: keys remain even after the attacker stops, requiring manual intervention to purge them.

### Likelihood Explanation

The attacker precondition is a valid authenticated account on the organization backend — a normal user role, reachable without any privileged access. The API endpoint `POST /transactions` is the standard transaction-creation path used by every organization user. No special knowledge beyond the API schema is required; the field name `reminderMillisecondsBefore` is self-documenting. The attack is repeatable at the rate of transaction submissions.

### Recommendation

Add `@Min(1)` and a sensible `@Max` (e.g., one week in milliseconds) to `reminderMillisecondsBefore` in `CreateTransactionDto`:

```typescript
@IsOptional()
@IsNumber()
@Min(1)
@Max(7 * 24 * 60 * 60 * 1_000) // 1 week
reminderMillisecondsBefore?: number;
``` [1](#0-0) 

Additionally, add a server-side guard in `createTransactions` to reject a `remindAt` that is already in the past or unreasonably far in the future before calling `addReminder`.

### Proof of Concept

1. Register/log in as a normal user on the organization backend.
2. Create a valid Hedera transaction (any type) and sign it.
3. Submit `POST /transactions` with the body:
   ```json
   {
     "name": "test",
     "description": "dos",
     "transactionBytes": "<valid_signed_tx_hex>",
     "signature": "<valid_sig_hex>",
     "creatorKeyId": <your_key_id>,
     "mirrorNetwork": "testnet",
     "reminderMillisecondsBefore": -9007199254740991
   }
   ```
4. The server accepts the request (passes `@IsNumber()` validation, passes the `!dto.reminderMillisecondsBefore` guard since `-9007199254740991` is truthy).
5. `remindAt` is computed as `validStart + 9007199254740991 ms` — a date in the year ~285,000.
6. `SchedulerService.addReminder` writes `schedule:transaction:sign:<id>` to Redis with `PXAT = <year 285000 timestamp>`.
7. Repeat with new transactions. Each iteration adds one immortal Redis key.
8. Observe Redis memory growing without bound via `redis-cli INFO memory`. [4](#0-3) [3](#0-2)

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction.dto.ts (L39-41)
```typescript
  @IsOptional()
  @IsNumber()
  reminderMillisecondsBefore?: number;
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L464-476)
```typescript
      // Batch schedule reminders
      const reminderPromises = savedTransactions
        .map((tx, index) => {
          const dto = dtos[index];
          if (!dto.reminderMillisecondsBefore) return null;

          const remindAt = new Date(tx.validStart.getTime() - dto.reminderMillisecondsBefore);
          return this.schedulerService.addReminder(
            getTransactionSignReminderKey(tx.id),
            remindAt,
          );
        })
        .filter(Boolean);
```

**File:** back-end/libs/common/src/scheduler/scheduler.service.ts (L40-43)
```typescript
  async addReminder(key: string, date: Date) {
    key = `${this.SCHEDULE_PREFIX}${key}`;
    await this.pubClient.set(key, key, 'PXAT', date.getTime());
  }
```
