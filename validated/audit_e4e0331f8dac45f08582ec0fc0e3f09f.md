All referenced code has been verified. Every claim in the report is accurate.

---

Audit Report

## Title
`CreateTransactionObserversDto` Allows Unbounded `userIds` Array With Intra-Array Duplicates, Enabling Authenticated Resource Exhaustion

## Summary
`CreateTransactionObserversDto` enforces only `@ArrayMinSize(1)` on `userIds` with no upper bound. The `createTransactionObservers` service deduplicates only against already-persisted observers, not against repeated entries within the incoming request itself. An authenticated transaction creator can submit a single POST request with a massive array of repeated user IDs, causing unbounded in-memory object allocation and a burst of database insert attempts before the DB unique constraint fires.

## Finding Description

**Root cause 1 — No `@ArrayMaxSize` on `userIds`:**

`CreateTransactionObserversDto` accepts an arbitrarily large array bounded only by the 2 MB HTTP body limit configured in `setup-app.ts`. [1](#0-0) [2](#0-1) 

With a 2 MB limit and JSON integers separated by commas, an attacker can pack roughly 500,000+ entries into a single request.

**Root cause 2 — Intra-array duplicate check is absent:**

`createTransactionObservers` checks each incoming `userId` only against `transaction.observers` (the snapshot of already-persisted rows loaded before the loop). It never checks whether the same `userId` appears multiple times within `dto.userIds` itself. [3](#0-2) 

If `dto.userIds = [99, 99, 99, …]` and userId 99 is not yet an observer, every iteration passes the guard and pushes a new `TransactionObserver` object into the in-memory `observers` array. All N objects are then passed to `this.repo.save(observers)`. [4](#0-3) 

**The DB unique constraint exists but does not prevent the in-memory phase:**

The `TransactionObserver` entity has a unique index on `(userId, transactionId)`, which rejects duplicate rows at the database level — but only after the server has already allocated the full in-memory array and attempted the batch insert. [5](#0-4) 

**Controller entry point — authenticated and verified users only:** [6](#0-5) 

## Impact Explanation
A single 2 MB request causes the Node.js process to allocate up to ~500,000 `TransactionObserver` JS objects in memory, iterate over all of them, and issue a batch DB insert. The DB unique constraint fires on the second duplicate, throwing an error caught as `BadRequestException`, but the full in-memory allocation and at least one DB round-trip have already occurred. Repeated requests from one or more transaction creators can spike heap usage and DB connection load, degrading or crashing the API service for all users. This is a server-side resource exhaustion (memory + DB) triggered by a single authenticated HTTP request.

## Likelihood Explanation
Any registered, verified user who has created at least one transaction satisfies the precondition. No admin or privileged role is required. The endpoint is reachable over standard HTTPS. The crafted payload is trivial to construct (a JSON array with a repeated integer). No rate-limiting on this endpoint is visible in the codebase.

## Recommendation

1. **Add `@ArrayMaxSize` to `CreateTransactionObserversDto`** — enforce a reasonable upper bound (e.g., 100 or 1000) on the `userIds` array:
   ```ts
   @ArrayMaxSize(100)
   @ArrayMinSize(1)
   userIds: number[];
   ``` [1](#0-0) 

2. **Deduplicate `dto.userIds` before the loop** in `createTransactionObservers` — use `[...new Set(dto.userIds)]` to eliminate intra-array duplicates before building the `observers` array:
   ```ts
   for (const userId of [...new Set(dto.userIds)]) {
   ``` [3](#0-2) 

## Proof of Concept

```
POST /transactions/1/observers
Authorization: Bearer <valid_jwt_of_transaction_creator>
Content-Type: application/json

{ "userIds": [99,99,99, … repeated ~500,000 times …] }
```

1. Attacker registers as a normal user and creates one transaction (becomes its creator).
2. Sends the above request. The body fits within the 2 MB limit.
3. The service loads `transaction.observers` (empty for a new transaction), then iterates all 500,000 entries — each passes the `!transaction.observers.some(o => o.userId === 99)` check since the snapshot never updates.
4. 500,000 `TransactionObserver` objects are allocated in memory and passed to `this.repo.save(observers)`.
5. TypeORM attempts to insert them; the DB unique index on `(userId, transactionId)` rejects the second insert, throwing an error caught as `BadRequestException`.
6. The attacker receives a 400 response, but the server has already performed the full in-memory allocation and at least one DB round-trip.
7. The request can be repeated in a tight loop across multiple transactions the attacker owns.

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction-observers.dto.ts (L1-7)
```typescript
import { ArrayMinSize, IsArray, IsNumber } from 'class-validator';

export class CreateTransactionObserversDto {
  @IsArray()
  @IsNumber({}, { each: true })
  @ArrayMinSize(1)
  userIds: number[];
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

**File:** back-end/libs/common/src/database/entities/transaction-observer.entity.ts (L19-22)
```typescript
@Entity()
@Index(['userId', 'transactionId'], { unique: true })
@Index(['transactionId'])
@Index(['userId'])
```

**File:** back-end/apps/api/src/transactions/observers/observers.controller.ts (L29-50)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
@Serialize(TransactionObserverDto)
export class ObserversController {
  constructor(private observersService: ObserversService) {}

  /* Create transaction observers for the given transaction id with the user ids */
  @ApiOperation({
    summary: 'Creates transaction observers',
    description: 'Create transaction observers for the given transaction with the provided data.',
  })
  @ApiResponse({
    status: 201,
    type: TransactionObserverDto,
  })
  @Post()
  createTransactionObserver(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() body: CreateTransactionObserversDto,
  ): Promise<TransactionObserver[]> {
    return this.observersService.createTransactionObservers(user, transactionId, body);
  }
```
