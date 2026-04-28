### Title
Missing Duplicate `userId` Validation in `createTransactionObservers` Allows Irrevocable Observer Access

### Summary
The `CreateTransactionObserversDto` DTO and `createTransactionObservers` service method accept an array of `userIds` without checking for duplicates within the submitted array itself. A transaction creator can submit repeated `userId` values in a single POST request, causing multiple `TransactionObserver` database records to be created for the same user. Because observer removal operates by record ID (not by `userId`), the creator cannot revoke observer access in a single operation and may falsely believe access has been revoked when duplicate records remain.

### Finding Description

**Root cause — DTO layer (no `@ArrayUnique()`):**

`CreateTransactionObserversDto` enforces `@IsArray()`, `@IsNumber({}, { each: true })`, and `@ArrayMinSize(1)`, but has no uniqueness constraint on the submitted `userIds`. [1](#0-0) 

**Root cause — service layer (duplicate check is against DB snapshot, not the incoming array):**

`createTransactionObservers` loads `transaction.observers` once before the loop and checks each incoming `userId` against that static snapshot. Newly constructed (but not yet persisted) observer objects are pushed to a local `observers[]` array, so the snapshot never reflects them. If `dto.userIds = [5, 5, 5]` and userId 5 is not already in the DB, all three iterations pass the guard and three records are inserted. [2](#0-1) 

**Root cause — removal is by record ID, not by `userId`:**

`removeTransactionObserver` deletes a single record by its primary key. If three records exist for the same `userId`, one DELETE call leaves two records intact and the user retains observer access. [3](#0-2) 

**Entry point — authenticated, non-privileged user:**

The endpoint is guarded only by JWT authentication and email verification. Any user who has created a transaction can reach `createTransactionObservers`. [4](#0-3) 

### Impact Explanation

1. **Irrevocable observer access**: After duplicate records are created, a creator who issues a single `DELETE /transactions/{id}/observers/{observerId}` believes they have revoked access. The remaining duplicate records keep the user as a valid observer, bypassing the creator's intent to revoke.
2. **Data integrity corruption**: Multiple `TransactionObserver` rows for the same `(transactionId, userId)` pair violate the expected one-to-one relationship and can cause unexpected behavior in any component that iterates over observer records (e.g., notification fan-out sending duplicate alerts).
3. **Notification amplification**: If the notifications service fans out to every observer record, a user with N duplicate records receives N copies of every notification for that transaction.

### Likelihood Explanation

- **Attacker profile**: Any authenticated, verified user who has created at least one transaction — no admin or privileged role required.
- **Trigger**: A single crafted POST request with a repeated `userId` in the `userIds` array (e.g., `{"userIds": [42, 42, 42]}`).
- **No rate-limit or size cap**: `CreateTransactionObserversDto` has no `@ArrayMaxSize()`, so the array can be arbitrarily large, amplifying the number of duplicate records in one request.

### Recommendation

**Short term**: Add `@ArrayUnique()` from `class-validator` to the `userIds` field in `CreateTransactionObserversDto`:

```typescript
import { ArrayMinSize, ArrayUnique, IsArray, IsNumber } from 'class-validator';

export class CreateTransactionObserversDto {
  @IsArray()
  @IsNumber({}, { each: true })
  @ArrayMinSize(1)
  @ArrayUnique()
  userIds: number[];
}
```

Additionally, deduplicate within the service loop itself as a defense-in-depth measure:

```typescript
const uniqueUserIds = [...new Set(dto.userIds)];
for (const userId of uniqueUserIds) { ... }
```

**Long term**: Add a database-level unique constraint on `(transactionId, userId)` in the `TransactionObserver` entity to make duplicate insertion impossible regardless of application-layer validation.

### Proof of Concept

**Preconditions**: Authenticated user `A` has created transaction with `id = 1`. User `B` has `id = 42` and is not yet an observer.

**Step 1 — Create duplicate observer records:**
```http
POST /transactions/1/observers
Authorization: Bearer <A's JWT>
Content-Type: application/json

{ "userIds": [42, 42, 42] }
```
**Result**: Three `TransactionObserver` rows are inserted for `userId=42, transactionId=1` (e.g., with IDs 10, 11, 12).

**Step 2 — Creator attempts to revoke access:**
```http
DELETE /transactions/1/observers/10
Authorization: Bearer <A's JWT>
```
**Result**: Record 10 is deleted. Records 11 and 12 remain.

**Step 3 — Verify user B still has observer access:**
```http
GET /transactions/1/observers
Authorization: Bearer <B's JWT>
```
**Result**: 200 OK — user B is still listed as an observer and retains full read access to the transaction, contrary to the creator's intent.

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

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L47-68)
```typescript
    const observers: TransactionObserver[] = [];

    for (const userId of dto.userIds) {
      if (!transaction.observers.some(o => o.userId === userId)) {
        const observer = this.repo.create({ userId, transactionId, role: Role.FULL });
        observers.push(observer);
      }
    }

    if (observers.length === 0) {
      return [];
    }

    try {
      const result = await this.repo.save(observers);

      emitTransactionUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);

      return result;
    } catch (error) {
      throw new BadRequestException(error.message);
    }
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L132-141)
```typescript
  /* Remove the transaction observer for the given transaction observer id. */
  async removeTransactionObserver(id: number, user: User): Promise<boolean> {
    const observer = await this.getUpdateableObserver(id, user);

    await this.repo.remove(observer);

    emitTransactionUpdate(this.notificationsPublisher, [{ entityId: observer.transactionId }]);

    return true;
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
