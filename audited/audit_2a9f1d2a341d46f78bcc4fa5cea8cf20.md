### Title
Duplicate `userIds` in `createTransactionObservers` leads to inconsistent observer state

### Summary
The `createTransactionObservers` function in `observers.service.ts` accepts an array `userIds` and iterates over it to add observers to a transaction. The duplicate-check inside the loop only validates against already-persisted observers loaded from the database — it never checks for duplicates within the incoming `userIds` array itself. Passing the same `userId` twice in a single request bypasses the guard and attempts to insert two `TransactionObserver` rows with the same `(userId, transactionId)` pair, leading to either duplicate records or an unhandled constraint error.

---

### Finding Description

In `back-end/apps/api/src/transactions/observers/observers.service.ts`, the `createTransactionObservers` method iterates over `dto.userIds`:

```typescript
// observers.service.ts lines 49–53
for (const userId of dto.userIds) {
  if (!transaction.observers.some(o => o.userId === userId)) {
    const observer = this.repo.create({ userId, transactionId, role: Role.FULL });
    observers.push(observer);
  }
}
```

`transaction.observers` is the set of observers already persisted in the database (loaded at line 37–40). The guard `!transaction.observers.some(o => o.userId === userId)` correctly skips a userId that was previously saved, but it never checks whether the same `userId` appears more than once in the current request's `dto.userIds` array.

**Scenario:**
1. Caller sends `POST /transactions/:id/observers` with `{ "userIds": [5, 5] }`.
2. First iteration: `userId = 5` is not in `transaction.observers` → a new `TransactionObserver` is created and pushed to `observers`.
3. Second iteration: `userId = 5` is still not in `transaction.observers` (nothing has been saved yet) → a second `TransactionObserver` is created and pushed to `observers`.
4. `this.repo.save(observers)` is called with two objects sharing the same `(userId, transactionId)`.

The DTO class `CreateTransactionObserversDto` only validates that `userIds` is a non-empty array of numbers — no uniqueness constraint is enforced at the DTO level:

```typescript
// create-transaction-observers.dto.ts lines 1–8
export class CreateTransactionObserversDto {
  @IsArray()
  @IsNumber({}, { each: true })
  @ArrayMinSize(1)
  userIds: number[];
}
``` [1](#0-0) [2](#0-1) 

---

### Impact Explanation

- If no unique database constraint exists on `(userId, transactionId)` in `TransactionObserver`, duplicate rows are silently inserted. Downstream logic that counts or iterates observers (e.g., notification dispatch, permission checks) will process the same user multiple times, producing incorrect behavior.
- If a unique constraint does exist, the `repo.save` call throws, which is caught and re-thrown as a `BadRequestException` with a raw database error message — an unhelpful and unexpected failure for a caller who may have passed the duplicate accidentally.
- Either outcome represents an inconsistent or fragile state analogous to the M04 report: the system either stores corrupt data or fails non-gracefully on a valid-looking input. [3](#0-2) 

---

### Likelihood Explanation

Any authenticated user who is the creator of a transaction can reach this code path. The endpoint is `POST /transactions/:transactionId/observers`, guarded only by the creator check at line 44. No special role is required. A duplicate `userId` in the array can occur accidentally (e.g., a client-side bug that appends the same user twice) or intentionally. The attack surface is therefore realistic and reachable by ordinary users. [4](#0-3) 

---

### Recommendation

Deduplicate `dto.userIds` before the loop, or check against the in-progress `observers` array as well as the persisted ones:

```typescript
// Option A: deduplicate at entry
const uniqueUserIds = [...new Set(dto.userIds)];

for (const userId of uniqueUserIds) {
  if (!transaction.observers.some(o => o.userId === userId)) {
    const observer = this.repo.create({ userId, transactionId, role: Role.FULL });
    observers.push(observer);
  }
}
```

Additionally, add a `@ArrayUnique()` decorator to `CreateTransactionObserversDto.userIds` so the validation layer rejects duplicate entries before they reach the service.

---

### Proof of Concept

```http
POST /transactions/1/observers
Authorization: Bearer <creator_token>
Content-Type: application/json

{
  "userIds": [42, 42]
}
```

**Expected (correct) behavior:** One `TransactionObserver` row for `userId=42` is created.

**Actual behavior:** Two `TransactionObserver` objects are built in the loop (both pass the `transaction.observers` check since neither is persisted yet) and passed to `repo.save()`. Depending on the schema, either two duplicate rows are inserted, or a database constraint error is thrown and surfaced as a `400 Bad Request` with a raw SQL error message. [5](#0-4) [2](#0-1)

### Citations

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L32-69)
```typescript
  async createTransactionObservers(
    user: User,
    transactionId: number,
    dto: CreateTransactionObserversDto,
  ): Promise<TransactionObserver[]> {
    const transaction = await this.entityManager.findOne(Transaction, {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user', 'observers'],
    });

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to delete it');

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
  }
```

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
