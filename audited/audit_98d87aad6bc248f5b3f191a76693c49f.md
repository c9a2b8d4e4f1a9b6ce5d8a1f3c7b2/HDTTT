### Title
`CreateTransactionObserversDto.userIds` Array Not Validated for Duplicates, Causing Raw DB Error Exposure

### Summary

The `POST /transactions/:transactionId/observers` endpoint accepts a `userIds` array with no uniqueness constraint at the DTO validation layer. The service-level deduplication check only compares against **already-persisted** observers, not against duplicates within the incoming array itself. When duplicate IDs are submitted in a single request, the batch `repo.save()` call hits the database unique constraint and the raw PostgreSQL error message — including internal table and constraint names — is returned directly to the caller.

### Finding Description

**Root cause — missing `@ArrayUnique()` in the DTO:**

`CreateTransactionObserversDto` applies only `@IsArray()`, `@IsNumber({}, { each: true })`, and `@ArrayMinSize(1)`. There is no `@ArrayUnique()` decorator. [1](#0-0) 

**Service-level check only guards against already-persisted records:**

The loop in `createTransactionObservers` filters out userIds that already exist in `transaction.observers` (loaded once at the start of the call). It does **not** deduplicate within `dto.userIds` itself. [2](#0-1) 

If `dto.userIds = [5, 5]` and userId 5 is not yet an observer, both iterations pass the guard, and two `TransactionObserver` objects for the same `(userId=5, transactionId)` are pushed into the `observers` array.

**DB constraint fires, raw error is exposed:**

The entity declares a unique index on `(userId, transactionId)`: [3](#0-2) 

When `repo.save(observers)` is called with the two duplicate entries, PostgreSQL throws a unique-constraint violation. The `catch` block forwards the raw error message directly to the HTTP response: [4](#0-3) 

The raw PostgreSQL message contains internal identifiers such as the constraint name (`IDX_...`) and table name (`transaction_observer`), which are returned to the caller in the 400 response body.

**Contrast with the approvers service**, which uses a transactional `isNode` check that catches intra-request duplicates cleanly before any insert: [5](#0-4) 

### Impact Explanation

1. **Information disclosure**: The raw PostgreSQL error string — including internal constraint names and table names — is returned to the authenticated caller in the HTTP 400 body. This leaks schema internals.
2. **Broken batch semantics**: A request containing `[validUserId, validUserId, anotherValidUserId]` fails entirely rather than deduplicating and succeeding for the unique entries. The transaction creator cannot add any observers in that call.

No data corruption occurs because the DB constraint prevents duplicate rows from being written.

### Likelihood Explanation

The endpoint is reachable by any authenticated user who is the creator of a transaction — a standard, unprivileged role. The trigger requires only submitting a `userIds` array with a repeated value, which is a trivially crafted HTTP request. No special tooling or knowledge is required beyond a valid JWT and a transaction the user created.

### Recommendation

1. Add `@ArrayUnique()` from `class-validator` to `CreateTransactionObserversDto.userIds` to reject duplicate values at the validation layer before the service is reached.
2. As a defence-in-depth measure, deduplicate `dto.userIds` inside `createTransactionObservers` (e.g., `const uniqueIds = [...new Set(dto.userIds)]`) before the loop, mirroring the pattern used in the approvers service.
3. Do not forward raw `error.message` from database exceptions to HTTP responses. Map DB constraint errors to a generic, safe message.

### Proof of Concept

**Preconditions**: Authenticated as a user who created transaction with `id=1`. No observers yet on that transaction.

**Request**:
```http
POST /transactions/1/observers
Authorization: Bearer <creator-jwt>
Content-Type: application/json

{ "userIds": [42, 42] }
```

**Step-by-step**:
1. `createTransactionObservers` loads `transaction.observers` — empty.
2. Loop iteration 1: `userId=42` not in observers → pushed to `observers[]`.
3. Loop iteration 2: `userId=42` still not in `transaction.observers` (in-memory snapshot) → pushed again.
4. `repo.save([{userId:42,...}, {userId:42,...}])` executes.
5. PostgreSQL raises: `duplicate key value violates unique constraint "IDX_<hash>_transaction_observer_userId_transactionId"`.
6. `catch (error)` re-throws `new BadRequestException(error.message)`.

**Observed response** (HTTP 400):
```json
{
  "statusCode": 400,
  "message": "duplicate key value violates unique constraint \"IDX_<hash>_transaction_observer_userId_transactionId\""
}
```

Internal constraint name and table structure are disclosed. The entire request fails; no observers are added even if other valid, non-duplicate IDs were included in the array.

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

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L47-54)
```typescript
    const observers: TransactionObserver[] = [];

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L249-251)
```typescript
          /* Check if the approver already exists */
          if (await this.isNode(dtoApprover, transactionId, transactionalEntityManager))
            throw new Error(this.APPROVER_ALREADY_EXISTS);
```
