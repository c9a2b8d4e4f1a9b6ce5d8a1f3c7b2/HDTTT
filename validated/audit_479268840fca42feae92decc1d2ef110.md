### Title
Missing `@ArrayMinSize(1)` on `CreateTransactionApproversArrayDto.approversArray` Allows Empty Array Submission Triggering Spurious Transaction Status Update Notifications

### Summary
The `CreateTransactionApproversArrayDto` class is missing an `@ArrayMinSize(1)` constraint on its `approversArray` field. Any authenticated user who is the creator of a transaction can POST `{ "approversArray": [] }` to the approvers endpoint, which passes DTO validation, performs zero state changes, but unconditionally emits a `TransactionStatusUpdate` NATS notification event — causing downstream consumers to process a spurious update for a transaction that was not modified.

### Finding Description
**Root cause — missing `@ArrayMinSize(1)` in the DTO:**

`back-end/apps/api/src/transactions/dto/create-transaction-approver.dto.ts` lines 25–29:

```typescript
export class CreateTransactionApproversArrayDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionApproverDto)
  approversArray: CreateTransactionApproverDto[];   // ← no @ArrayMinSize(1)
}
``` [1](#0-0) 

Compare with the sibling DTO `CreateTransactionObserversDto`, which correctly applies `@ArrayMinSize(1)`: [2](#0-1) 

And the nested `approvers` field inside `CreateTransactionApproverDto` also correctly applies `@ArrayMinSize(1)`: [3](#0-2) 

**Exploit path in the service:**

In `back-end/apps/api/src/transactions/approvers/approvers.service.ts`, `createTransactionApprovers` iterates over `dto.approversArray` and then unconditionally emits a `TransactionStatusUpdate` event after the database transaction block — regardless of whether any approvers were actually created: [4](#0-3) 

When `dto.approversArray` is `[]`, the `for` loop at line 353 is a no-op, the database transaction commits with zero writes, and `emitTransactionStatusUpdate` fires at line 358 for a transaction that was not modified.

### Impact Explanation
A transaction creator can repeatedly POST `{ "approversArray": [] }` to `POST /transactions/:id/approvers`. Each call:
1. Passes DTO validation (no `@ArrayMinSize(1)` guard).
2. Performs zero database writes.
3. Publishes a spurious `TransactionStatusUpdate` NATS event.

Downstream consumers — the WebSocket gateway and notification service — receive and process these events, triggering unnecessary re-fetches and UI updates for all connected clients observing that transaction. This is a concrete, demonstrable logic integrity failure: a state-change notification is emitted when no state change occurred.

### Likelihood Explanation
The attacker precondition is minimal: any authenticated user who has created at least one transaction can trigger this. No admin keys, no leaked credentials, and no privileged access are required. The endpoint is reachable via a standard authenticated HTTP POST.

### Recommendation
Add `@ArrayMinSize(1)` to `approversArray` in `CreateTransactionApproversArrayDto`, consistent with how `CreateTransactionObserversDto` and the nested `approvers` field are already guarded:

```typescript
export class CreateTransactionApproversArrayDto {
  @IsArray()
  @ArrayMinSize(1)          // ← add this
  @ValidateNested({ each: true })
  @Type(() => CreateTransactionApproverDto)
  approversArray: CreateTransactionApproverDto[];
}
```

### Proof of Concept
1. Authenticate as a normal user and create a transaction (obtain `transactionId`).
2. Send the following request:
   ```
   POST /transactions/{transactionId}/approvers
   Authorization: Bearer <valid_token>
   Content-Type: application/json

   { "approversArray": [] }
   ```
3. **Expected (correct) behavior**: HTTP 400 — validation rejects the empty array.
4. **Actual behavior**: HTTP 201 — request succeeds, zero approvers are created, and a `TransactionStatusUpdate` NATS event is emitted for the unmodified transaction.
5. Repeat step 2 in a loop to generate a stream of spurious status-update events with no rate limit beyond standard auth.

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

**File:** back-end/apps/api/src/transactions/dto/create-transaction-observers.dto.ts (L1-7)
```typescript
import { ArrayMinSize, IsArray, IsNumber } from 'class-validator';

export class CreateTransactionObserversDto {
  @IsArray()
  @IsNumber({}, { each: true })
  @ArrayMinSize(1)
  userIds: number[];
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L353-362)
```typescript
        for (const approver of dto.approversArray) {
          await createApprover(approver);
        }
      });

      emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transactionId  }]);
    } catch (error) {
      throw new BadRequestException(error.message);
    }

```
