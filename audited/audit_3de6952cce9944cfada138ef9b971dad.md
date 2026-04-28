### Title
Flawed Guard in `archiveTransaction` Allows Creator to Transition Manual Transactions Out of Terminal States

### Summary
The `archiveTransaction` function in `back-end/apps/api/src/transactions/transactions.service.ts` contains a logically inverted guard condition. Because the condition uses `&&` (AND) instead of `||` (OR), any authenticated user who is the creator of a `isManual=true` transaction can call `PATCH /transactions/archive/:id` to force the status to `ARCHIVED` regardless of the transaction's current state — including terminal states such as `EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, and `REJECTED`. This is the direct analog of the external report's "arbitrary stage setter with no restrictions" pattern.

### Finding Description

The guard in `archiveTransaction` is:

```typescript
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  ) &&
  !transaction.isManual
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
``` [1](#0-0) 

The condition to **throw** is: `(status NOT in allowed list) AND (NOT isManual)`.  
The condition to **proceed** is therefore: `(status IN allowed list) OR (isManual == true)`.

When `isManual = true`, the entire status check is short-circuited. The function proceeds unconditionally to:

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [2](#0-1) 

The intended logic — "only allow archiving a manual transaction that is still in-progress" — is correctly expressed in the **front-end** guard:

```typescript
const canArchive = computed(() => {
  const isManual = props.organizationTransaction?.isManual;
  return isManual && isCreator.value && transactionIsInProgress.value;
});
``` [3](#0-2) 

The front-end correctly requires **both** `isManual` and an in-progress status. The back-end only requires **either**, making the back-end guard weaker and bypassable by a direct API call.

The endpoint is reachable by any authenticated user who is the creator of the transaction:

```typescript
@Patch('/archive/:id')
async archiveTransaction(@GetUser() user, @Param('id', ParseIntPipe) id: number): Promise<boolean> {
  return this.transactionsService.archiveTransaction(id, user);
}
``` [4](#0-3) 

The `TransactionStatus` enum defines the terminal states that should be immutable:

```typescript
export enum TransactionStatus {
  EXECUTED = 'EXECUTED',
  FAILED = 'FAILED',
  EXPIRED = 'EXPIRED',
  CANCELED = 'CANCELED',
  ARCHIVED = 'ARCHIVED',
  REJECTED = 'REJECTED',
  ...
}
``` [5](#0-4) 

### Impact Explanation

A transaction creator with a `isManual=true` transaction in any terminal state (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `REJECTED`) can issue:

```
PATCH /transactions/archive/<id>
```

This overwrites the terminal status with `ARCHIVED`, causing:

1. **Audit trail corruption**: An `EXECUTED` transaction can be re-labeled `ARCHIVED`, hiding successful on-chain execution from status-based queries and reports.
2. **Unauthorized state transition from terminal states**: The state machine invariant — that terminal states are immutable — is violated. `EXECUTED → ARCHIVED`, `FAILED → ARCHIVED`, `CANCELED → ARCHIVED` are all reachable.
3. **Notification system confusion**: `emitTransactionStatusUpdate` is called after the status overwrite, triggering downstream notification logic based on the now-incorrect `ARCHIVED` status for a transaction that was already in a terminal state. [6](#0-5) 

### Likelihood Explanation

- **Attacker profile**: Any authenticated organization user who has created at least one manual transaction (`isManual=true`). No admin or privileged role is required.
- **Preconditions**: The attacker must be the `creatorKey.userId` of the target transaction. This is a normal user-level capability.
- **Trigger**: A single direct HTTP `PATCH` request to `/transactions/archive/:id`, bypassing the front-end guard entirely.
- **Detectability**: The back-end performs no logging of unexpected state transitions, so the corruption is silent.

### Recommendation

Replace the `&&` (AND) with `||` (OR) so that **both** conditions must be satisfied to proceed:

```typescript
// Current (broken): throws only if status is wrong AND not manual
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  ) &&
  !transaction.isManual
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}

// Fixed: throws if not manual OR status is not in the allowed list
if (
  !transaction.isManual ||
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  )
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

This matches the front-end's intent: `isManual && isCreator && transactionIsInProgress`.

### Proof of Concept

1. Authenticate as a normal organization user (User A).
2. Create a manual transaction (`isManual: true`) via `POST /transactions` with `isManual: true`.
3. Wait for or simulate the transaction reaching `EXECUTED` status (e.g., via the chain service executing it, or via the scheduler marking it `EXPIRED`).
4. Confirm the transaction is in a terminal state by calling `GET /transactions/:id`.
5. Issue: `PATCH /transactions/archive/:id` directly (bypassing the front-end).
6. Observe: the response is `true` (HTTP 200), and a subsequent `GET /transactions/:id` shows `status: "ARCHIVED"` instead of `"EXECUTED"` or `"EXPIRED"`.
7. The audit trail now shows the transaction as `ARCHIVED` rather than its true terminal state, and a spurious status-update notification has been emitted. [7](#0-6)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L708-733)
```typescript
  async archiveTransaction(id: number, user: User): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);

    if (
      ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
        transaction.status,
      ) &&
      !transaction.isManual
    ) {
      throw new BadRequestException(ErrorCodes.OMTIP);
    }

    await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
    emitTransactionStatusUpdate(
      this.notificationsPublisher,
      [{
        entityId: transaction.id,
        additionalData: {
          transactionId: transaction.transactionId,
          network: transaction.mirrorNetwork,
        },
      }],
    );

    return true;
  }
```

**File:** front-end/src/renderer/pages/TransactionDetails/components/TransactionDetailsHeader.vue (L189-193)
```vue
const canArchive = computed(() => {
  const isManual = props.organizationTransaction?.isManual;

  return isManual && isCreator.value && transactionIsInProgress.value;
});
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L264-270)
```typescript
  @Patch('/archive/:id')
  async archiveTransaction(
    @GetUser() user,
    @Param('id', ParseIntPipe) id: number,
  ): Promise<boolean> {
    return this.transactionsService.archiveTransaction(id, user);
  }
```

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L46-56)
```typescript
export enum TransactionStatus {
  NEW = 'NEW', // unused
  CANCELED = 'CANCELED',
  REJECTED = 'REJECTED',
  WAITING_FOR_SIGNATURES = 'WAITING FOR SIGNATURES',
  WAITING_FOR_EXECUTION = 'WAITING FOR EXECUTION',
  EXECUTED = 'EXECUTED',
  FAILED = 'FAILED',
  EXPIRED = 'EXPIRED',
  ARCHIVED = 'ARCHIVED',
}
```
