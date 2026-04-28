The code at lines 711–718 is confirmed exactly as described. The guard condition is: [1](#0-0) 

The logic flaw is real and verified. The SECURITY.md contains no exclusion that applies here — this is not a theoretical impact, not a best-practice recommendation, and requires no privileged access or leaked credentials.

---

# Audit Report

## Title
Incorrect Boolean Guard in `archiveTransaction` Allows Creators to Archive Manual Transactions in Any Terminal State

## Summary
The `archiveTransaction` function in `back-end/apps/api/src/transactions/transactions.service.ts` contains a logically flawed guard. Because the two sub-conditions are joined with `&&` instead of `||`, the guard is trivially bypassed for any transaction where `isManual = true`, allowing a creator to force any such transaction — including `EXECUTED`, `FAILED`, `EXPIRED`, or `CANCELED` — into `ARCHIVED` status.

## Finding Description
**Vulnerable code** (`transactions.service.ts`, lines 711–718):

```typescript
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  ) &&
  !transaction.isManual          // ← second operand of &&
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

The guard throws only when **both** sub-conditions are simultaneously true:
- The status is outside `[WAITING_FOR_SIGNATURES, WAITING_FOR_EXECUTION]`
- **AND** `isManual` is `false`

When `isManual = true`, `!transaction.isManual` evaluates to `false`, short-circuiting the entire `&&` expression to `false`. The guard **never throws**, regardless of the transaction's current status. The unconditional update at line 720 then executes:

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [2](#0-1) 

**Intended logic** (inferred): the guard should throw if the status is not in the allowed set **regardless** of `isManual`, i.e., the operator should be `||` not `&&`, or the `isManual` check should be a separate, independent gate.

## Impact Explanation
- A creator can transition an already-`EXECUTED` transaction to `ARCHIVED`, hiding it from dashboards and audit views that filter on terminal status.
- A creator can transition a `FAILED` or `EXPIRED` transaction to `ARCHIVED`, masking execution failures from approvers and observers.
- The `emitTransactionStatusUpdate` call at lines 721–730 fires after the invalid transition, causing the notification system to broadcast an "archived" event for a transaction that actually failed or was already executed — directly corrupting the audit trail and misleading all subscribers. [3](#0-2) 

## Likelihood Explanation
- **Preconditions**: authenticated, verified user who is the creator of any `isManual = true` transaction. No admin access, no privileged keys, no leaked credentials required.
- **Trigger**: a single `PATCH /transactions/archive/:id` HTTP request after the transaction reaches a terminal state.
- **Access control**: the endpoint is protected only by `JwtAuthGuard` + `VerifiedUserGuard`; any organization user who creates manual transactions can exploit this immediately. [4](#0-3) 

## Recommendation
Replace the `&&` with `||` so that the guard blocks archiving whenever the status is not in the permitted set, independent of `isManual`:

```typescript
// Fixed guard
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  ) ||
  !transaction.isManual
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

Alternatively, if manual transactions are intentionally allowed to be archived from *any* state, the status check should be removed entirely for the manual path and documented explicitly. Either way, add unit tests covering `isManual = true` transactions in each terminal state (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`) to assert that `archiveTransaction` throws `BadRequestException`.

## Proof of Concept
1. Authenticate as a normal verified user.
2. `POST /transactions` with `isManual: true` — record the returned `id`.
3. Allow the transaction to reach `EXECUTED` (or `FAILED`, `EXPIRED`, `CANCELED`) through normal flow.
4. `PATCH /transactions/archive/:id` as the same user.
5. Observe HTTP 200 and confirm the transaction's status is now `ARCHIVED` despite having been in a terminal state — and that an "archived" notification was emitted.

The guard at lines 711–718 evaluates `false` at step 4 because `!transaction.isManual` is `false`, so no exception is raised and the `repo.update` at line 720 executes unconditionally. [5](#0-4)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L708-720)
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
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L721-730)
```typescript
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
```
