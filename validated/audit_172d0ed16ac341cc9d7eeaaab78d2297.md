The code is confirmed. Here is the audit report.

---

Audit Report

## Title
Incorrect Boolean Guard in `archiveTransaction` Allows Creator to Overwrite Terminal Transaction States on Manual Transactions

## Summary
`archiveTransaction` in `transactions.service.ts` uses a logically flawed `&&` guard. When `isManual` is `true`, the second operand `!transaction.isManual` evaluates to `false`, short-circuiting the entire condition to `false` and preventing the guard from ever throwing — regardless of the transaction's current status. This allows the creator of any manual transaction to archive it even when it is in a terminal state (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`), overwriting the authoritative state and corrupting the audit trail.

## Finding Description

**Root cause — incorrect boolean guard:**

The guard at lines 711–718 of `transactions.service.ts` reads:

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

The guard only throws when **both** sub-expressions are `true`. When `transaction.isManual === true`, `!transaction.isManual` is `false`, and the `&&` short-circuits to `false` — the guard never fires, regardless of `transaction.status`.

| `status NOT IN [WFS, WFE]` | `!isManual` | throws? |
|---|---|---|
| true | true | yes (correct) |
| true | **false** | **no — isManual bypasses status check entirely** |
| false | true | no (correct status) |
| false | false | no (correct status) |

**Unconditional write follows immediately:**

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [2](#0-1) 

This overwrites whatever terminal state the transaction holds.

**Entry point — authenticated HTTP endpoint, no privilege required:**

```typescript
@Patch('/archive/:id')
async archiveTransaction(@GetUser() user, @Param('id', ParseIntPipe) id: number): Promise<boolean> {
  return this.transactionsService.archiveTransaction(id, user);
}
``` [3](#0-2) 

The only access control is `getTransactionForCreator`, which verifies the caller is the transaction's creator — a normal user role:

```typescript
if (transaction.creatorKey?.userId !== user?.id) {
  throw new UnauthorizedException('Only the creator has access to this transaction');
}
``` [4](#0-3) 

**Test gap — unit and controller tests use `isManual: false`:**

The controller spec fixture sets `isManual: false`: [5](#0-4) 

No test exercises `archiveTransaction` with `isManual: true` and a terminal status, so the flawed branch is never covered.

## Impact Explanation

A transaction creator can overwrite any terminal state (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`) with `ARCHIVED` on any manual transaction they own:

- An `EXECUTED` transaction — already submitted to and confirmed by the Hedera network — can be relabeled `ARCHIVED`, hiding the on-chain execution from the organization's audit trail.
- A `FAILED` transaction can be silently buried as `ARCHIVED`, preventing operators from investigating the failure.
- A spurious `STATUS_UPDATE` notification is emitted for a transaction already in a terminal state, potentially confusing downstream consumers.

The system explicitly treats these as terminal/final states: [6](#0-5) 

## Likelihood Explanation

- **Attacker preconditions**: authenticated user, creator of at least one manual transaction. No admin or privileged key required.
- **Trigger**: a single `PATCH /transactions/archive/:id` HTTP request after the transaction reaches a terminal state.
- **Discoverability**: the `isManual` flag is set by the creator at creation time and is visible in the transaction response body. Manual transactions are an explicitly supported workflow (the `isManual` field is stored and used throughout the service).
- Any user who creates a manual transaction and then executes it is in the exact position to trigger this bug.

## Recommendation

The guard should be restructured so that the status check is **always** enforced, regardless of `isManual`. The correct intent is: only allow archiving when the transaction is in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`:

```typescript
// Correct: status check is always enforced
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  )
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

If the intent is to allow manual transactions to be archived from *additional* statuses (e.g., `NEW`), that should be expressed as an explicit allowlist, not by bypassing the status check entirely:

```typescript
const archivableStatuses = [
  TransactionStatus.WAITING_FOR_SIGNATURES,
  TransactionStatus.WAITING_FOR_EXECUTION,
  ...(transaction.isManual ? [TransactionStatus.NEW] : []),
];

if (!archivableStatuses.includes(transaction.status)) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

Additionally, add unit tests covering `isManual: true` with each terminal status to ensure the guard is enforced.

## Proof of Concept

1. Authenticated user Alice creates a manual transaction (`isManual: true`) via `POST /transactions`.
2. The transaction is executed and reaches status `EXECUTED`.
3. Alice sends: `PATCH /transactions/archive/<id>` with her JWT.
4. In `archiveTransaction`:
   - `getTransactionForCreator` passes (Alice is the creator).
   - Guard evaluates: `(status NOT IN [WFS, WFE]) && (!isManual)` → `true && false` → `false`.
   - Guard does **not** throw.
   - `repo.update({ id }, { status: TransactionStatus.ARCHIVED })` executes unconditionally.
5. The transaction's status is now `ARCHIVED`, overwriting `EXECUTED`. The on-chain execution is hidden from the audit trail.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L98-105)
```typescript
  private readonly terminalStatuses = [
    TransactionStatus.EXECUTED,
    TransactionStatus.EXPIRED,
    TransactionStatus.FAILED,
    TransactionStatus.CANCELED,
    TransactionStatus.ARCHIVED,
    TransactionStatus.REJECTED,
  ];
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L711-718)
```typescript
    if (
      ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
        transaction.status,
      ) &&
      !transaction.isManual
    ) {
      throw new BadRequestException(ErrorCodes.OMTIP);
    }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L720-720)
```typescript
    await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L886-888)
```typescript
    if (transaction.creatorKey?.userId !== user?.id) {
      throw new UnauthorizedException('Only the creator has access to this transaction');
    }
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

**File:** back-end/apps/api/src/transactions/transactions.controller.spec.ts (L107-107)
```typescript
      isManual: false,
```
