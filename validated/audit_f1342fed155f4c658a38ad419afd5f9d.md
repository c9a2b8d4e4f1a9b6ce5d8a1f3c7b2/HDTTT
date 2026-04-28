All claims are verified against the actual code. The guard logic, DTO, entity, status enum, and test gap all match the description exactly.

---

Audit Report

## Title
`archiveTransaction` Guard Bypassed by `isManual` Flag Allows Overwriting Terminal Transaction States

## Summary
The `archiveTransaction` function uses a logically flawed AND condition that allows any transaction creator who set `isManual: true` at creation time to overwrite any terminal status (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`) with `ARCHIVED`, corrupting the audit trail and broadcasting false status notifications.

## Finding Description
The guard in `archiveTransaction` at lines 711–718 of `back-end/apps/api/src/transactions/transactions.service.ts`:

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

The condition throws only when **both** sub-expressions are true. When `isManual=true`, `!transaction.isManual` evaluates to `false`, short-circuiting the entire AND to `false` — no exception is raised regardless of the current status. Execution falls through unconditionally to:

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [2](#0-1) 

`isManual` is a user-controlled optional boolean accepted directly from the request body in `CreateTransactionDto`: [3](#0-2) 

It is stored verbatim on the `Transaction` entity and never reset after execution: [4](#0-3) 

The `TransactionStatus` enum defines all terminal states that can be overwritten: [5](#0-4) 

The existing e2e test at lines 884–897 only exercises a **non-manual** transaction (no `isManual: true` fixture), leaving the bypass path untested: [6](#0-5) 

## Impact Explanation
- **Audit trail corruption**: An `EXECUTED` transaction's status is permanently overwritten to `ARCHIVED` in PostgreSQL. The true outcome of the Hedera network operation is erased from the application's record.
- **False notifications**: All observers and signers receive an `ARCHIVED` status-update notification for a transaction that was actually executed, making it impossible to distinguish executed from archived without querying the Hedera mirror node directly.
- **Terminal-state masking**: A `FAILED` transaction can be archived, hiding the failure from all participants. A `CANCELED` transaction can be re-archived, producing duplicate status events.
- **State machine violation**: `ARCHIVED` is a terminal state alongside `EXECUTED`, `FAILED`, `EXPIRED`, and `CANCELED`. Allowing one terminal state to overwrite another breaks the invariant that terminal states are immutable.

## Likelihood Explanation
- Any verified, authenticated user can set `isManual: true` at transaction creation — no privileged role is required.
- The exploit requires exactly two API calls: `POST /transactions` (with `isManual: true`) and `PATCH /transactions/archive/:id` after execution.
- The `getTransactionForCreator` check only verifies ownership, not status eligibility, so the attacker needs only to be the creator of the transaction.
- The test suite does not cover this path, so the bypass has not been caught by automated testing.

## Recommendation
Fix the guard to check status independently of `isManual`. The intent of `isManual` appears to be allowing archival of transactions that are still in non-terminal states (e.g., `WAITING_FOR_SIGNATURES`), not to bypass terminal-state protection entirely. The corrected logic should be:

```typescript
const archivableStatuses = [
  TransactionStatus.WAITING_FOR_SIGNATURES,
  TransactionStatus.WAITING_FOR_EXECUTION,
];

if (!archivableStatuses.includes(transaction.status)) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

If `isManual` transactions genuinely need a broader set of archivable statuses, define that set explicitly rather than removing the status check entirely:

```typescript
const archivableStatuses = transaction.isManual
  ? [TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION]
  : [TransactionStatus.WAITING_FOR_SIGNATURES];

if (!archivableStatuses.includes(transaction.status)) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

Additionally, add an e2e test covering the `isManual=true` + `EXECUTED` combination to assert that `PATCH /transactions/archive/:id` returns `400` and does not overwrite the status.

## Proof of Concept

1. Authenticate as any verified user.
2. `POST /transactions` with body `{ ..., isManual: true }` → transaction created with `status = WAITING_FOR_SIGNATURES`, `isManual = true`.
3. Allow signatures to be collected; the chain service executes the transaction on Hedera and sets `status = EXECUTED`. `isManual` remains `true`.
4. `PATCH /transactions/archive/:id` (as the creator).
5. Guard evaluates: `!includes(EXECUTED)` → `true`; `!true` → `false`; `true && false` → `false` → **no exception thrown**.
6. `repo.update({ id }, { status: TransactionStatus.ARCHIVED })` executes unconditionally.
7. `emitTransactionStatusUpdate` fires, broadcasting `ARCHIVED` to every observer and signer.
8. The database now shows `ARCHIVED` for a transaction that was actually `EXECUTED` on the Hedera network.

The same path applies identically to `FAILED`, `EXPIRED`, and `CANCELED` statuses whenever `isManual=true`.

### Citations

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L720-730)
```typescript
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
```

**File:** back-end/apps/api/src/transactions/dto/create-transaction.dto.ts (L35-37)
```typescript
  @IsOptional()
  @IsBoolean()
  isManual?: boolean;
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

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L126-127)
```typescript
  @Column({ default: false })
  isManual: boolean;
```

**File:** back-end/apps/api/test/spec/transaction.e2e-spec.ts (L884-897)
```typescript
    it("(PATCH) should not archive a transaction if it's already executed", async () => {
      const transaction = addedTransactions.userTransactions[0];
      const oldStatus = transaction.status;
      await repo.update({ id: transaction.id }, { status: TransactionStatus.EXECUTED });

      const { status } = await endpoint.patch(null, transaction.id.toString(), userAuthToken);

      const transactionFromDb = await repo.findOne({ where: { id: transaction.id } });

      expect(status).toEqual(400);
      expect(transactionFromDb?.status).not.toEqual(TransactionStatus.ARCHIVED);

      await repo.update({ id: transaction.id }, { status: oldStatus });
    });
```
