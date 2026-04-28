### Title
Creator Can Archive Manual Transaction in Any Terminal State, Bypassing Status Invariants

### Summary
The `archiveTransaction` function in `transactions.service.ts` contains a logic flaw where the status guard is completely skipped for manual transactions (`isManual = true`). Any transaction creator can archive their own manual transaction regardless of its current status — including terminal states like `EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, and `REJECTED` — corrupting the off-chain audit trail and hiding true on-chain outcomes from other participants.

### Finding Description
The guard in `archiveTransaction` is a compound AND condition:

```typescript
// back-end/apps/api/src/transactions/transactions.service.ts L711-L718
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  ) &&
  !transaction.isManual
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

The exception is thrown only when **both** sub-conditions are true:
- status is NOT in `[WAITING_FOR_SIGNATURES, WAITING_FOR_EXECUTION]`
- AND the transaction is NOT manual

When `isManual = true`, the second operand is always `false`, making the entire condition `false`. The status check is **never evaluated** for manual transactions. The function then unconditionally writes `ARCHIVED`:

```typescript
// L720
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
```

The `PATCH /transactions/archive/:id` endpoint is reachable by any authenticated, verified user who is the creator of the transaction — no admin role required.

### Impact Explanation
A creator of a manual transaction can:
1. Execute the transaction on the Hedera network (status → `EXECUTED`)
2. Immediately call `PATCH /transactions/archive/:id`
3. The status is overwritten to `ARCHIVED`

Other participants (signers, observers, approvers) who rely on the off-chain record now see `ARCHIVED` instead of `EXECUTED`. The true on-chain outcome is hidden. The same applies to `FAILED`, `EXPIRED`, `CANCELED`, and `REJECTED` states — all can be silently overwritten to `ARCHIVED`, permanently corrupting the transaction audit trail.

### Likelihood Explanation
The attacker only needs to be a normal authenticated user who created a manual transaction. Manual transactions are a standard product feature (`isManual: true` in `CreateTransactionDto`). No privileged access, leaked credentials, or admin role is required. The endpoint is a standard `PATCH` call with no additional confirmation.

### Recommendation
Remove the `&& !transaction.isManual` short-circuit so the status