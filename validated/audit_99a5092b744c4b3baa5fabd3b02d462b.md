### Title
Creator Can Archive Already-Executed Manual Transactions, Corrupting Audit Trail

### Summary
The `archiveTransaction` function in the backend API service performs a status check before updating a transaction's state to `ARCHIVED`, but the check is completely bypassed for manual transactions and the database update does not include a status guard in the `WHERE` clause. A malicious transaction creator can directly call the archive API endpoint to set an already-executed (or otherwise terminal-state) manual transaction to `ARCHIVED`, corrupting the organization's audit trail without any race condition required.

### Finding Description

**Root Cause — Missing Status Guard in `archiveTransaction`**

In `back-end/apps/api/src/transactions/transactions.service.ts`, the `archiveTransaction` function reads the transaction status, performs a conditional check, and then issues an unconditional `UPDATE`: [1](#0-0) 

The guard logic is:

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

For any **manual** transaction (`isManual = true`), the right-hand operand `!transaction.isManual` evaluates to `false`, making the entire `AND` expression `false`. The guard **never throws** for manual transactions, regardless of their current status (`EXECUTED`, `FAILED`, `EXPIRED`, `REJECTED`, etc.).

The subsequent update has no status condition in the `WHERE` clause:

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
```

Compare this to the correctly hardened `cancelTransactionWithOutcome`, which uses an atomic conditional update: [2](#0-1) 

```typescript
.andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
```

No such guard exists in `archiveTransaction`.

**Frontend Enforcement Is Insufficient**

The frontend correctly restricts the archive button to manual, in-progress transactions: [3](#0-2) 

```typescript
const canArchive = computed(() => {
  const isManual = props.organizationTransaction?.isManual;
  return isManual && isCreator.value && transactionIsInProgress.value;
});
```

`isInProgressStatus` explicitly excludes `EXECUTED`, `FAILED`, `EXPIRED`, and `REJECTED`: [4](#0-3) 

However, the backend does not enforce this invariant. Any authenticated user who is the transaction creator can call the archive API endpoint directly, bypassing the frontend guard entirely.

**Exploit Path (No Race Condition Required)**

1. Attacker registers as a normal organization user (no admin privileges needed).
2. Attacker creates a manual transaction and adds required signers/approvers.
3. Transaction collects signatures, reaches `WAITING_FOR_EXECUTION`, and is executed on the Hedera network — status becomes `EXECUTED`.
4. Attacker directly calls `PATCH /transactions/{id}/archive` via HTTP (bypassing the frontend).
5. Backend reads `transaction.status = EXECUTED`, evaluates the guard: `!isManual = false` → guard does not throw.
6. `repo.update({ id }, { status: TransactionStatus.ARCHIVED })` runs unconditionally.
7. The `EXECUTED` transaction is now recorded as `ARCHIVED` in the organization database.

**Secondary Issue — TOCTOU for Non-Manual Transactions**

For non-manual transactions in `WAITING_FOR_EXECUTION`, the guard passes (status is in the allowed list), but the update still has no status guard in the `WHERE` clause. If the chain service executes the transaction (moving it to `EXECUTED`) between the read and the update, the archive call overwrites `EXECUTED` with `ARCHIVED`. This is a classic TOCTOU race condition, though it requires precise timing.

### Impact Explanation

An executed Hedera transaction is immutable on-chain, but the organization's internal records are corrupted: the transaction appears as `ARCHIVED` rather than `EXECUTED`. Observers and auditors relying on the organization's transaction history will see a misleading record. A malicious creator can use this to conceal that a transaction was executed — for example, hiding an unauthorized fund transfer or account modification from post-hoc review. The state corruption is permanent unless an administrator manually corrects the database.

### Likelihood Explanation

**High for the manual transaction case.** No race condition, no privileged access, and no special timing is required. Any registered organization user who creates a manual transaction can exploit this by issuing a direct HTTP request after the transaction has been executed. The only precondition is being the creator of a manual transaction

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L673-679)
```typescript
    const updateResult = await this.repo
      .createQueryBuilder()
      .update(Transaction)
      .set({ status: TransactionStatus.CANCELED })
      .where('id = :id', { id })
      .andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
      .execute();
```

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

**File:** front-end/src/renderer/utils/transactionStatusGuards.ts (L3-5)
```typescript
export const isInProgressStatus = (status: TransactionStatus | null | undefined): boolean =>
  [TransactionStatus.NEW, TransactionStatus.WAITING_FOR_EXECUTION, TransactionStatus.WAITING_FOR_SIGNATURES]
    .includes(status as TransactionStatus);
```
