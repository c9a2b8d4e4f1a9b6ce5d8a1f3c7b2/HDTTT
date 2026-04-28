### Title
`isManual` Flag Bypasses Status Guard in `archiveTransaction`, Allowing Creators to Corrupt Terminal-State Transactions

### Summary
The `archiveTransaction` function in `transactions.service.ts` uses a compound boolean guard that is intended to restrict archiving to active (in-progress) manual transactions. Due to a logical flaw, the `isManual` flag completely bypasses the status check, allowing a transaction creator to archive a transaction that is already in a terminal state (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `REJECTED`). This is the direct analog of the external report: a flag controlling optional behavior (`isManual`) interacts with a state-transition guard in an unintended way, creating an exploitable path.

### Finding Description

**Root cause — `archiveTransaction`, lines 711–716:** [1](#0-0) 

```typescript
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

The error code `OMTIP` means **"Only Manual Transactions In Progress"** — confirming the developer's intent: only manual transactions that are currently in an active state should be archivable.

However, the guard is:

```
throw if (status NOT in active states) AND (isManual == false)
```

De Morgan's law: the guard **passes** (no throw) when:

```
(status IS in active states) OR (isManual == true)
```

The second branch — `isManual == true` — is unconditional on status. A creator of any `isManual=true` transaction can call `archiveTransaction` regardless of whether the transaction is `EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, or `REJECTED`. The `repo.update` on line 720 then overwrites the terminal status with `ARCHIVED`.

**Attacker-controlled entry path:**

1. Attacker (normal user) creates a transaction with `isManual: true` via `POST /transactions`.
2. The transaction proceeds through the normal lifecycle and reaches `EXECUTED` (or any other terminal state).
3. Attacker calls the archive endpoint (e.g., `PATCH /transactions/:id/archive`) as the creator.
4. `getTransactionForCreator` passes (attacker is the creator).
5. The `isManual` branch of the guard passes — no exception is thrown.
6. `repo.update({ id }, { status: TransactionStatus.ARCHIVED })` overwrites `EXECUTED` → `ARCHIVED`.

The `isManual` flag is set at creation time and is attacker-controlled: [2](#0-1) 

### Impact Explanation

- **Audit trail corruption**: The true terminal outcome (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `REJECTED`) is permanently overwritten with `ARCHIVED`. Other participants — signers, observers, approvers — who rely on the status to confirm the transaction's real outcome are misled.
- **State integrity violation**: The system's invariant that terminal states are immutable is broken. An `EXECUTED` transaction (confirmed on the Hedera network) can be relabeled `ARCHIVED` by its creator, hiding the fact that it was executed.
- **Cross-user impact**: Signers and observers have no ability to prevent or detect this change. The notification system will emit a status-update event, but the new status (`ARCHIVED`) gives no indication of the prior terminal state. [3](#0-2) 

### Likelihood Explanation

- **Preconditions**: The attacker must be the creator of a `isManual=true` transaction. This is a standard, unprivileged user action — no admin keys or special roles required.
- **Trigger**: A single API call to the archive endpoint after the transaction reaches any terminal state.
- **Detection difficulty**: The status change emits a notification, but the notification only signals a status update — it does not preserve or expose the prior status. Observers receive `ARCHIVED` with no record of the original terminal state in the notification payload. [4](#0-3) 

### Recommendation

Fix the guard to require **both** conditions simultaneously: the transaction must be `isManual=true` **and** in an active status. Replace the current compound condition with:

```typescript
const isActiveStatus = [
  TransactionStatus.WAITING_FOR_SIGNATURES,
  TransactionStatus.WAITING_FOR_EXECUTION,
].includes(transaction.status);

if (!transaction.isManual || !isActiveStatus) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

This enforces the documented intent: only manual transactions that are currently in progress may be archived. [5](#0-4) 

### Proof of Concept

**Steps:**

1. Authenticate as a normal user (User A).
2. Create a transaction with `isManual: true` and a `validStart` in the near future.
3. Have the required signers sign the transaction so it reaches `WAITING_FOR_EXECUTION`.
4. Wait for the chain service to execute it (or manually trigger execution), bringing it to `EXECUTED`.
5. As User A (creator), call `PATCH /transactions/{id}/archive`.

**Expected result (correct behavior):** `400 Bad Request` — transaction is already in a terminal state and cannot be archived.

**Actual result (vulnerable behavior):** `200 OK` — transaction status is updated from `EXECUTED` to `ARCHIVED` in the database. All other participants now see `ARCHIVED` instead of `EXECUTED`, with no record of the true outcome. [1](#0-0)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L449-452)
```typescript
            mirrorNetwork: data.mirrorNetwork,
            validStart: data.validStart,
            isManual: data.isManual,
            cutoffAt: data.cutoffAt,
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L639-648)
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L707-733)
```typescript
  /* Archive the transaction if the transaction is sign only. */
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
