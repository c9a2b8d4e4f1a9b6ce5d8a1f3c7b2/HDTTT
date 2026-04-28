### Title
`removeTransaction()` Lacks Status Guard, Allowing Creators to Overwrite Terminal Transaction States

### Summary
`TransactionsService.removeTransaction()` performs no status check before forcibly overwriting a transaction's status to `CANCELED` and soft-deleting the record. Unlike `cancelTransaction()`, which explicitly enforces a `cancelableStatuses` allowlist, `removeTransaction()` accepts any transaction in any state — including terminal states (`EXECUTED`, `FAILED`, `EXPIRED`, `REJECTED`, `ARCHIVED`). Any authenticated user who is the creator of a transaction can call `DELETE /transactions/:id` to corrupt the audit trail of an already-executed or otherwise finalized transaction.

### Finding Description

**Root cause — missing state guard in `removeTransaction()`:**

`cancelTransaction()` correctly enforces a status allowlist: [1](#0-0) [2](#0-1) 

`removeTransaction()` performs no equivalent check: [3](#0-2) 

The function only verifies creator ownership via `getTransactionForCreator`, then unconditionally:
1. Overwrites `status` → `CANCELED` (line 633)
2. Soft-deletes the record (line 634)
3. Emits a status-update notification with the corrupted state (lines 639–648)

**Exposed endpoint:** [4](#0-3) 

This is a standard authenticated REST endpoint — no elevated role is required beyond being the transaction creator.

**Contrast with the correct pattern:**

`cancelTransactionWithOutcome()` uses both an in-memory status check and a conditional `WHERE status IN (...)` clause in the UPDATE query, making it race-safe and state-safe: [5](#0-4) 

`removeTransaction()` has neither guard.

### Impact Explanation

A creator can call `DELETE /transactions/:id` on a transaction whose status is `EXECUTED`, `FAILED`, `EXPIRED`, `REJECTED`, or `ARCHIVED`. The result:

- The database record's `status` is overwritten from its true terminal value to `CANCELED`, permanently corrupting the audit trail.
- The record is soft-deleted (`deletedAt` set), hiding it from normal queries for all participants (observers, signers).
- A `TRANSACTION_STATUS_UPDATE` notification is broadcast to all subscribers with the false `CANCELED` status, propagating the corrupted state system-wide.
- Observers and signers — who have a legitimate interest in the true outcome — lose visibility into whether the transaction was actually executed on the Hedera network.

The on-chain Hedera state is unaffected, but the off-chain record of what happened is permanently falsified. This is an unauthorized state mutation and audit-trail integrity violation.

### Likelihood Explanation

- **Attacker profile:** Any authenticated, verified user who created a transaction. No admin or privileged role is required.
- **Precondition:** The attacker must be the creator of the target transaction (enforced by `getTransactionForCreator`).
- **Trigger:** A single `DELETE /transactions/:id` HTTP request after the transaction reaches a terminal state.
- **Detectability:** Low — the soft-delete hides the record from normal queries; the notification system actively propagates the false state, making it appear legitimate.

### Recommendation

Add a status guard to `removeTransaction()` that mirrors the pattern in `cancelTransactionWithOutcome()`. Reject the operation if the transaction is in a terminal state:

```typescript
async removeTransaction(id: number, user: User, softRemove: boolean = true): Promise<boolean> {
  const transaction = await this.getTransactionForCreator(id, user);

  // Guard: do not allow deletion of terminal-state transactions
  const terminalStatuses = [
    TransactionStatus.EXECUTED,
    TransactionStatus.FAILED,
    TransactionStatus.EXPIRED,
    TransactionStatus.REJECTED,
    TransactionStatus.ARCHIVED,
  ];
  if (terminalStatuses.includes(transaction.status)) {
    throw new BadRequestException(ErrorCodes.OTIP); // or a dedicated error code
  }

  // ... rest of the function
}
```

Alternatively, if deletion of terminal-state records is intentionally allowed (e.g., for cleanup), the status must **not** be overwritten to `CANCELED` — the original terminal status should be preserved in the soft-delete path.

### Proof of Concept

1. Authenticate as a normal user (creator of a transaction).
2. Wait for (or observe) a transaction to reach `EXECUTED` status.
3. Send: `DELETE /transactions/{id}` with a valid JWT.
4. **Expected (correct) behavior:** `400 Bad Request` — terminal state cannot be deleted.
5. **Actual behavior:** `200 OK` — the transaction's status is overwritten to `CANCELED`, the record is soft-deleted, and a `CANCELED` status-update notification is broadcast to all observers and signers. [6](#0-5) [4](#0-3)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L92-96)
```typescript
  private readonly cancelableStatuses = [
    TransactionStatus.NEW,
    TransactionStatus.WAITING_FOR_SIGNATURES,
    TransactionStatus.WAITING_FOR_EXECUTION,
  ];
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L628-651)
```typescript
  /* Remove the transaction for the given transaction id. */
  async removeTransaction(id: number, user: User, softRemove: boolean = true): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);

    if (softRemove) {
      await this.repo.update(transaction.id, { status: TransactionStatus.CANCELED });
      await this.repo.softRemove(transaction);
    } else {
      await this.repo.remove(transaction);
    }

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L665-679)
```typescript
    if (transaction.status === TransactionStatus.CANCELED) {
      return CancelTransactionOutcome.ALREADY_CANCELED;
    }

    if (!this.cancelableStatuses.includes(transaction.status)) {
      throw new BadRequestException(ErrorCodes.OTIP);
    }

    const updateResult = await this.repo
      .createQueryBuilder()
      .update(Transaction)
      .set({ status: TransactionStatus.CANCELED })
      .where('id = :id', { id })
      .andWhere('status IN (:...statuses)', { statuses: this.cancelableStatuses })
      .execute();
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L313-316)
```typescript
  @Delete('/:id')
  deleteTransaction(@GetUser() user, @Param('id', ParseIntPipe) id: number): Promise<boolean> {
    return this.transactionsService.removeTransaction(id, user, true);
  }
```
