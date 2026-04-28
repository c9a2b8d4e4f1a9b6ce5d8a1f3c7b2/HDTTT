### Title
Incorrect Logical Operator in `archiveTransaction` Guard Allows Archiving of Terminal-State Transactions

### Summary

`archiveTransaction` in `transactions.service.ts` uses `&&` in its guard condition instead of the correct logic, causing the status check to be completely bypassed whenever `transaction.isManual` is `true`. Any authenticated user who is the creator of a manual transaction can archive it regardless of its current status — including terminal states such as `EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, or `REJECTED` — corrupting the transaction state record.

### Finding Description

The guard in `archiveTransaction` is:

```typescript
// back-end/apps/api/src/transactions/transactions.service.ts, lines 711-718
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  ) &&
  !transaction.isManual
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
``` [1](#0-0) 

The condition throws only when **both** sub-expressions are true:
- `status NOT IN [WAITING_FOR_SIGNATURES, WAITING_FOR_EXECUTION]`
- `isManual === false`

When `isManual` is `true`, `!transaction.isManual` evaluates to `false`, making the entire `&&` expression `false`. The guard never throws, and execution falls through unconditionally to:

```typescript
await this.repo.update({ id }, { status: TransactionStatus.ARCHIVED });
``` [2](#0-1) 

This means a manual transaction in any terminal state (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `REJECTED`) can be transitioned to `ARCHIVED` by its creator via `PATCH /transactions/archive/:id`. [3](#0-2) 

The `terminalStatuses` array defined in the same service explicitly lists these as states that should not be further mutated:

```typescript
private readonly terminalStatuses = [
  TransactionStatus.EXECUTED,
  TransactionStatus.EXPIRED,
  TransactionStatus.FAILED,
  TransactionStatus.CANCELED,
  TransactionStatus.ARCHIVED,
  TransactionStatus.REJECTED,
];
``` [4](#0-3) 

The existing test suite only covers the case where `isManual` is `false` (or `undefined`) with a terminal status, which correctly throws. The case `isManual: true` + terminal status is untested and silently passes the guard. [5](#0-4) 

### Impact Explanation

A transaction creator can overwrite the status of a finalized transaction (e.g., `EXECUTED`) to `ARCHIVED`. This:
- Corrupts the audit trail and history view, since `ARCHIVED` is filtered differently from `EXECUTED`/`FAILED` in `getHistoryTransactions`
- Breaks any downstream logic or reporting that relies on terminal states being immutable
- Allows a user to hide an executed or failed transaction from the history by re-labeling it as `ARCHIVED` [6](#0-5) 

### Likelihood Explanation

The attacker is the transaction creator — a normal, unprivileged user. The preconditions are:
1. Create a transaction with `isManual: true` (a standard, documented feature)
2. Wait for it to reach any terminal state (e.g., `EXECUTED`, `CANCELED`)
3. Call `PATCH /transactions/archive/:id` with a valid auth token

No special access, leaked credentials, or race conditions are required. The endpoint is publicly reachable by any authenticated user for their own transactions. [3](#0-2) 

### Recommendation

Remove the `isManual` condition from the guard entirely, or restructure it so that the status check is always enforced regardless of `isManual`:

```typescript
// Correct: always enforce status check
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  )
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

If `isManual` is intended as an additional requirement (i.e., only manual transactions may be archived), use `||`:

```typescript
if (
  ![TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    transaction.status,
  ) ||
  !transaction.isManual
) {
  throw new BadRequestException(ErrorCodes.OMTIP);
}
```

Add a test case covering `isManual: true` with a terminal status (e.g., `EXECUTED`) to confirm the guard rejects it. [7](#0-6) 

### Proof of Concept

1. Authenticate as a normal user and create a transaction with `isManual: true`:
   ```
   POST /transactions  { ..., isManual: true }
   → 201 { id: 42, status: "WAITING_FOR_SIGNATURES" }
   ```
2. Allow the transaction to reach `EXECUTED` status (or manually set it in a test environment via the DB).
3. Call the archive endpoint:
   ```
   PATCH /transactions/archive/42
   Authorization: Bearer <user_token>
   → 200 true
   ```
4. Query the transaction:
   ```
   GET /transactions/42
   → { id: 42, status: "ARCHIVED" }   ← was EXECUTED
   ```

The guard at line 711–718 does not throw because `!transaction.isManual` (`!true`) is `false`, making the `&&` expression `false`, and the `repo.update` call at line 720 executes unconditionally. [8](#0-7)

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L981-1000)
```typescript
  /* Get the status where clause for the history transactions */
  private getHistoryStatusWhere(
    filtering: Filtering[],
  ): TransactionStatus | FindOperator<TransactionStatus> {
    const allowedStatuses = [
      TransactionStatus.EXECUTED,
      TransactionStatus.FAILED,
      TransactionStatus.EXPIRED,
      TransactionStatus.CANCELED,
      TransactionStatus.ARCHIVED,
    ];
    const forbiddenStatuses = Object.values(TransactionStatus).filter(
      s => !allowedStatuses.includes(s),
    );

    if (!filtering || filtering.length === 0) return Not(In([...forbiddenStatuses]));

    const statusFilter = filtering.find(f => f.property === 'status');

    if (!statusFilter) return Not(In([...forbiddenStatuses]));
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

**File:** back-end/apps/api/src/transactions/transactions.service.spec.ts (L1831-1883)
```typescript
  describe('archiveTransaction', () => {
    beforeEach(() => {
      jest.resetAllMocks();
    });

    it('should throw if transaction status is not archiveable', async () => {
      const transaction = {
        creatorKey: { userId: 1 },
        status: TransactionStatus.CANCELED,
      };

      jest
        .spyOn(service, 'getTransactionForCreator')
        .mockResolvedValueOnce(transaction as Transaction);

      await expect(service.archiveTransaction(123, { id: 1 } as User)).rejects.toThrow(
        ErrorCodes.OMTIP,
      );
    });

    it('should update transaction status to ARCHIVED and return true', async () => {
      const transaction = {
        id: 123,
        transactionId: '0.0.12345@1232351234.0123',
        creatorKey: { userId: 1 },
        isManual: true,
        status: TransactionStatus.WAITING_FOR_EXECUTION,
        mirrorNetwork: 'testnet',
      };

      jest
        .spyOn(service, 'getTransactionForCreator')
        .mockResolvedValueOnce(transaction as Transaction);

      const result = await service.archiveTransaction(123, { id: 1 } as User);

      expect(transactionsRepo.update).toHaveBeenCalledWith(
        { id: 123 },
        { status: TransactionStatus.ARCHIVED },
      );
      expect(result).toBe(true);
      expect(emitTransactionStatusUpdate).toHaveBeenCalledWith(
        notificationsPublisher,
        [{
          entityId: transaction.id,
          additionalData: {
            transactionId: expect.any(String),
            network: transaction.mirrorNetwork,
          },
        }],
      );
    });
  });
```
