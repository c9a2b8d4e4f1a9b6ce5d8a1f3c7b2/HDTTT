All code references have been verified against the actual repository. The claims are accurate.

---

# Audit Report

## Title
Observers and Approvers Can Be Added to Terminal-State Transactions

## Summary
`ObserversService.createTransactionObservers`, `ApproversService.createTransactionApprovers`, `updateTransactionApprover`, `removeTransactionApprover`, `updateTransactionObserver`, and `removeTransactionObserver` perform no check on `transaction.status` before persisting mutations. A transaction creator can therefore add, update, or remove observers and approvers on transactions already in a terminal state (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `ARCHIVED`), violating the state-machine invariant that terminal transactions are immutable.

## Finding Description

**Root cause — `createTransactionObservers`**

`ObserversService.createTransactionObservers` fetches the transaction and applies exactly two guards before saving new `TransactionObserver` rows: [1](#0-0) 

There is no `transaction.status` check. A transaction with status `EXECUTED`, `CANCELED`, `FAILED`, `EXPIRED`, or `ARCHIVED` passes both guards and new observers are persisted. [2](#0-1) 

**Root cause — `createTransactionApprovers`**

`ApproversService.createTransactionApprovers` delegates its authorization entirely to `getCreatorsTransaction`: [3](#0-2) 

`getCreatorsTransaction` only checks existence and creator identity — no status guard: [4](#0-3) 

**Root cause — `updateTransactionObserver` / `removeTransactionObserver`**

Both delegate to `getUpdateableObserver`, which again only checks existence and creator identity, with no status guard: [5](#0-4) 

**Root cause — `removeTransactionApprover`**

`removeTransactionApprover` fetches the approver and removes it with no transaction status check: [6](#0-5) 

**Contrast with correct guards elsewhere**

`approveTransaction` correctly rejects non-active states: [7](#0-6) 

**Terminal-state short-circuit access control**

`getTransactionObserversByTransactionId` short-circuits access control for terminal transactions, returning the full observer list to any user who appears in it: [8](#0-7) 

This means a newly injected observer on a terminal transaction immediately gains unrestricted access to the full observer list.

## Impact Explanation

- **Audit-trail corruption**: Observer and approver lists for a terminal transaction are part of its immutable historical record. Post-execution mutation breaks the integrity of that record.
- **Unauthorized access grant**: Adding an observer to a terminal transaction causes the short-circuit access-control path (lines 92–101 of `observers.service.ts`) to return the full observer list to the newly added user, granting visibility they should not receive after the transaction closed.
- **Notification spam / confusion**: `emitTransactionUpdate` is called on every successful observer addition (line 63 of `observers.service.ts`), sending real-time notifications about already-closed transactions, which can mislead users and downstream consumers.
- **Approver record manipulation**: Approvers can be added to or removed from already-executed transactions, retroactively altering who was recorded as an approver.

## Likelihood Explanation

The attacker precondition is minimal: any authenticated user who is the creator of at least one transaction. No privileged role is required. The endpoint `POST /transactions/:transactionId/observers` is a standard REST call reachable by any creator. The transaction's terminal status is never surfaced as a rejection reason, so the operation succeeds silently. This is a straightforward, low-effort call that any creator can make at any time after their transaction closes.

## Recommendation

Add a terminal-state guard in each mutating path. The set of terminal statuses is already well-defined and used consistently elsewhere in the codebase:

1. **`createTransactionObservers`** — after the existence/creator checks (line 44), add:
   ```ts
   const TERMINAL = [
     TransactionStatus.EXECUTED, TransactionStatus.FAILED,
     TransactionStatus.EXPIRED, TransactionStatus.CANCELED,
     TransactionStatus.ARCHIVED,
   ];
   if (TERMINAL.includes(transaction.status))
     throw new BadRequestException('Cannot modify a terminal transaction');
   ```
2. **`getCreatorsTransaction`** — add the same guard so all callers (`createTransactionApprovers`, `updateTransactionApprover`) inherit it automatically.
3. **`getUpdateableObserver`** — add the same guard so `updateTransactionObserver` and `removeTransactionObserver` inherit it.
4. **`removeTransactionApprover`** — fetch the parent transaction and add the same guard before calling `removeNode`.

## Proof of Concept

1. Authenticated creator creates a transaction; it reaches `EXECUTED`.
2. Creator calls:
   ```
   POST /transactions/{id}/observers
   { "userIds": [victimId] }
   ```
3. `createTransactionObservers` passes both guards (transaction exists, caller is creator) and persists the new `TransactionObserver` row.
4. `emitTransactionUpdate` fires, sending a spurious notification to the victim.
5. The victim now appears in the observer list of a terminal transaction, corrupting the immutable audit record.
6. Because `getTransactionObserversByTransactionId` short-circuits access control for terminal transactions (lines 92–101 of `observers.service.ts`), the newly added observer can immediately call `GET /transactions/{id}/observers` and receive the full observer list without any further authorization check.

### Citations

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L42-45)
```typescript
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to delete it');
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L60-65)
```typescript
    try {
      const result = await this.repo.save(observers);

      emitTransactionUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);

      return result;
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L92-101)
```typescript
    if (
      [
        TransactionStatus.EXECUTED,
        TransactionStatus.EXPIRED,
        TransactionStatus.FAILED,
        TransactionStatus.CANCELED,
        TransactionStatus.ARCHIVED,
      ].includes(transaction.status)
    )
      return transaction.observers;
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L144-160)
```typescript
  private async getUpdateableObserver(id: number, user: User): Promise<TransactionObserver> {
    const observer = await this.repo.findOneBy({ id });

    if (!observer) throw new BadRequestException(ErrorCodes.ONF);

    const transaction = await this.entityManager.findOne(Transaction, {
      where: { id: observer.transactionId },
      relations: ['creatorKey', 'creatorKey.user'],
    });

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to update it');

    return observer;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-240)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);

```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L534-544)
```typescript
  async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);

    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const result = await this.removeNode(approver.id);

    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);

    return result;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L583-589)
```typescript
    /* Checks if the transaction is requires approval */
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);

```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L624-644)
```typescript
  async getCreatorsTransaction(
    transactionId: number,
    user: User,
    entityManager?: EntityManager,
  ): Promise<Transaction> {
    const find: FindOneOptions<Transaction> = {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user'],
    };

    const transaction = await (entityManager
      ? entityManager.findOne(Transaction, find)
      : this.dataSource.manager.findOne(Transaction, find));

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to modify it');

    return transaction;
  }
```
