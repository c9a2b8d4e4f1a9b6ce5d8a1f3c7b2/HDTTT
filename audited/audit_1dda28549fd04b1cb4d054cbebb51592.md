### Title
Misleading Error Message in `createTransactionObservers` References Wrong Operation ("delete" Instead of "add observers")

---

### Summary
The `createTransactionObservers` function in `observers.service.ts` throws an authorization error with the message `"Only the creator of the transaction is able to delete it"` — but the function is performing a **create** (add observers) operation, not a delete. This is a direct analog to the external report's finding of copy-paste/stale error messages that misrepresent the operation being guarded.

---

### Finding Description
In `back-end/apps/api/src/transactions/observers/observers.service.ts`, the `createTransactionObservers` method performs an authorization check to ensure only the transaction creator can add observers. When the check fails, it throws:

```typescript
throw new UnauthorizedException('Only the creator of the transaction is able to delete it');
``` [1](#0-0) 

The word **"delete"** is factually wrong here. The function is `createTransactionObservers` — it saves new `TransactionObserver` records to the database. [2](#0-1) 

By contrast, the `getUpdateableObserver` helper — which is called by both `updateTransactionObserver` and `removeTransactionObserver` — correctly says `"Only the creator of the transaction is able to update it"`. [3](#0-2) 

The misleading message in `createTransactionObservers` is clearly a copy-paste artifact from the delete/remove path.

---

### Impact Explanation
When a non-creator user attempts to add observers to a transaction, the API correctly rejects the request (the authorization logic itself is sound), but the error message returned to the caller says `"delete"`. This:

- Misleads API consumers and front-end developers into believing the endpoint they hit is a **delete** endpoint, not a **create** endpoint, making debugging significantly harder.
- Can cause incorrect incident triage: a developer seeing "delete" in an error log while investigating a failed observer-creation call will look in the wrong place.
- In a security audit or penetration test context, a misleading error message can mask the true access-control boundary, potentially causing reviewers to overlook or misclassify the guard.

---

### Likelihood Explanation
This code path is exercised every time a non-creator user calls the create-observers endpoint. The misleading message is always emitted in that scenario. It is not theoretical — it is the live error string returned by the API.

---

### Recommendation
Update line 45 of `observers.service.ts` to accurately describe the guarded operation:

```typescript
// Before (misleading)
throw new UnauthorizedException('Only the creator of the transaction is able to delete it');

// After (accurate)
throw new UnauthorizedException('Only the creator of the transaction is able to add observers to it');
``` [1](#0-0) 

---

### Proof of Concept

1. Create a transaction as User A.
2. Authenticate as User B (non-creator).
3. Call `POST /transactions/:id/observers` with a valid body.
4. Observe the `401 Unauthorized` response body:
   ```json
   { "message": "Only the creator of the transaction is able to delete it" }
   ```
5. The word "delete" appears in the response for a **create** request, confirming the misleading message is live and reachable without any special privileges. [4](#0-3)

### Citations

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L32-61)
```typescript
  async createTransactionObservers(
    user: User,
    transactionId: number,
    dto: CreateTransactionObserversDto,
  ): Promise<TransactionObserver[]> {
    const transaction = await this.entityManager.findOne(Transaction, {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user', 'observers'],
    });

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to delete it');

    const observers: TransactionObserver[] = [];

    for (const userId of dto.userIds) {
      if (!transaction.observers.some(o => o.userId === userId)) {
        const observer = this.repo.create({ userId, transactionId, role: Role.FULL });
        observers.push(observer);
      }
    }

    if (observers.length === 0) {
      return [];
    }

    try {
      const result = await this.repo.save(observers);
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L144-158)
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

```
