### Title
Any Authenticated User Can Remove Any Transaction Approver Without Ownership Verification

### Summary
`ApproversService.removeTransactionApprover()` accepts only an approver `id`, verifies only that the approver record exists, and never checks whether the calling user is the creator/owner of the parent transaction. This is the direct analog of the external `VestedZeroNFT::split()` bug: a function that performs an existence check but not a caller-identity check, allowing any authenticated user to delete any approver from any transaction they do not own.

### Finding Description

**Root cause — missing caller check in `removeTransactionApprover`**

```
back-end/apps/api/src/transactions/approvers/approvers.service.ts
lines 533-544
```

```typescript
async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);   // existence only
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);
    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(...);
    return result;
}
```

The function signature takes **no `user` parameter**. `getTransactionApproverById` only confirms the record exists — it never compares the caller's identity to the transaction's `creatorKey.userId`. [1](#0-0) 

**Contrast with every other mutating operation in the same service**, which all call `getCreatorsTransaction(transactionId, user)` first:

```typescript
// createTransactionApprovers — line 239
await this.getCreatorsTransaction(transactionId, user);

// getTransactionForCreator — lines 879-891
if (transaction.creatorKey?.userId !== user?.id)
    throw new UnauthorizedException('Only the creator has access to this transaction');
``` [2](#0-1) [3](#0-2) 

**Exploit path:**

1. Attacker registers a normal account (no privileges required).
2. Attacker authenticates and obtains a JWT — passes `JwtAuthGuard` and `VerifiedUserGuard`.
3. Attacker enumerates or guesses approver IDs (sequential integers in a PostgreSQL auto-increment column).
4. Attacker calls `DELETE /transactions/approvers/:id` for any approver ID.
5. `removeTransactionApprover(id)` is invoked with no user context; the approver is deleted unconditionally.
6. The approval threshold for the victim's transaction is now broken or entirely removed, allowing the transaction to proceed without the required approvals.

### Impact Explanation

- **Approval workflow bypass**: An attacker can strip all approvers from any pending transaction, collapsing a multi-party approval requirement to zero.
- **Unauthorized transaction execution**: Once approvers are removed, the transaction can advance to `WAITING_FOR_EXECUTION` or be manually executed by its creator without the intended governance controls.
- **Cross-tenant integrity break**: Any user can tamper with any other user's transaction approver tree, violating the isolation invariant of the organization workflow. [1](#0-0) 

### Likelihood Explanation

- **Precondition**: Only a valid JWT (any registered user). No admin role, no leaked secrets.
- **Approver IDs** are sequential database integers — trivially enumerable by incrementing from 1.
- The endpoint is reachable via the standard REST API protected only by `JwtAuthGuard` + `VerifiedUserGuard`, both of which any registered user satisfies.
- No rate-limiting or anomaly detection is visible on this path. [4](#0-3) 

### Recommendation

Add a `user: User` parameter to `removeTransactionApprover` and resolve the parent transaction before deletion, then assert the caller is the creator — exactly as every other mutating method does:

```typescript
async removeTransactionApprover(id: number, user: User): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    // Resolve the root transaction and verify ownership
    const root = await this.getRootNodeFromNode(id);
    await this.getCreatorsTransaction(root.transactionId, user); // throws if not creator

    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
    return result;
}
```

The controller endpoint must also be updated to pass `@GetUser() user` to the service call. [3](#0-2) 

### Proof of Concept

**Preconditions**: Two registered users — Alice (transaction creator) and Bob (attacker). Alice has created a transaction with an approver record (approver `id = 1`).

```
# Step 1 — Bob authenticates
POST /auth/login  { email: "bob@example.com", password: "..." }
→ { access_token: "<BOB_JWT>" }

# Step 2 — Bob deletes Alice's approver (no ownership check)
DELETE /transactions/approvers/1
Authorization: Bearer <BOB_JWT>

→ HTTP 200 OK   (approver deleted, Alice's approval requirement destroyed)
```

**Expected (correct) behaviour**: HTTP 401/403 — "Only the creator of the transaction is able to modify it."

**Actual behaviour**: HTTP 200 — approver deleted unconditionally, approval workflow bypassed. [1](#0-0)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-240)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);

```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L533-544)
```typescript
  /* Removes the transaction approver by id */
  async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);

    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const result = await this.removeNode(approver.id);

    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);

    return result;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L623-644)
```typescript
  /* Get the transaction by id and verifies that the user is the creator */
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

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L54-57)
```typescript
@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
```
