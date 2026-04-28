### Title
Missing Transaction Existence and Authorization Check in `createComment` Allows Any Authenticated User to Post Comments on Arbitrary Transactions

### Summary
The `createComment` function in `CommentsService` accepts a caller-supplied `transactionId` and immediately persists a comment without verifying that the transaction exists or that the requesting user has any relationship to it. Every other write path in the same codebase performs both checks; `createComment` skips them entirely. Any authenticated user can post comments on any transaction in the system.

### Finding Description
`createComment` in `back-end/apps/api/src/transactions/comments/comments.service.ts` (lines 15–24):

```typescript
async createComment(
  user: User,
  transactionId: number,
  dto: CreateCommentDto,
): Promise<TransactionComment> {
  const comment = this.repo.create(dto);
  comment['transaction'].id = transactionId;
  comment.user = user;
  return this.repo.save(comment);   // no existence check, no authz check
}
```

The function:
1. Does **not** query the database to confirm a `Transaction` row with `id = transactionId` exists.
2. Does **not** verify the calling user is a creator, signer, observer, or approver of that transaction.

Every analogous write path in the same service layer performs both checks:

- `ObserversService.createTransactionObservers` fetches the transaction and throws `ErrorCodes.TNF` if absent, then asserts `creatorKey.userId === user.id`.
- `ApproversService.createTransactionApprovers` delegates to `getCreatorsTransaction`, which throws `ErrorCodes.TNF` on a missing transaction and `UnauthorizedException` if the caller is not the creator.
- `TransactionsService.getTransactionForCreator` (used by cancel/archive/execute) performs the same two-step guard.

`createComment` is the only write path that omits both guards.

**Exploit path:**
1. Attacker authenticates as any valid user (User A) who has no relationship to Transaction T owned by User B.
2. Attacker sends `POST /transactions/{T.id}/comments` with arbitrary comment text.
3. `createComment` is called with `transactionId = T.id`; no check is performed.
4. The comment is persisted and associated with Transaction T.
5. All legitimate participants of Transaction T (creator, signers, observers, approvers) now see a comment injected by an unauthorized party.

If `transactionId` references a non-existent row and the database enforces a foreign-key constraint, the unhandled DB exception propagates as an unmasked 500 response, leaking internal error details. If no FK constraint is enforced, an orphaned comment row is silently created.

### Impact Explanation
- **Unauthorized state modification**: Any authenticated user can inject comments into transactions they have no legitimate access to, polluting the audit trail and communication channel for every transaction in the system.
- **Information leakage**: Comment content written by legitimate participants may be visible to the commenter; an attacker who can write to a transaction can probe which IDs exist and observe any response-level data.
- **Integrity degradation**: The comment history, which may be used for compliance or coordination, can be corrupted by arbitrary users.

### Likelihood Explanation
Exploitation requires only a valid session token — no elevated privileges, no leaked credentials, no special network position. Transaction IDs are sequential integers, making enumeration trivial. The attack is fully reachable via the normal REST API surface.

### Recommendation
Add the same two-step guard used by every other write service before persisting the comment:

```typescript
async createComment(
  user: User,
  transactionId: number,
  dto: CreateCommentDto,
): Promise<TransactionComment> {
  const transaction = await this.repo.manager.findOne(Transaction, {
    where: { id: transactionId },
    relations: ['creatorKey', 'observers', 'signers', 'signers.userKey'],
  });
  if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

  // Verify the user has a relationship to this transaction
  const isParticipant =
    transaction.creatorKey?.userId === user.id ||
    transaction.observers?.some(o => o.userId === user.id) ||
    transaction.signers?.some(s => s.userKey?.userId === user.id);
  if (!isParticipant) throw new UnauthorizedException(...);

  const comment = this.repo.create(dto);
  comment['transaction'].id = transactionId;
  comment.user = user;
  return this.repo.save(comment);
}
```

### Proof of Concept
**Preconditions**: Two accounts exist — `userA` (attacker, no relation to any transaction) and `userB` (creator of transaction with `id = 42`).

1. Authenticate as `userA`, obtain JWT.
2. `POST /transactions/42/comments` with body `{ "message": "injected comment" }` and `Authorization: Bearer <userA-token>`.
3. Response: `201 Created` — comment is persisted.
4. Authenticate as `userB`, fetch transaction 42 comments.
5. `userA`'s comment appears in the list, confirming unauthorized write succeeded.

**Root cause reference:** [1](#0-0) 

**Contrast with guarded paths:** [2](#0-1) [3](#0-2)

### Citations

**File:** back-end/apps/api/src/transactions/comments/comments.service.ts (L15-24)
```typescript
  async createComment(
    user: User,
    transactionId: number,
    dto: CreateCommentDto,
  ): Promise<TransactionComment> {
    const comment = this.repo.create(dto);
    comment['transaction'].id = transactionId;
    comment.user = user;
    return this.repo.save(comment);
  }
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L37-45)
```typescript
    const transaction = await this.entityManager.findOne(Transaction, {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user', 'observers'],
    });

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to delete it');
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-239)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);
```
