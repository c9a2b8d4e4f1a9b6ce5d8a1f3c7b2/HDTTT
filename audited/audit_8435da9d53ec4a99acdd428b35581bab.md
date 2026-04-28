### Title
`CommentsService.createComment()` Does Not Verify Transaction Existence Before Persisting Comment

### Summary
`CommentsService.createComment()` accepts a caller-supplied `transactionId` and immediately creates and saves a comment entity linked to it without first verifying the transaction exists. This is a direct analog of the external report: a state-mutating function operates on an unvalidated foreign-key reference. Every other transaction-related service in the codebase performs an explicit existence check; `createComment` is the sole exception.

### Finding Description
In `back-end/apps/api/src/transactions/comments/comments.service.ts` lines 15–24, `createComment()` takes `transactionId: number`, constructs a `TransactionComment` entity, sets `comment['transaction'].id = transactionId`, and calls `this.repo.save(comment)` — with no prior lookup to confirm the transaction row exists. [1](#0-0) 

Compare this to `ObserversService.createTransactionObservers()`, which explicitly fetches the transaction and throws `BadRequestException(ErrorCodes.TNF)` if it is absent: [2](#0-1) 

And `ApproversService.createTransactionApprovers()`, which delegates to `getCreatorsTransaction()` that also throws on a missing transaction: [3](#0-2) 

`createComment` performs neither an existence check nor an authorization check (it does not verify the calling user is a creator, signer, observer, or approver of the referenced transaction). All other write-path services enforce both invariants.

### Impact Explanation
**Orphaned record creation / database integrity corruption**: If the database schema does not enforce a foreign-key constraint on `transaction_comment.transactionId`, a comment row is persisted referencing a non-existent transaction, silently corrupting the database state. Subsequent queries that join `transaction_comment` to `transaction` will silently drop or mishandle these rows.

**Unhandled 500 propagation**: If a FK constraint does exist, the `repo.save()` call throws an unhandled database exception that propagates as an HTTP 500, leaking internal stack/schema details rather than returning a proper 400.

**Authorization bypass**: Because no access check is performed, any authenticated user can attach comments to any `transactionId` — including transactions they have no relationship to — bypassing the access-control model enforced uniformly by every other service.

### Likelihood Explanation
The precondition is a valid authentication token only — no privileged role is required. Any registered user can call the comment-creation endpoint with an arbitrary integer `trans

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

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L37-42)
```typescript
    const transaction = await this.entityManager.findOne(Transaction, {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user', 'observers'],
    });

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);
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
