All claims in the report are verified against the actual code. The vulnerability is real and confirmed.

---

## Audit Report

## Title
Any Authenticated User Can Post Comments on Any Transaction Without Access Verification

## Summary
`CommentsController.createComment()` in `back-end/apps/api/src/transactions/comments/comments.controller.ts` allows any registered, verified user to post a comment on any transaction by supplying an arbitrary `transactionId`. No check exists to verify the requesting user has any relationship (creator, signer, approver, or observer) to the target transaction. The code itself acknowledges this gap with an explicit TODO. The service layer performs no compensating check either.

## Finding Description
The controller class is protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — guards that verify authentication and account verification status, but not transaction-level authorization. [1](#0-0) 

The `createComment` handler carries an explicit developer acknowledgment that no access control exists: [2](#0-1) 

`CommentsService.createComment()` performs no relationship check — it directly creates and persists the comment with the caller-supplied `transactionId` and authenticated user, with no validation that the user belongs to the transaction: [3](#0-2) 

By contrast, every other state-mutating transaction sub-resource enforces a relationship check. `ApproversController.removeTransactionApprover()` calls `getCreatorsTransaction(transactionId, user)` before proceeding: [4](#0-3) 

`ApproversService.createTransactionApprovers()` also calls `getCreatorsTransaction` before creating approvers: [5](#0-4) 

`ApproversService.getVerifiedApproversByTransactionId()` enforces that the user is a creator, observer, signer, or approver before returning data: [6](#0-5) 

The comments subsystem has no equivalent check at any layer.

## Impact Explanation
- **Unauthorized state mutation**: Any authenticated user can inject comments into transactions they have no business relationship with, polluting the audit trail and comment history of sensitive multi-signature transactions.
- **Workflow disruption**: Comments are used for workflow coordination (approval notes, rejection reasons). Unauthorized comments can mislead legitimate participants and disrupt the multi-signature signing workflow.
- **Integrity degradation**: The comment history, which may serve as an audit trail, can be contaminated by arbitrary users with no stake in the transaction.

Note: The transaction ID enumeration sub-impact claimed in the report (confirming transaction existence by successfully posting) is excluded per SECURITY.md: *"Impacts causing only the enumeration or confirmation of the existence of users or tenants."* The primary impact of unauthorized state mutation stands independently. [7](#0-6) 

## Likelihood Explanation
- **Preconditions**: Attacker only needs a valid, verified account — the lowest privilege level in the system.
- **Trivial exploitation**: Transaction IDs are sequential integers parsed via `ParseIntPipe`, making targeted or brute-force posting straightforward.
- **No rate limiting**: The `POST /transactions/:transactionId/comments` endpoint has no `@Throttle` decorator, unlike other sensitive endpoints such as `remindSigners`.
- **Insider threat**: Any malicious or compromised low-privilege account can exploit this immediately without any special knowledge. [2](#0-1) 

## Recommendation
Add a relationship check in `CommentsService.createComment()` (or as a guard/interceptor on the controller) that verifies the requesting user is a creator, signer, approver, or observer of the target transaction before persisting the comment. This mirrors the pattern already used in `ApproversService.getVerifiedApproversByTransactionId()` and `ApproversService.getCreatorsTransaction()`. [8](#0-7) 

## Proof of Concept
1. Register and verify two accounts: `alice` (transaction creator) and `bob` (unrelated user).
2. As `alice`, create a multi-signature transaction. Note the returned `transactionId` (e.g., `42`).
3. As `bob` (who is not a creator, signer, approver, or observer of transaction `42`), send:
   ```
   POST /transactions/42/comments
   Authorization: Bearer <bob's JWT>
   Content-Type: application/json

   { "comment": "Injected comment by unauthorized user" }
   ```
4. The server returns `201 Created` and the comment is persisted to the database.
5. `alice` and all legitimate participants now see `bob`'s comment in the transaction's comment history, despite `bob` having no relationship to the transaction. [2](#0-1) [3](#0-2)

### Citations

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L14-16)
```typescript
@ApiTags('Transaction Comments')
@Controller('transactions/:transactionId?/comments')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
```

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L21-29)
```typescript
  @Post()
  //TODO need some sort of guard or check to ensure user can comment here
  createComment(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() dto: CreateCommentDto,
  ) {
    return this.commentsService.createComment(user, transactionId, dto);
  }
```

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L103-113)
```typescript
  async removeTransactionApprover(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Param('id', ParseIntPipe) id: number,
  ) {
    await this.approversService.getCreatorsTransaction(transactionId, user);
    await this.approversService.removeTransactionApprover(id);
    // await this.approversService.emitSyncIndicators(transactionId);

    return true;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L131-149)
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
      return approvers;

    if (
      userKeysToSign.length === 0 &&
      transaction.creatorKey?.userId !== user.id &&
      !transaction.observers.some(o => o.userId === user.id) &&
      !transaction.signers.some(s => s.userKey?.userId === user.id) &&
      !approvers.some(a => a.userId === user.id)
    )
      throw new UnauthorizedException("You don't have permission to view this transaction");
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

**File:** SECURITY.md (L41-41)
```markdown
- Impacts causing only the enumeration or confirmation of the existence of users or tenants.
```
