All code references check out. The vulnerability is confirmed.

---

Audit Report

## Title
Any Verified User Can Post Comments on Transactions They Have No Access To

## Summary
`CommentsController` is protected only by `VerifiedUserGuard` at the class level. Neither the controller handler nor `CommentsService` performs any ownership or access check before writing or reading transaction comments. The developer acknowledged this gap with a `//TODO` comment. Every other transaction-scoped sub-resource (`observers`, `approvers`, `signers`) enforces the canonical access model (creator / signer / observer / approver); comments do not.

## Finding Description

`CommentsController` applies `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` at the class level — nothing more. [1](#0-0) 

The `createComment` handler passes control directly to `CommentsService.createComment`, which performs no access check — it creates and saves the comment unconditionally. [2](#0-1) 

`getComments` and `getCommentById` similarly carry no access check. [3](#0-2) 

By contrast, `TransactionsService.verifyAccess` defines the canonical access model used everywhere else: a user must be a creator, signer, observer, or approver to interact with a transaction. [4](#0-3) 

`ObserversService.getTransactionObserversByTransactionId` and `ApproversService.getVerifiedApproversByTransactionId` both enforce this model before returning data. [5](#0-4) [6](#0-5) 

## Impact Explanation
Any verified organization user who has no relationship to a transaction can:
1. **Write** — `POST /transactions/:transactionId/comments` posts arbitrary comments on any transaction in the system, constituting unauthorized write access to transaction data.
2. **Read** — `GET /transactions/:transactionId/comments` and `GET /transactions/comments/:id` expose all comments on any transaction, leaking potentially sensitive discussion or metadata.

This breaks the transaction visibility model enforced consistently across every other sub-resource in the codebase.

## Likelihood Explanation
Exploitation requires only a valid verified-user JWT and knowledge of a `transactionId` integer (trivially enumerable). No special privileges, race conditions, or complex setup are needed. The `//TODO need some sort of guard or check to ensure user can comment here` comment in the source confirms the gap was known and left unresolved. [7](#0-6) 

## Recommendation
Before writing or reading comments, call `TransactionsService.verifyAccess` (or `getTransactionWithVerifiedAccess`) to enforce the same creator / signer / observer / approver check used by every other transaction-scoped service. Concretely:

1. Inject `TransactionsService` into `CommentsService`.
2. In `createComment`, fetch the transaction and call `verifyAccess(transaction, user)`; throw `UnauthorizedException` if it returns `false`.
3. In `getTransactionComments`, apply the same check (pass the requesting `user` through from the controller).
4. Remove the `//TODO` comment once the check is in place.

## Proof of Concept
```
# Attacker has a valid JWT for user B, who has no relationship to transaction 42.
# Transaction 42 was created by user A.

# Write a comment on a transaction the attacker has no access to:
curl -X POST https://<host>/transactions/42/comments \
  -H "Authorization: Bearer <attacker_jwt>" \
  -H "Content-Type: application/json" \
  -d '{"message": "unauthorized comment"}'
# Returns 201 Created — comment is persisted.

# Read all comments on the same transaction:
curl https://<host>/transactions/42/comments \
  -H "Authorization: Bearer <attacker_jwt>"
# Returns 200 OK with full comment history.
```

### Citations

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L14-29)
```typescript
@ApiTags('Transaction Comments')
@Controller('transactions/:transactionId?/comments')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
//TODO add serializer
export class CommentsController {
  constructor(private commentsService: CommentsService) {}

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

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L31-39)
```typescript
  @Get()
  getComments(@Param('transactionId', ParseIntPipe) transactionId: number) {
    return this.commentsService.getTransactionComments(transactionId);
  }

  @Get('/:id')
  getCommentById(@Param('id', ParseIntPipe) id: number) {
    return this.commentsService.getTransactionCommentById(id);
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L786-808)
```typescript
  async verifyAccess(transaction: Transaction, user: User): Promise<boolean> {
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (
      [
        TransactionStatus.EXECUTED,
        TransactionStatus.EXPIRED,
        TransactionStatus.FAILED,
        TransactionStatus.CANCELED,
        TransactionStatus.ARCHIVED,
      ].includes(transaction.status)
    )
      return true;

    const userKeysToSign = await this.userKeysToSign(transaction, user, true);

    return (
      userKeysToSign.length !== 0 ||
      transaction.creatorKey?.userId === user.id ||
      !!transaction.observers?.some(o => o.userId === user.id) ||
      !!transaction.signers?.some(s => s.userKey?.userId === user.id) ||
      !!transaction.approvers?.some(a => a.userId === user.id)
    );
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L103-110)
```typescript
    if (
      userKeysToSign.length === 0 &&
      transaction.creatorKey?.userId !== user.id &&
      !transaction.observers.some(o => o.userId === user.id) &&
      !transaction.signers.some(s => s.userKey?.userId === user.id) &&
      !approvers.some(a => a.userId === user.id)
    )
      throw new UnauthorizedException("You don't have permission to view this transaction");
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L142-149)
```typescript
    if (
      userKeysToSign.length === 0 &&
      transaction.creatorKey?.userId !== user.id &&
      !transaction.observers.some(o => o.userId === user.id) &&
      !transaction.signers.some(s => s.userKey?.userId === user.id) &&
      !approvers.some(a => a.userId === user.id)
    )
      throw new UnauthorizedException("You don't have permission to view this transaction");
```
