Audit Report

## Title
Any Authenticated User Can Post Comments on Transactions They Have No Access To

## Summary
`CommentsController.createComment()` performs no per-transaction authorization check. Any registered, verified user can post comments on — and read comments from — any transaction, regardless of whether they are a creator, signer, observer, or approver of that transaction. The gap is self-documented in the source code with a `//TODO` comment.

## Finding Description
The `CommentsController` is protected at the class level by three guards: [1](#0-0) 

These guards verify only that the caller holds a valid, non-blacklisted JWT and has a verified account status. They do not verify any relationship between the caller and the target transaction.

The `createComment` handler explicitly acknowledges the missing check and proceeds to write the comment unconditionally: [2](#0-1) 

`CommentsService.createComment()` performs no access check either — it directly creates and persists the entity: [3](#0-2) 

The application already has a correct authorization primitive, `verifyAccess()`, which checks creator, signer, observer, and approver membership: [4](#0-3) 

This method is correctly applied in `getTransactionWithVerifiedAccess()` and `importSignatures()`, but is entirely absent from the comments path.

The `getComments` and `getCommentById` endpoints on the same controller are equally unprotected — they accept any authenticated request and return all comments for any transaction ID: [5](#0-4) 

## Impact Explanation
Any authenticated, verified user can:
1. **Write** comments on transactions they have no relationship to, polluting the audit trail and communication channel of sensitive multi-signature workflows.
2. **Read** all comments on any transaction, leaking internal deliberation, key management decisions, and operational context that should be restricted to transaction participants.

The comment thread is part of the transaction's collaborative workflow. Unauthorized writes break the integrity of that record; unauthorized reads break confidentiality.

## Likelihood Explanation
Exploitation requires only a valid JWT token — i.e., any registered, verified user in the organization. Transaction IDs are sequential integers (`@PrimaryGeneratedColumn()`), making enumeration trivial. No elevated privileges, race conditions, or special tooling are needed. A single authenticated HTTP `POST` to `/transactions/:transactionId/comments` with any integer `transactionId` suffices. [6](#0-5) 

## Recommendation
Before persisting a comment, call `TransactionsService.getTransactionWithVerifiedAccess(transactionId, user)` (or inline `verifyAccess()`) in `createComment`. Apply the same check to `getComments` and `getCommentById`. Inject `TransactionsService` into `CommentsService` (or `CommentsController`) to make this check available.

## Proof of Concept
```
# Step 1: Authenticate as any verified user and obtain a JWT
POST /auth/login
{ "email": "attacker@org.com", "password": "..." }
→ { "accessToken": "<JWT>" }

# Step 2: Post a comment on a transaction the attacker has no access to
POST /transactions/1/comments
Authorization: Bearer <JWT>
Content-Type: application/json
{ "message": "Injected comment on transaction 1" }
→ 201 Created  (no access check performed)

# Step 3: Read all comments on any transaction
GET /transactions/1/comments
Authorization: Bearer <JWT>
→ 200 OK  [ { "id": 1, "message": "...", ... } ]
```

The attacker only needs to increment the `transactionId` path parameter to target any transaction in the system.

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L786-809)
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
  }
```

**File:** back-end/libs/common/src/database/entities/transaction-comment.entity.ts (L6-11)
```typescript
export class TransactionComment {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => Transaction, transaction => transaction.comments)
  transaction: Transaction;
```
