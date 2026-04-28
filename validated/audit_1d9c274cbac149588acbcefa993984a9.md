### Title
Missing Authorization Check on Transaction Comment Creation Allows Any Authenticated User to Comment on Arbitrary Transactions

### Summary
The `POST /transactions/:transactionId/comments` endpoint is protected only by JWT authentication guards but contains an explicit developer TODO acknowledging that no membership/relationship check exists. Any authenticated organization user can post comments on any transaction — including transactions they have no relationship to (not creator, observer, signer, or approver). The same endpoint also leaks comments to any authenticated user via `GET /transactions/:transactionId/comments`.

### Finding Description
In `back-end/apps/api/src/transactions/comments/comments.controller.ts`, the `createComment` handler carries a developer-left TODO:

```
//TODO need some sort of guard or check to ensure user can comment here
``` [1](#0-0) 

The controller applies only `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — all of which verify that the caller is a valid authenticated user, but none of which verify that the caller has any relationship to the target transaction. [2](#0-1) 

The underlying `CommentsService.createComment` performs no access check either — it directly creates and persists the comment: [3](#0-2) 

By contrast, every other sensitive transaction sub-resource (observers, approvers, transaction details) enforces a relationship check — verifying the requesting user is the creator, a signer, an observer, or an approver before granting access: [4](#0-3) 

The `GET /transactions/:transactionId/comments` and `GET /transactions/:transactionId/comments/:id` routes similarly have no access control, allowing any authenticated user to read comments on any transaction: [5](#0-4) 

### Impact Explanation
An authenticated organization user with no relationship to a transaction can:
1. **Write comments** on any transaction by ID, polluting the comment thread and potentially injecting misleading information into multi-sig approval workflows.
2. **Read all comments** on any transaction, leaking sensitive operational context (e.g., internal notes about key holders, approval rationale, financial details) that the transaction creator intended to restrict to participants.

### Likelihood Explanation
Exploitation requires only a valid JWT — obtainable by any registered organization user. The attacker needs only to enumerate or guess integer transaction IDs (sequential `id` values in the database) and issue a standard HTTP POST. No elevated privilege or special tooling is required.

### Recommendation
Add a relationship guard to `createComment` (and the `GET` routes) that verifies the requesting user is the transaction creator, a signer, an observer, or an approver — mirroring the pattern already used in `TransactionsService.verifyAccess`:

```typescript
// In CommentsService.createComment, before saving:
const hasAccess = await this.transactionsService.verifyAccess(transaction, user);
if (!hasAccess) throw new UnauthorizedException("You don't have permission to comment on this transaction");
```

Also resolve the `//TODO add serializer` note on the controller class to prevent unintended field exposure in comment responses. [6](#0-5) 

### Proof of Concept

1. Authenticate as any valid organization user and obtain a JWT.
2. Identify any transaction ID (e.g., `42`) belonging to a different user's workflow.
3. Issue:
   ```http
   POST /transactions/42/comments
   Authorization: Bearer <jwt>
   Content-Type: application/json

   { "message": "Attacker comment" }
   ```
4. The server responds `201 Created` and the comment is persisted, associated with the attacker's user account, on a transaction they have no legitimate access to.
5. Issue `GET /transactions/42/comments` with the same JWT to read all existing comments on that transaction — no relationship check is performed.

### Citations

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L14-18)
```typescript
@ApiTags('Transaction Comments')
@Controller('transactions/:transactionId?/comments')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
//TODO add serializer
export class CommentsController {
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
