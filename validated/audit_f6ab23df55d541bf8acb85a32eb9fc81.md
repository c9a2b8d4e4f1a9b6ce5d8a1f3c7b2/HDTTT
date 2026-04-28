### Title
Any Authenticated User Can Post Comments on Any Transaction Without Ownership or Participation Check

### Summary
The `createComment` endpoint in `CommentsController` applies only authentication guards (JWT) at the controller level but performs no authorization check to verify that the requesting user has any relationship to the target transaction. Any authenticated organization member can post a comment on any transaction — including transactions they did not create, are not a signer of, are not an approver of, and are not an observer of. The developer explicitly acknowledged this gap with a `TODO` comment in the source.

### Finding Description

**Root cause:**

`CommentsController.createComment()` is protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` at the controller class level. No per-route guard or service-layer ownership check exists. [1](#0-0) 

The developer left an explicit acknowledgment of the missing check: [2](#0-1) 

`CommentsService.createComment()` performs no relationship verification — it blindly creates and persists the comment for any `(user, transactionId)` pair: [3](#0-2) 

**Contrast with protected endpoints:**

Other write operations on transactions do enforce ownership. For example, `ApproversService.createTransactionApprovers()` calls `getCreatorsTransaction()` which throws `UnauthorizedException` if the caller is not the transaction creator: [4](#0-3) [5](#0-4) 

No equivalent check exists anywhere in the comments path.

**Exploit path:**

1. Attacker registers as a normal organization user (no admin or special role required).
2. Attacker obtains a valid JWT via `POST /auth/login`.
3. Attacker enumerates or guesses any `transactionId` (integer IDs are sequential).
4. Attacker sends `POST /transactions/{transactionId}/comments` with arbitrary content.
5. The comment is persisted to the database and associated with the target transaction — a transaction the attacker has no legitimate relationship to.

### Impact Explanation

- **Unauthorized state mutation**: Any authenticated user can inject arbitrary comment records into any transaction's audit trail, corrupting the collaboration and review history that organization members rely on for high-stakes Hedera network operations.
- **Cross-tenant integrity violation**: The tool is designed for multi-user organizations where transactions are owned by specific creators and visible only to participants. The comment endpoint breaks this isolation boundary.
- **Harassment / confusion**: Malicious comments can mislead approvers or signers about the state or intent of a transaction, potentially influencing signing decisions.

### Likelihood Explanation

- **Preconditions**: Only a valid JWT from any registered organization user — no admin role, no special privilege.
- **Effort**: A single authenticated HTTP request. Transaction IDs are sequential integers, trivially enumerable.
- **Detection**: No existing guard or service check prevents or logs unauthorized comment attempts.

### Recommendation

Add a relationship check inside `CommentsService.createComment()` (or as a dedicated guard) that verifies the requesting user is one of: the transaction creator, a signer, an approver, or an observer — mirroring the pattern already used in `ApproversService.getVerifiedApproversByTransactionId()`: [6](#0-5) 

Resolve the existing `TODO` at: [7](#0-6) 

### Proof of Concept

```
# Step 1 — Login as any registered user (no admin required)
POST /auth/login
{ "email": "attacker@org.com", "password": "..." }
→ { "accessToken": "<JWT>" }

# Step 2 — Post a comment on a transaction the attacker has no relation to
POST /transactions/42/comments
Authorization: Bearer <JWT>
{ "content": "Injected comment on victim's transaction" }

→ HTTP 201 Created
  Comment is persisted in the database linked to transaction 42,
  visible to all participants of that transaction.
```

The attacker needs only a valid organization account. No elevated privileges are required. The comment is permanently stored and appears in the transaction's comment history retrieved by `GET /transactions/42/comments`, which is also unguarded. [8](#0-7)

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

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L31-34)
```typescript
  @Get()
  getComments(@Param('transactionId', ParseIntPipe) transactionId: number) {
    return this.commentsService.getTransactionComments(transactionId);
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L111-152)
```typescript
  async getVerifiedApproversByTransactionId(
    transactionId: number,
    user: User,
  ): Promise<TransactionApprover[]> {
    const transaction = await this.dataSource.manager.findOne(Transaction, {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user', 'observers', 'signers', 'signers.userKey'],
    });

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    const approvers = await this.getApproversByTransactionId(transactionId);

    const userKeysToSign = await userKeysRequiredToSign(
      transaction,
      user,
      this.transactionSignatureService,
      this.dataSource.manager,
    );

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

    return approvers;
  }
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
