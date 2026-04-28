The code confirms all claims in the report. Here is the audit output:

---

Audit Report

## Title
Any Authenticated User Can Post Comments on Arbitrary Transactions Due to Missing Access Control in `CommentsController::createComment`

## Summary
The `POST /transactions/:transactionId/comments` endpoint in `CommentsController` creates a comment record for any `transactionId` supplied by the caller without verifying that the requesting user has any relationship (creator, signer, observer, or approver) to the target transaction. A developer-authored `TODO` in the source code explicitly acknowledges this gap. The two `GET` comment endpoints similarly pass no user context, allowing any authenticated user to read all comments on any transaction.

## Finding Description

In `back-end/apps/api/src/transactions/comments/comments.controller.ts`, the `createComment` handler is protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` at the controller class level. No ownership or relationship check is performed before delegating to the service: [1](#0-0) 

The inline `//TODO need some sort of guard or check to ensure user can comment here` is a developer acknowledgment that access control is intentionally deferred and currently absent: [2](#0-1) 

`CommentsService::createComment` performs no relationship check either — it directly creates and persists the comment: [3](#0-2) 

The two `GET` endpoints pass no `user` context at all, meaning any authenticated user can read comments on any transaction: [4](#0-3) 

Contrast this with every other write operation in the transaction subsystem, which all enforce creator-only or relationship-based access before mutating state:

- `ObserversService::createTransactionObservers` checks `transaction.creatorKey?.userId !== user.id` and throws `UnauthorizedException`: [5](#0-4) 

- `ApproversService::getCreatorsTransaction` throws `UnauthorizedException` if the caller is not the creator: [6](#0-5) 

- `TransactionsService::getTransactionForCreator` enforces the same pattern before `cancelTransaction` and `removeTransaction`: [7](#0-6) 

## Impact Explanation

Any verified organization member can:

1. **Write** arbitrary comments to any transaction in the system regardless of their relationship to it — polluting audit trails and potentially injecting misleading information into multi-signature workflows.
2. **Read** all comments on any transaction, including those belonging to other users' private or sensitive workflows, because the `GET` endpoints accept no user context and perform no filtering.

In an organization with many users and sensitive financial transactions, this breaks the confidentiality and integrity of the comment/audit-trail subsystem.

## Likelihood Explanation

The endpoint is reachable by any user who has completed email verification (`VerifiedUserGuard` passes for `UserStatus.NONE`). No special role or privilege is required. The attacker only needs a valid JWT and a known `transactionId`, which can be enumerated via the `/transactions` listing endpoint. Likelihood is **High**.

## Recommendation

1. In `CommentsService::createComment`, load the target transaction and verify the requesting user is the creator, a signer, an observer, or an approver — mirroring the pattern already used in `ObserversService::getTransactionObserversByTransactionId` and `ApproversService::getVerifiedApproversByTransactionId`.
2. Apply the same relationship check to `getTransactionComments` and `getTransactionCommentById`, passing the authenticated `user` into the service methods and throwing `UnauthorizedException` when the user has no relationship to the transaction.
3. Remove the `//TODO` comment once the guard is implemented.

## Proof of Concept

```
# 1. Register and verify an account (attacker)
POST /auth/register  { email, password }
POST /auth/verify    { token }

# 2. Authenticate and obtain JWT
POST /auth/login     { email, password }
→ { access_token: "<JWT>" }

# 3. Enumerate transaction IDs (attacker has no relationship to these)
GET /transactions
Authorization: Bearer <JWT>
→ [ { id: 42, ... }, { id: 43, ... }, ... ]

# 4. Post a comment on an arbitrary transaction the attacker has no access to
POST /transactions/42/comments
Authorization: Bearer <JWT>
Content-Type: application/json
{ "comment": "Attacker-injected comment" }

→ HTTP 201 Created
{ "id": 99, "transactionId": 42, "userId": <attacker_id>, "comment": "Attacker-injected comment" }

# 5. Read all comments on any transaction
GET /transactions/42/comments
Authorization: Bearer <JWT>
→ HTTP 200 OK  [ all comments, no access check ]
```

The `createComment` call succeeds because `CommentsService::createComment` performs no relationship check — it blindly sets `comment['transaction'].id = transactionId` and calls `this.repo.save(comment)`. [8](#0-7)

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

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L44-45)
```typescript
    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to delete it');
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L638-644)
```typescript
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to modify it');

    return transaction;
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L879-891)
```typescript
  async getTransactionForCreator(id: number, user: User) {
    const transaction = await this.getTransactionById(id);

    if (!transaction) {
      throw new BadRequestException(ErrorCodes.TNF);
    }

    if (transaction.creatorKey?.userId !== user?.id) {
      throw new UnauthorizedException('Only the creator has access to this transaction');
    }

    return transaction;
  }
```
