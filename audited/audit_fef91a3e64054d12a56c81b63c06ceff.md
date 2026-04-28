### Title
Any Verified User Can Post Comments on Arbitrary Transactions Due to Missing Authorization Check

### Summary
The `createComment` endpoint in `CommentsController` allows any authenticated and verified user to post comments on any transaction by ID, regardless of whether they are the creator, signer, approver, or observer of that transaction. The code even contains a developer TODO acknowledging the missing check. Additionally, `getComments` and `getCommentById` expose all transaction comments to any authenticated user without verifying access rights to the underlying transaction.

### Finding Description
In `back-end/apps/api/src/transactions/comments/comments.controller.ts`, the `CommentsController` applies only authentication guards at the controller level (`JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard`). The `createComment` handler at line 22 carries an explicit developer note:

```
//TODO need some sort of guard or check to ensure user can comment here
``` [1](#0-0) 

No ownership or membership check is ever performed. The underlying `CommentsService.createComment` method receives the `transactionId` from the URL parameter and immediately creates and persists the comment without verifying that the calling user has any relationship to that transaction:

```typescript
async createComment(user, transactionId, dto) {
    const comment = this.repo.create(dto);
    comment['transaction'].id = transactionId;
    comment.user = user;
    return this.repo.save(comment);
}
``` [2](#0-1) 

The `getComments` (line 31) and `getCommentById` (line 36) handlers also accept no user context and perform no access check, returning comment data for any transaction ID to any authenticated caller: [3](#0-2) 

By contrast, every other state-modifying endpoint in the system (approvers, observers, signers) enforces creator-only or participant-only access at the service layer. For example, `observers.service.ts` explicitly checks `transaction.creatorKey?.userId !== user.id` before allowing updates: [4](#0-3) 

The comments subsystem is the sole exception.

### Impact Explanation
A malicious verified user (any user who has completed registration) can:

1. **Unauthorized state mutation**: POST arbitrary comments to any transaction ID in the system, including transactions belonging to other organizations or users they have no relationship with. This pollutes the transaction audit trail and comment history with unauthorized content.
2. **Information disclosure**: GET all comments for any transaction ID, potentially exposing sensitive business discussions, key identifiers, or operational details embedded in comments by legitimate participants.
3. **Transaction enumeration**: By iterating transaction IDs and observing whether a comment is accepted or an error is returned, an attacker can enumerate valid transaction IDs across the entire system.

### Likelihood Explanation
The attacker precondition is minimal: a valid, verified account on the organization backend. Any registered user who has completed the email verification flow satisfies this. No admin privileges, no leaked credentials, and no special knowledge are required. The attack path is a single authenticated HTTP POST to `/transactions/:transactionId/comments` with an arbitrary `transactionId`. The developer TODO comment confirms this was a known gap, making it likely to remain unaddressed without explicit remediation.

### Recommendation
In `CommentsService.createComment`, verify that the calling user is a participant of the target transaction (creator, signer, approver, or observer) before persisting the comment. Apply the same pattern used in `ObserversService.getUpdateableObserver` — fetch the transaction with its `creatorKey` relation and check membership. Similarly, `getTransactionComments` and `getTransactionCommentById` should verify the requesting user has access to the parent transaction before returning comment data.

### Proof of Concept

1. Register and verify two accounts: `attacker@example.com` and `victim@example.com`.
2. As `victim`, create a transaction (e.g., `POST /transactions`). Note the returned `id`, e.g., `42`.
3. As `attacker`, authenticate and obtain a JWT.
4. Send:
   ```
   POST /transactions/42/comments
   Authorization: Bearer <attacker_jwt>
   Content-Type: application/json

   { "content": "Unauthorized comment by attacker" }
   ```
5. Observe HTTP 201 response — the comment is persisted on victim's transaction.
6. Send `GET /transactions/42/comments` as `attacker` — all comments on victim's transaction are returned, including any sensitive content posted by legitimate participants. [5](#0-4) [6](#0-5)

### Citations

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L14-39)
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

  @Get()
  getComments(@Param('transactionId', ParseIntPipe) transactionId: number) {
    return this.commentsService.getTransactionComments(transactionId);
  }

  @Get('/:id')
  getCommentById(@Param('id', ParseIntPipe) id: number) {
    return this.commentsService.getTransactionCommentById(id);
  }
```

**File:** back-end/apps/api/src/transactions/comments/comments.service.ts (L15-37)
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

  // Get the transaction comment for the given id.
  getTransactionCommentById(id: number) {
    return this.repo.findOneBy({ id });
  }

  // Get the transaction comments for the given transaction id.
  getTransactionComments(transactionId: number) {
    return this.repo
      .createQueryBuilder('comment')
      .where('comment.transactionId = :transactionId', { transactionId })
      .getMany();
  }
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L156-158)
```typescript
    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to update it');

```
