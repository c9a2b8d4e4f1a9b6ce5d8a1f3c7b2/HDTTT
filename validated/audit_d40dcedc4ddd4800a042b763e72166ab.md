All four code claims in the report are verified against the actual source. Here is the audit report:

---

Audit Report

## Title
Any Verified User Can Post Comments on Arbitrary Transactions Due to Missing Authorization Check

## Summary
`CommentsController` and `CommentsService` apply no ownership or membership check before allowing any authenticated, verified user to create or read comments on any transaction by ID. A developer TODO in the controller explicitly acknowledges the gap. Every other participant-modifying subsystem (observers, approvers, signers) enforces creator or participant checks; the comments subsystem is the sole exception.

## Finding Description
`CommentsController` is decorated with `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` at the class level — these only confirm the caller is a valid, verified user, not that they have any relationship to the target transaction. [1](#0-0) 

The `createComment` handler at line 21–29 carries an explicit developer acknowledgement of the missing check: [2](#0-1) 

The underlying `CommentsService.createComment` immediately creates and persists the comment with no lookup of the transaction, no verification that the user is the creator, signer, approver, or observer: [3](#0-2) 

`getComments` and `getCommentById` accept no `user` parameter and perform no access check, returning comment data for any `transactionId` to any authenticated caller: [4](#0-3) [5](#0-4) 

By contrast, `ObserversService.createTransactionObservers` first fetches the transaction, then throws `UnauthorizedException` if `transaction.creatorKey?.userId !== user.id`: [6](#0-5) 

The same pattern is applied in `getTransactionObserversByTransactionId`, which checks creator, observer, signer, and approver membership before returning data: [7](#0-6) 

## Impact Explanation
1. **Unauthorized write**: Any verified user can `POST /transactions/:transactionId/comments` with an arbitrary `transactionId`, injecting comments into transactions they have no relationship with, polluting the audit trail.
2. **Information disclosure**: Any verified user can `GET /transactions/:transactionId/comments` and retrieve all comments for any transaction, potentially exposing sensitive business discussions or operational details embedded by legitimate participants.
3. **Transaction enumeration**: By iterating `transactionId` values and observing whether a comment is accepted or a database error is returned, an attacker can enumerate valid transaction IDs across the entire system.

## Likelihood Explanation
The attacker precondition is minimal: a valid, verified account. No admin privileges, no leaked credentials, and no special knowledge are required. The attack path is a single authenticated HTTP POST or GET to `/transactions/:transactionId/comments`. The developer TODO at line 22 confirms this was a known, unaddressed gap. [8](#0-7) 

## Recommendation
In `CommentsService.createComment`, before persisting the comment, fetch the target transaction and verify the calling user is the creator, a signer, an approver, or an observer — mirroring the pattern already used in `ObserversService` and `ApproversService`. Apply the same participant check in `getTransactionComments` and `getTransactionCommentById`. Remove the TODO once the check is in place.

## Proof of Concept
```
# Attacker has a valid verified JWT token but no relationship to transaction ID 999

# 1. Write an unauthorized comment
POST /transactions/999/comments
Authorization: Bearer <attacker_jwt>
Content-Type: application/json
{"message": "unauthorized comment"}
# → 201 Created — comment persisted with no ownership check

# 2. Read all comments on an arbitrary transaction
GET /transactions/999/comments
Authorization: Bearer <attacker_jwt>
# → 200 OK — full comment list returned with no access check

# 3. Enumerate valid transaction IDs
for id in $(seq 1 10000); do
  curl -s -o /dev/null -w "%{http_code} $id\n" \
    -X POST /transactions/$id/comments \
    -H "Authorization: Bearer <attacker_jwt>" \
    -H "Content-Type: application/json" \
    -d '{"message":"probe"}'
done
# 201 responses reveal valid transaction IDs; errors reveal invalid ones
```

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

**File:** back-end/apps/api/src/transactions/comments/comments.service.ts (L27-37)
```typescript
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
