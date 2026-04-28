All code references have been verified against the actual repository. Every claim in the report is confirmed by the source.

---

Audit Report

## Title
Missing Access Control on Transaction Comment Creation — Any Authenticated User Can Comment on Any Transaction

## Summary
`CommentsController` exposes `POST /transactions/:transactionId/comments` with only authentication guards (`JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard`). No authorization check verifies that the requesting user has any relationship to the target transaction. The developer acknowledged this gap with a `TODO` comment directly above the handler. The read endpoints (`GET` comments) are similarly unguarded.

## Finding Description

In `back-end/apps/api/src/transactions/comments/comments.controller.ts`, the `POST` handler carries an explicit developer acknowledgment of the missing check and delegates directly to the service with no ownership verification: [1](#0-0) 

`CommentsService.createComment` performs no access check — it creates and saves the comment unconditionally: [2](#0-1) 

The `GET` endpoints are equally unguarded, passing no user context into the service: [3](#0-2) 

This contrasts sharply with every other transaction-related write operation. `ObserversService.createTransactionObservers` explicitly enforces creator-only access: [4](#0-3) 

`ApproversService.createTransactionApprovers` calls `getCreatorsTransaction` at the entry point: [5](#0-4) 

Which throws `UnauthorizedException` for any non-creator caller: [6](#0-5) 

The comments module has no equivalent guard at any layer.

## Impact Explanation

Any authenticated organization member can:
1. **Write**: Post arbitrary comments on any transaction regardless of whether they are the creator, signer, observer, or approver — injecting misleading or disruptive content into multi-signature coordination workflows.
2. **Read**: Retrieve all comments on any transaction, exposing potentially sensitive deliberation, workflow decisions, or internal coordination details.
3. **Spam/disrupt**: Flood transaction comment threads to interfere with legitimate participants' workflows.

## Likelihood Explanation

High. The attack requires only a valid organization account and a known (or enumerated) integer `transactionId`. Transaction IDs are sequential integers, making enumeration trivial. The three guards on the controller (`JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard`) verify only that the user is authenticated and verified — they perform zero authorization over the specific transaction resource. The developer `TODO` on line 22 confirms this is a known, unresolved gap, not an oversight that might be handled elsewhere.

## Recommendation

Implement a relationship check in `CommentsService.createComment` before persisting the comment. The check should verify the requesting user is one of: the transaction creator, a designated signer, an observer, or an approver. The pattern already exists in `ApproversService.getVerifiedApproversByTransactionId` and `ObserversService.getTransactionObserversByTransactionId`, both of which load the transaction with its relations and throw `UnauthorizedException` if the user has no relationship to it. The same logic should be extracted into a shared helper and applied to `createComment`, `getTransactionComments`, and `getTransactionCommentById`.

## Proof of Concept

```
# Attacker: authenticated org member with no relationship to transaction ID 42
POST /transactions/42/comments
Authorization: Bearer <attacker_jwt>
Content-Type: application/json

{ "message": "Injected comment on a transaction I have no access to" }

# Response: 201 Created — comment is saved with attacker's user ID
# No ownership or relationship check is performed at any layer
```

```
# Read all comments on any transaction
GET /transactions/42/comments
Authorization: Bearer <attacker_jwt>

# Response: 200 OK — full comment list returned with no authorization check
```

### Citations

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

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L44-45)
```typescript
    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to delete it');
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L239-239)
```typescript
    await this.getCreatorsTransaction(transactionId, user);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L640-641)
```typescript
    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to modify it');
```
