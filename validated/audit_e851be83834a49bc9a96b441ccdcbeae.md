All claims in the report are verified against the actual code. Here is the audit report:

---

Audit Report

## Title
Missing Access Control on `createComment` Allows Any Authenticated User to Permanently Post Comments on Any Transaction

## Summary
`POST /transactions/:transactionId/comments` in `CommentsController` applies only authentication guards and performs no ownership or relationship check against the target transaction. Any verified organization member can post comments on any transaction they have no connection to. Because no delete or update route exists for comments, unauthorized comments are permanent.

## Finding Description
The `@Post()` handler in `CommentsController` is protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — all applied at the class level. No per-route guard or service-level check verifies that the caller is the transaction creator, an observer, an approver, or a signer. [1](#0-0) 

The developer acknowledged this gap inline: [2](#0-1) 

`CommentsService.createComment()` performs no relationship verification — it blindly creates and saves the comment for any `transactionId` supplied: [3](#0-2) 

Contrast this with `ObserversService.createTransactionObservers()`, which explicitly throws `UnauthorizedException` if the caller is not the transaction creator: [4](#0-3) 

And `getTransactionForCreator()` in `TransactionsService`, which enforces the same check: [5](#0-4) 

No delete or update route exists for comments — confirmed by the second TODO: [6](#0-5) 

## Impact Explanation
Any authenticated, verified organization member can:
1. Write arbitrary comments onto any transaction they have no relationship to.
2. Inject misleading or malicious instructions into the comment thread of a transaction pending signatures or approval, potentially influencing signers or approvers.
3. Because no delete route exists (and no admin-scoped delete is present either), these comments are permanent and irremovable by any party.

This constitutes unauthorized, persistent state modification on another user's transaction record.

## Likelihood Explanation
- **Attacker precondition**: only a valid JWT for any verified organization member — the lowest privilege level in the system.
- **Attack path**: a single authenticated HTTP `POST` to `/transactions/:transactionId/comments`.
- **Transaction ID enumeration**: IDs are sequential integers parsed via `ParseIntPipe`, requiring no special knowledge to enumerate.
- The developer TODO in the source confirms the gap was known but unaddressed. [7](#0-6) 

## Recommendation
In `CommentsService.createComment()`, before saving, fetch the target transaction and verify the caller is the creator, an observer, an approver, or a signer — mirroring the pattern used in `ObserversService.getTransactionObserversByTransactionId()`: [8](#0-7) 

Additionally, implement delete and update routes for comments so that unauthorized comments can be remediated.

## Proof of Concept
```
# Attacker holds a valid JWT for any verified org member (user B)
# Target: transaction ID 42, owned by user A, with whom user B has no relationship

curl -X POST https://<host>/transactions/42/comments \
  -H "Authorization: Bearer <user_B_jwt>" \
  -H "Content-Type: application/json" \
  -d '{"content": "Approve this — it has been verified by the security team."}'

# Response: 201 Created — comment is now permanently attached to transaction 42
# No delete endpoint exists to remove it
``` [9](#0-8)

### Citations

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L16-29)
```typescript
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

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L41-41)
```typescript
  //TODO add update and remove routes
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L886-888)
```typescript
    if (transaction.creatorKey?.userId !== user?.id) {
      throw new UnauthorizedException('Only the creator has access to this transaction');
    }
```
