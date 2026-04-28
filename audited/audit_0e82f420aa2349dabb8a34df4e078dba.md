### Title
Any Authenticated User Can Post Comments on Any Transaction (Missing Access Control on `createComment`)

### Summary
The `CommentsController` exposes a `POST /transactions/:transactionId/comments` endpoint that allows any authenticated, verified user to post a comment on any transaction in the system, regardless of whether they are a creator, signer, observer, or approver of that transaction. The code itself contains a developer TODO acknowledging the missing guard.

### Finding Description
In `back-end/apps/api/src/transactions/comments/comments.controller.ts`, the `createComment` handler is protected only by the controller-level guards `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. These guards verify that the caller holds a valid, non-blacklisted JWT and has a verified account status — but they perform no check that the caller has any relationship to the target transaction. [1](#0-0) 

The developer explicitly flagged this gap with a TODO comment directly above the handler:

```
//TODO need some sort of guard or check to ensure user can comment here
``` [2](#0-1) 

By contrast, every other state-mutating endpoint in the transaction subsystem enforces transaction-level ownership or participation checks. For example, `ObserversService.createTransactionObservers` explicitly verifies `transaction.creatorKey?.userId !== user.id` before allowing the operation: [3](#0-2) 

No equivalent check exists anywhere in `CommentsService` or `CommentsController`.

### Impact Explanation
Any authenticated user — including users who have no relationship whatsoever to a transaction — can inject arbitrary comment content into that transaction's comment thread. This pollutes the audit trail and communication channel for sensitive multi-signature Hedera transactions (e.g., node updates, account key rotations). In an organizational context where comments may drive signing decisions or approvals, injected comments from unauthorized parties could mislead legitimate participants.

### Likelihood Explanation
The attack path requires only a valid JWT (i.e., any registered, verified organization member). The transaction ID is an auto-incrementing integer, making enumeration trivial. No special privilege, role, or knowledge of the transaction is required. The TODO comment confirms the gap was known but unresolved.

### Recommendation
In `CommentsService.createComment`, add a participation check before persisting the comment. Verify that the requesting user is one of: the transaction creator, a signer, an observer, or an approver. The pattern already exists in `ObserversService.getTransactionObserversByTransactionId`: [4](#0-3) 

Apply the same logic (or extract it into a shared `verifyAccess` helper — one already exists in `TransactionsService`) before allowing comment creation. [5](#0-4) 

### Proof of Concept

```
# 1. Register/login as any verified user (user B, unrelated to the target transaction)
POST /auth/login
{ "email": "unrelated@org.com", "password": "..." }
→ { "accessToken": "<JWT_B>" }

# 2. Enumerate or guess a transaction ID (integer, sequential)
# 3. Post a comment on a transaction the user has no relationship to
POST /transactions/42/comments
Authorization: Bearer <JWT_B>
{ "content": "Injected comment from unauthorized user" }

# Result: 201 Created — comment is persisted with no access check
```

The controller accepts the request, passes all guards, and delegates directly to `CommentsService.createComment` with no further authorization. [2](#0-1)

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
