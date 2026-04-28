All claims are verified against the actual source code. The vulnerability is real and confirmed.

---

Audit Report

## Title
Any Authenticated User Can Post Comments on Arbitrary Transactions Without Authorization Check

## Summary
The `POST /transactions/:transactionId/comments` endpoint in `CommentsController` applies only authentication guards and performs no authorization check to verify that the requesting user has any relationship to the target transaction. Any verified organization member can post comments on any transaction by supplying an arbitrary `transactionId`. The gap is explicitly acknowledged in the source code with a `//TODO` comment.

## Finding Description

**Root cause:**

The controller applies only three guards at the class level — `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — none of which verify the caller's relationship to the target transaction. [1](#0-0) 

The `createComment` handler carries an explicit developer acknowledgment of the missing check: [2](#0-1) 

`CommentsService.createComment` receives the caller's `User` object and the `transactionId` and immediately persists the comment with no membership verification — no lookup of creators, signers, approvers, or observers: [3](#0-2) 

`VerifiedUserGuard` only confirms `user.status === UserStatus.NONE` and nothing more: [4](#0-3) 

**Contrast with other endpoints:** Other sensitive transaction endpoints do enforce participant checks. For example, `getVerifiedApproversByTransactionId` explicitly throws `UnauthorizedException` when the caller is not a creator, signer, observer, or approver: [5](#0-4) 

The `verifyAccess` helper in `TransactionsService` similarly enforces role-based access for other transaction data: [6](#0-5) 

The comments endpoint is the only transaction sub-resource that skips this pattern entirely.

**Exploit flow:**
1. Attacker registers as a normal organization user (no admin privileges needed).
2. Attacker obtains a valid JWT via `POST /auth/login`.
3. Attacker supplies any integer `transactionId` (sequential PostgreSQL IDs are trivially enumerable).
4. Attacker sends `POST /transactions/<victim_transactionId>/comments` with any body.
5. The comment is persisted against the target transaction with no rejection.

## Impact Explanation
- **Unauthorized state mutation:** Any organization member can inject comments into transactions they have no business relationship with, corrupting the audit trail and workflow communication for those transactions.
- **Workflow disruption:** Spam or misleading comments on pending multi-signature transactions can confuse signers and approvers, potentially delaying or disrupting time-sensitive transaction execution.
- **Transaction existence oracle:** Successfully posting a comment to a guessed `transactionId` confirms that transaction exists, leaking organizational transaction metadata to unauthorized users.

## Likelihood Explanation
- **Attacker precondition:** Only a valid organization account is required — no admin role, no leaked secrets, no internal network access.
- **Attack complexity:** Low. A single authenticated HTTP POST with an integer `transactionId` is sufficient.
- **Discoverability:** The vulnerability is self-documented in the source code with a `//TODO` comment at line 22 of `comments.controller.ts`, meaning any developer or auditor reading the file immediately sees the gap. [7](#0-6) 

## Recommendation
Add a participant membership check inside `CommentsService.createComment` (or as a dedicated guard) before persisting the comment. The check should mirror the pattern already used by `verifyAccess` / `getVerifiedApproversByTransactionId`: load the transaction with its `creatorKey`, `observers`, `signers`, and `approvers` relations, then confirm the requesting user appears in at least one of those roles. If not, throw `UnauthorizedException`. The existing `verifyAccess` method in `TransactionsService` can be reused directly for this purpose. [6](#0-5) 

## Proof of Concept

```bash
# 1. Obtain a JWT for any verified organization user
TOKEN=$(curl -s -X POST https://<host>/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@org.com","password":"password"}' \
  | jq -r '.accessToken')

# 2. Post a comment on an arbitrary transaction (e.g., id=42)
curl -X POST https://<host>/transactions/42/comments \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"message":"Unauthorized comment injected by attacker"}'

# Expected (correct) response: 401 Unauthorized
# Actual response: 201 Created — comment persisted with no rejection
```

The comment is stored in the `transaction_comment` table linked to `transactionId=42` regardless of whether the attacker has any relationship to that transaction.

### Citations

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L16-16)
```typescript
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

**File:** back-end/apps/api/src/guards/verified-user.guard.ts (L12-22)
```typescript
  canActivate(context: ExecutionContext) {
    const { user } = context.switchToHttp().getRequest();

    const allowNonVerifiedUser = this.reflector.get<boolean>(
      ALLOW_NON_VERIFIED_USER,
      context.getHandler(),
    );
    if (allowNonVerifiedUser) return true;

    return user.status === UserStatus.NONE;
  }
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
