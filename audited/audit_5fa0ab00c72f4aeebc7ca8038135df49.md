### Title
Any Authenticated User Can Post Comments on Transactions They Have No Access To

### Summary
The `CommentsController` enforces authentication (`JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard`) but does **not** enforce the transaction membership check (creator / observer / signer / approver) that every other transaction sub-resource endpoint enforces. Any verified user on the organization server can `POST /transactions/:transactionId/comments` against any transaction ID, bypassing the access-control invariant the rest of the system upholds. The code itself acknowledges this with a `//TODO need some sort of guard or check to ensure user can comment here` comment that was never resolved.

### Finding Description

**Invariant the system enforces everywhere else**

Every transaction sub-resource endpoint gates access by verifying the requesting user is one of: transaction creator, observer, signer, or approver. Examples:

- `GET /transactions/:id` → `TransactionsService.getTransactionWithVerifiedAccess()` → `verifyAccess()` [1](#0-0) 
- `GET /transactions/:transactionId/observers` → `ObserversService.getTransactionObserversByTransactionId()` throws `UnauthorizedException` if user is not a participant [2](#0-1) 
- `GET /transactions/:transactionId/approvers` → `ApproversService.getVerifiedApproversByTransactionId()` throws `UnauthorizedException` if user is not a participant [3](#0-2) 

**The missing check in `CommentsController`**

`POST /transactions/:transactionId/comments` applies only the three authentication guards at the controller level. No membership check exists at the route level or inside `CommentsService.createComment`. The developer left an explicit TODO acknowledging this gap:

```
@Post()
//TODO need some sort of guard or check to ensure user can comment here
createComment(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Body() dto: CreateCommentDto,
) {
  return this.commentsService.createComment(user, transactionId, dto);
}
``` [4](#0-3) 

The controller-level guards only verify the JWT is valid and not blacklisted, and that the user's account status is `NONE` (verified). They do not check whether the user has any relationship to the target transaction. [5](#0-4) 

**Exploit path**

1. Attacker registers/is invited to the organization server and obtains a valid JWT.
2. Attacker enumerates or guesses any integer `transactionId` (IDs are sequential integers).
3. Attacker sends `POST /transactions/<id>/comments` with a valid JWT and any comment body.
4. The request passes all three guards (JWT valid, not blacklisted, user verified).
5. `CommentsService.createComment` writes the comment to the database with no membership check.
6. The comment is persisted against a transaction the attacker has no legitimate access to.

The `GET /transactions/:transactionId/comments` and `GET /transactions/:transactionId/comments/:id` endpoints also lack membership checks, allowing any authenticated user to read comments on any transaction. [6](#0-5) 

### Impact Explanation

- **Unauthorized state mutation**: Any verified user can inject comments into transactions they are not a party to, polluting the audit trail and collaboration history of private multi-party transactions.
- **Information disclosure**: A successful `POST` (201) confirms the transaction exists; `GET` on comments reveals comment content from other participants, leaking internal deliberation on sensitive financial operations.
- **Integrity violation**: The comment log is part of the transaction's collaborative record. Unauthorized entries corrupt the integrity of that record for all legitimate participants.

### Likelihood Explanation

- Attacker precondition: only a valid organization account (any non-admin user suffices).
- Transaction IDs are sequential integers starting from 1, making enumeration trivial.
- No rate-limiting specific to this endpoint is visible.
- The vulnerability requires zero privilege escalation — a freshly registered user can exploit it immediately.
- The TODO comment confirms the gap was known but unresolved, meaning it has existed since the feature was shipped.

### Recommendation

Add a membership check inside `CommentsService.createComment` (or as a guard/interceptor on the route) that calls the existing `TransactionsService.verifyAccess()` or an equivalent check before persisting the comment:

```typescript
const transaction = await this.transactionsService.getTransactionWithVerifiedAccess(transactionId, user);
// throws UnauthorizedException if user is not creator/observer/signer/approver
```

The same check should be applied to `getComments` and `getCommentById` to prevent read-side information disclosure. The pattern is already established in `verifyAccess`: [7](#0-6) 

### Proof of Concept

**Setup**: Two users exist on the server — Alice (creator of transaction #42, a sensitive multi-sig transfer) and Bob (a verified user with no relationship to transaction #42).

**Steps**:
1. Bob logs in: `POST /auth/login` → receives `accessToken`.
2. Bob posts a comment:
   ```
   POST /transactions/42/comments
   Authorization: Bearer <bob_token>
   Content-Type: application/json

   { "content": "Attacker comment" }
   ```
3. **Expected**: `403 Unauthorized` — Bob is not a participant of transaction #42.
4. **Actual**: `201 Created` — comment is written to the database.
5. Bob reads all comments: `GET /transactions/42/comments` → returns all comments including those from Alice and other legitimate participants.

**Root cause**: `CommentsController.createComment` at [4](#0-3)  delegates directly to `CommentsService.createComment` with no membership gate, while every other transaction sub-resource enforces the check established in `verifyAccess`. [8](#0-7)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L296-303)
```typescript
  @Get('/:id')
  @Serialize(TransactionFullDto)
  async getTransaction(
    @GetUser() user,
    @Param('id', TransactionIdPipe) id: number | TransactionId,
  ): Promise<Transaction> {
    return this.transactionsService.getTransactionWithVerifiedAccess(id, user);
  }
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

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L14-17)
```typescript
@ApiTags('Transaction Comments')
@Controller('transactions/:transactionId?/comments')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
//TODO add serializer
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
