### Title
Any Authenticated User Can Post Comments on Any Transaction Due to Missing Access Control

### Summary
The `CommentsController.createComment` endpoint in the API service lacks any ownership or membership check on the target transaction. Any authenticated, verified user can post comments on any transaction in the organization, regardless of whether they are a creator, approver, observer, or signer of that transaction. The code itself explicitly acknowledges this gap with a `TODO` comment.

### Finding Description
In `back-end/apps/api/src/transactions/comments/comments.controller.ts`, the `createComment` handler is protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` at the controller class level. These guards verify only that the caller holds a valid, non-blacklisted JWT and has a verified account — they impose no check on whether the caller has any relationship to the transaction being targeted. [1](#0-0) 

The developer explicitly flagged the missing check at line 22:

```typescript
//TODO need some sort of guard or check to ensure user can comment here
createComment(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Body() dto: CreateCommentDto,
) {
  return this.commentsService.createComment(user, transactionId, dto);
}
``` [2](#0-1) 

Every other sensitive write endpoint in the same codebase passes the authenticated user into the service layer for an ownership/membership check (e.g., `approversService.createTransactionApprovers(user, ...)`, `observersService.createTransactionObservers(user, ...)`). The comments endpoint skips this pattern entirely. [3](#0-2) [4](#0-3) 

Transaction IDs are sequential integers exposed through the `GET /transactions` and `GET /transaction-groups` endpoints, making enumeration trivial for any authenticated user.

### Impact Explanation
- **Unauthorized write access**: Any authenticated user can inject comments into transactions they have no business relationship with, constituting a cross-tenant integrity violation.
- **Workflow disruption**: Malicious or misleading comments can be injected into the approval/signing workflow of any transaction, potentially confusing approvers or signers.
- **Spam/harassment**: An attacker can flood any transaction's comment thread, degrading the usability of the collaboration layer.
- **Severity: Medium** — no direct asset theft, but unauthorized state mutation across organizational transaction boundaries.

### Likelihood Explanation
- **Preconditions**: Only a valid, verified account is required — the lowest privilege level in the system.
- **Exploit complexity**: Trivial. The attacker needs only a valid JWT and any transaction ID (obtainable via `GET /transactions` or by guessing sequential integers).
- **No rate-limit barrier specific to this endpoint** beyond the global throttler.
- **Likelihood: High** — reachable by any registered user with zero additional privilege.

### Recommendation
Add a membership/ownership check inside `CommentsService.createComment` (or via a dedicated guard) that verifies the requesting user is a creator, approver, observer, or signer of the target transaction before persisting the comment. This mirrors the pattern already used in `ApproversService`, `ObserversService`, and `SignersService`.

```typescript
// In CommentsService.createComment:
const hasAccess = await this.transactionsService.userHasAccessToTransaction(transactionId, user);
if (!hasAccess) throw new ForbiddenException();
```

### Proof of Concept
1. Register and verify two accounts: **User A** (attacker) and **User B** (victim).
2. User B creates a transaction; note its integer `transactionId` (e.g., `42`).
3. User A authenticates and obtains a valid JWT.
4. User A sends:
   ```
   POST /transactions/42/comments
   Authorization: Bearer <User A JWT>
   { "content": "Injected comment" }
   ```
5. The request succeeds with HTTP 201. The comment appears on User B's transaction despite User A having no creator, approver, observer, or signer relationship to it.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L47-54)
```typescript
  @Post()
  createTransactionApprovers(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() body: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    return this.approversService.createTransactionApprovers(user, transactionId, body);
  }
```

**File:** back-end/apps/api/src/transactions/observers/observers.controller.ts (L43-50)
```typescript
  @Post()
  createTransactionObserver(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() body: CreateTransactionObserversDto,
  ): Promise<TransactionObserver[]> {
    return this.observersService.createTransactionObservers(user, transactionId, body);
  }
```
