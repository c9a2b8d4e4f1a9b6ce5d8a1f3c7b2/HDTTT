### Title
Any Authenticated User Can Post Comments on Arbitrary Transactions Due to Missing Authorization Check

### Summary
The `createComment` endpoint in `CommentsController` (`back-end/apps/api/src/transactions/comments/comments.controller.ts`) enforces only authentication (JWT + verified user) but performs no check that the requesting user has any relationship to the target transaction. Any authenticated user can post comments on any transaction in the system — including transactions they did not create, are not a signer of, are not an approver of, and are not an observer of. The developers themselves flagged this gap with a `//TODO` comment directly on the handler.

### Finding Description

**Root cause:**

The controller applies `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` at the class level, which only confirms the caller is a valid, non-blacklisted, verified user. No guard or service-layer check verifies that the user is a participant (creator, signer, approver, or observer) of the transaction identified by `:transactionId`. [1](#0-0) 

The `//TODO need some sort of guard or check to ensure user can comment here` comment on line 22 is a developer acknowledgment that this authorization boundary is intentionally absent and unresolved. [2](#0-1) 

**Exploit path:**

1. Attacker registers as a normal user and obtains a valid JWT (standard sign-up flow via admin, then login).
2. Attacker enumerates or guesses any integer `transactionId` (IDs are sequential integers).
3. Attacker sends `POST /transactions/<any_id>/comments` with a valid JWT and arbitrary comment body.
4. The comment is persisted to the database and associated with that transaction — a transaction the attacker has no legitimate relationship to.

There is no service-layer check in `CommentsService.createComment` that validates the user's membership in the transaction's participant set.

### Impact Explanation

- **Unauthorized state modification**: Any authenticated user can inject comment records into the audit trail of any transaction in the organization, including sensitive multi-signature workflows involving Hedera Council operations.
- **Workflow integrity degradation**: Signers and approvers rely on the comment thread for coordination. Injected comments from unauthorized users corrupt this channel, potentially causing confusion or misdirection during time-sensitive signing rounds.
- **Data integrity**: The comment table accumulates records that violate the intended trust model (only participants should be able to comment), making forensic audit trails unreliable.

### Likelihood Explanation

- **Preconditions**: Only a valid, verified user account is required — the lowest privilege level in the system.
- **Effort**: A single authenticated HTTP `POST` request with a known or guessed integer transaction ID.
- **Transaction ID discoverability**: IDs are sequential integers. A user who legitimately participates in even one transaction can infer the ID range and probe others.
- **No rate-limit or anomaly detection** is visible on this endpoint beyond the standard `EmailThrottlerGuard` (which applies only to email-sending routes).

### Recommendation

Add an authorization check — either as a guard or inside `CommentsService.createComment` — that verifies the requesting user is a creator, signer, approver, or observer of the target transaction before persisting the comment. Example approach:

```typescript
// In CommentsService.createComment, before saving:
const isParticipant = await this.transactionsService.isUserParticipant(user.id, transactionId);
if (!isParticipant) {
  throw new ForbiddenException('You are not a participant of this transaction.');
}
```

Alternatively, implement a dedicated `TransactionParticipantGuard` and apply it to the `@Post()` handler, consistent with how `AdminGuard` is applied to admin-only routes. [3](#0-2) 

### Proof of Concept

```
# Step 1: Login as any verified user
POST /auth/login
Body: { "email": "user@org.com", "password": "..." }
→ Response: { "accessToken": "<JWT>" }

# Step 2: Post a comment on a transaction the user has no relationship to
POST /transactions/1/comments
Authorization: Bearer <JWT>
Body: { "message": "Injected comment on transaction I don't own" }
→ Response: 201 Created — comment is persisted to the DB

# Step 3: Verify the comment appears on the transaction
GET /transactions/1/comments
Authorization: Bearer <JWT>
→ Response: [..., { "message": "Injected comment on transaction I don't own", "userId": <attacker_id> }]
```

The `createComment` call succeeds and the unauthorized comment is stored, demonstrating that any authenticated user can pollute the comment history of any transaction in the organization. [2](#0-1)

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

**File:** back-end/apps/api/src/guards/admin.guard.ts (L1-9)
```typescript
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';

@Injectable()
export class AdminGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    const { user } = context.switchToHttp().getRequest();
    return user && user.admin;
  }
}
```
