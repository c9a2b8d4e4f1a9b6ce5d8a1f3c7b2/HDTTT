### Title
Missing Authorization Check on Transaction Comments Endpoint Allows Any Authenticated User to Comment on Arbitrary Transactions

### Summary
The `createComment` endpoint in `CommentsController` explicitly acknowledges via a `TODO` comment that it lacks any guard or check to verify the requesting user has a relationship to the target transaction. Any authenticated user holding a valid JWT can POST comments to — and GET comments from — any transaction ID in the system, including those belonging to other organizations or users. The `CommentsService.createComment` performs no ownership or membership validation before persisting the comment.

### Finding Description
In `back-end/apps/api/src/transactions/comments/comments.controller.ts`, the `createComment` handler is decorated only with the shared class-level guards (`JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard`), which verify that the caller holds a valid, non-blacklisted JWT and is a verified user. No additional check confirms that the caller is a creator, signer, observer, or approver of the target transaction. [1](#0-0) 

The developer explicitly flagged this gap: [2](#0-1) 

The service layer (`CommentsService.createComment`) performs no authorization check either — it directly creates and saves the comment entity using the caller-supplied `transactionId`: [3](#0-2) 

Similarly, `getComments` and `getCommentById` have no ownership check, allowing any authenticated user to read comments on any transaction: [4](#0-3) 

The same class-level guards apply to all three routes, and none of them enforce transaction-level membership: [5](#0-4) 

### Impact Explanation
- **Unauthorized state modification**: Any registered user can inject comments into transactions they have no relationship to, polluting the audit trail and potentially confusing signers or approvers about transaction intent.
- **Cross-tenant information disclosure**: Any registered user can enumerate and read all comments on any transaction ID by issuing `GET /transactions/:id/comments`, exposing internal deliberation, key coordination notes, or operational details across organizational boundaries.
- **Integrity failure**: In a multi-organization workflow where comments are used to coordinate signing decisions, an outsider injecting misleading comments could influence signers' behavior on high-value Hedera transactions (e.g., treasury transfers, file updates).

### Likelihood Explanation
Exploitation requires only a valid JWT token — i.e., being a registered and verified user on the backend. No privileged access, no leaked credentials, and no special knowledge beyond knowing or guessing integer transaction IDs (which are sequential per the TypeORM/PostgreSQL schema) are needed. The attack is a single authenticated HTTP POST or GET request.

### Recommendation
Add a transaction-membership guard to the `createComment` (and `getComments`) routes that verifies the requesting user is a creator, signer, observer, or approver of the target transaction before allowing the operation. This check should be implemented as a NestJS guard or within `CommentsService` by joining against the transaction's participant relations. The existing `TODO` comment at line 22 should be resolved with this enforcement logic. [1](#0-0) 

### Proof of Concept
1. Register two users (User A and User B) on the backend.
2. User A creates a transaction; note its integer `id` (e.g., `42`).
3. User B (who has no relationship to transaction `42`) authenticates and obtains a JWT.
4. User B sends:
   ```
   POST /transactions/42/comments
   Authorization: Bearer <user_b_jwt>
   Content-Type: application/json

   { "content": "Injected comment from unrelated user" }
   ```
5. The backend returns `201 Created` and the comment is persisted.
6. User B then sends `GET /transactions/42/comments` and receives all comments on User A's transaction, including any sensitive coordination notes.

Expected (correct) behavior: `403 Forbidden` — User B is not a participant of transaction `42`.
Actual behavior: `201 Created` / `200 OK` — no membership check is performed.

### Citations

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L14-18)
```typescript
@ApiTags('Transaction Comments')
@Controller('transactions/:transactionId?/comments')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
//TODO add serializer
export class CommentsController {
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

**File:** back-end/apps/api/src/transactions/comments/comments.service.ts (L32-37)
```typescript
  getTransactionComments(transactionId: number) {
    return this.repo
      .createQueryBuilder('comment')
      .where('comment.transactionId = :transactionId', { transactionId })
      .getMany();
  }
```
