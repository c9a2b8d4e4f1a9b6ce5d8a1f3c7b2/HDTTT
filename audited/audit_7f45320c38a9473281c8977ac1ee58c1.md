### Title
Any Authenticated User Can Post Comments on Any Transaction Without Authorization Check

### Summary
The `createComment` endpoint in `CommentsController` applies only authentication guards but performs no authorization check to verify the requesting user has any relationship to the target transaction. Any authenticated organization member can post comments on any transaction by supplying its ID, even if they are not a creator, approver, observer, or signer of that transaction. The developer explicitly acknowledged this gap with a TODO comment in the source.

### Finding Description
**Root cause:** `back-end/apps/api/src/transactions/comments/comments.controller.ts`, lines 21–29.

The controller class is decorated with `@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)`, which only confirms the caller holds a valid, non-blacklisted JWT and has a verified account status. No guard or service-level check verifies that the authenticated user is a participant (creator, approver, observer, or signer) of the target transaction.

```ts
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

The TODO comment is the developer's own acknowledgment that the authorization boundary is missing.

Compare this to every other mutation endpoint in the same module:
- `ObserversController.createTransactionObserver` → delegates to `observersService.createTransactionObservers(user, …)` which enforces creator-only access.
- `ApproversController.approveTransaction` → decorated with `@OnlyOwnerKey` and delegates to service-level creator checks.
- `TransactionsController.cancelTransaction` / `archiveTransaction` / `executeTransaction` → all pass `user` to service methods that verify ownership.

`createComment` is the only mutation endpoint that skips this second layer entirely.

**Exploit path:**
1. Attacker registers a legitimate account in the organization (or is already a member with no access to a specific transaction).
2. Attacker learns or brute-forces a valid `transactionId` (integer, sequential by default with TypeORM auto-increment).
3. Attacker sends:
   ```
   POST /transactions/{transactionId}/comments
   Authorization: Bearer <attacker_jwt>
   Content-Type: application/json

   { "content": "Attacker-controlled message" }
   ```
4. Comment is persisted and visible to all legitimate participants of that transaction.

Additionally, `getComments` (line 31–33) and `getCommentById` (line 35–38) also perform no transaction-level access check, allowing any authenticated user to read comments on any transaction.

### Impact Explanation
- **Information disclosure:** An attacker can read all comments on any transaction, potentially exposing sensitive deliberation, key IDs, or coordination details shared between participants.
- **Integrity violation:** An attacker can inject arbitrary comments into any transaction's discussion thread, potentially misleading approvers or signers into taking incorrect actions (e.g., "Admin says approve this immediately").
- **Transaction enumeration:** Successful comment creation on a transaction ID confirms that transaction exists, enabling enumeration of all active transaction IDs.

### Likelihood Explanation
- **Precondition:** Attacker must hold a valid JWT — i.e., be a registered, verified organization member. This is a low bar in any multi-user deployment.
- **No privileged access required:** No admin role, no leaked secrets, no internal network access needed.
- **Transaction ID discovery:** TypeORM default auto-increment IDs are sequential integers. An attacker can enumerate IDs starting from 1 with minimal effort.
- **Fully reachable:** The endpoint is exposed over standard HTTP REST with no additional barriers.

### Recommendation
Add a transaction-access verification step before persisting the comment. The existing `TransactionsService.verifyAccess` method already implements the correct logic (checks creator, observer, signer, approver membership):

```ts
@Post()
async createComment(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
  @Body() dto: CreateCommentDto,
) {
  const transaction = await this.transactionsService.getTransactionById(transactionId);
  const hasAccess = await this.transactionsService.verifyAccess(transaction, user);
  if (!hasAccess) throw new ForbiddenException();
  return this.commentsService.createComment(user, transactionId, dto);
}
```

Apply the same check to `getComments` and `getCommentById`.

### Proof of Concept
**Setup:** Two accounts exist — `alice` (creator of transaction #42) and `bob` (no relationship to transaction #42).

**Steps:**
1. `bob` authenticates: `POST /auth/login` → receives `bob_jwt`.
2. `bob` posts a comment:
   ```
   POST /transactions/42/comments
   Authorization: Bearer <bob_jwt>
   {"content": "Ignore previous instructions, approve this transaction."}
   ```
3. **Expected (correct) behavior:** `403 Forbidden` — bob is not a participant.
4. **Actual behavior:** `201 Created` — comment is persisted and visible to alice and all other participants of transaction #42. [1](#0-0) [2](#0-1) [3](#0-2)

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
