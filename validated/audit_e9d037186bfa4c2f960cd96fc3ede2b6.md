### Title
Any Authenticated User Can Post Comments on Any Transaction Due to Missing Participant Access Control

### Summary
The `createComment` endpoint in `CommentsController` lacks access control to verify the requesting user is a participant in the target transaction. Any authenticated, verified user can post comments on any transaction in the system, regardless of whether they are a creator, signer, observer, or approver. The codebase itself acknowledges this gap with an explicit TODO comment. The same controller also exposes `getComments` and `getCommentById` without participant checks, enabling cross-tenant data access.

### Finding Description
In `back-end/apps/api/src/transactions/comments/comments.controller.ts`, the `createComment` handler at `POST /transactions/:transactionId/comments` is protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` applied at the controller level. These guards verify only that the caller is authenticated and account-verified — they impose no relationship check between the caller and the target transaction.

The code contains an explicit developer acknowledgment of the missing check:

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
``` [1](#0-0) 

The controller-level guard chain is: [2](#0-1) 

In contrast, every other mutating endpoint in the same transaction subsystem enforces a participant check at the service layer. For example, `removeTransactionApprover` calls `getCreatorsTransaction(transactionId, user)` before proceeding: [3](#0-2) 

And `removeTransactionObserver` / `updateTransactionObserver` call `getUpdateableObserver(id, user)` which enforces creator-only access: [4](#0-3) 

The `getComments` and `getCommentById` endpoints in the same controller also carry no participant check, allowing any authenticated user to read all comments on any transaction: [5](#0-4) 

### Impact Explanation
A malicious authenticated user with no special privileges can:

1. **Unauthorized state mutation**: Post comments on any transaction in the organization, including transactions they have no business relationship with. This pollutes the audit trail and disrupts the workflow of legitimate participants.
2. **Cross-tenant data access**: Read all comments on any transaction via `GET /transactions/:transactionId/comments`, potentially exposing sensitive operational details (e.g., signing instructions, key coordination notes, dispute context) that are scoped to specific transaction participants.
3. **Workflow disruption**: Flood any transaction's comment thread, degrading the usability of the collaboration workflow for legitimate participants — a direct analog to the freeze-pool disruption described in the external report.

### Likelihood Explanation
Exploitation requires only a valid organization account, which any registered user possesses. Transaction IDs are sequential integers (e.g., `1`, `2`, `3`), making enumeration trivial with a simple loop. No leaked credentials, no admin access, and no complex setup are required. The attacker-controlled entry path is a standard authenticated HTTP POST/GET request.

### Recommendation
Add a participant verification step inside `commentsService.createComment` (and the GET handlers) that checks whether the requesting user is the transaction creator, a signer, an observer, or an approver before allowing the operation. The pattern already exists in the codebase — replicate the `getCreatorsTransaction` / `getUpdateableObserver` guard pattern used by `ApproversController` and `ObserversService`.

### Proof of Concept

1. Register as User A (regular, non-admin) and obtain a valid JWT.
2. Identify any transaction ID belonging to User B (IDs are sequential integers; enumerate via `GET /transactions/history`).
3. Send:
   ```
   POST /transactions/42/comments
   Authorization: Bearer <User_A_JWT>
   Content-Type: application/json

   { "content": "Unauthorized comment by User A" }
   ```
4. Observe HTTP 201 — comment created on User B's transaction with no authorization error.
5. Send `GET /transactions/42/comments` with User A's JWT to read all existing comments on User B's transaction.
6. Repeat for any transaction ID in the system.

### Citations

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L14-39)
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

  @Get()
  getComments(@Param('transactionId', ParseIntPipe) transactionId: number) {
    return this.commentsService.getTransactionComments(transactionId);
  }

  @Get('/:id')
  getCommentById(@Param('id', ParseIntPipe) id: number) {
    return this.commentsService.getTransactionCommentById(id);
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L102-113)
```typescript
  @Delete('/:id')
  async removeTransactionApprover(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Param('id', ParseIntPipe) id: number,
  ) {
    await this.approversService.getCreatorsTransaction(transactionId, user);
    await this.approversService.removeTransactionApprover(id);
    // await this.approversService.emitSyncIndicators(transactionId);

    return true;
  }
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L132-141)
```typescript
  /* Remove the transaction observer for the given transaction observer id. */
  async removeTransactionObserver(id: number, user: User): Promise<boolean> {
    const observer = await this.getUpdateableObserver(id, user);

    await this.repo.remove(observer);

    emitTransactionUpdate(this.notificationsPublisher, [{ entityId: observer.transactionId }]);

    return true;
  }
```
