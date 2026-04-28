Based on my review of the codebase, I found a valid analog to the external report's vulnerability class (missing access control on a state-mutating function).

---

### Title
Any Authenticated User Can Post Comments on Any Transaction Without Access Verification

### Summary
In `back-end/apps/api/src/transactions/comments/comments.controller.ts`, the `createComment()` endpoint allows any authenticated, verified user to post a comment on any transaction by supplying an arbitrary `transactionId`. There is no check that the requesting user has any relationship to the transaction (creator, signer, approver, or observer). The code itself acknowledges this gap with an explicit TODO comment. This is a direct analog to the external report: a state-mutating function callable by any authenticated user that should be restricted to users with a verified relationship to the resource.

### Finding Description
The `CommentsController.createComment()` method is protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` at the class level — meaning any registered, verified user in the organization can reach it. [1](#0-0) 

The comment on line 22 reads:
```
//TODO need some sort of guard or check to ensure user can comment here
```

This explicitly acknowledges that no access control exists. The `createComment` call passes the user and `transactionId` directly to the service with no prior check that the user is a creator, signer, approver, or observer of that transaction. [2](#0-1) 

By contrast, every other sensitive transaction sub-resource (approvers, observers, signers) performs user-relationship verification before allowing state changes. For example, `ApproversController` calls `getCreatorsTransaction(transactionId, user)` before removing an approver, and `ObserversService` checks user membership before updates. [3](#0-2) 

### Impact Explanation
- **Unauthorized state mutation**: Any authenticated user can inject comments into transactions they have no business relationship with, polluting the audit trail and comment history of sensitive multi-signature transactions.
- **Information harvesting**: By successfully posting to a `transactionId`, an attacker confirms the existence of that transaction and its ID, enabling enumeration of all transaction IDs in the system.
- **Integrity degradation**: Comments may be used for workflow coordination (e.g., approval notes, rejection reasons). Unauthorized comments can mislead legitimate participants and disrupt the multi-signature workflow.

### Likelihood Explanation
- **Preconditions**: Attacker only needs a valid, verified account in the organization — the lowest privilege level available.
- **No special knowledge required**: Transaction IDs are sequential integers (`ParseIntPipe`), making enumeration trivial via a simple loop.
- **No rate limiting observed** on the `POST /transactions/:transactionId/comments` endpoint (unlike `remindSigners` which has `@Throttle`).
- **Realistic**: Any malicious insider or compromised low-privilege account can exploit this immediately.

### Recommendation
Add an access-verification step in `CommentsService.createComment()` (or as a guard/decorator on the controller) that confirms the requesting user is a creator, signer, approver, or observer of the target transaction before persisting the comment. This pattern is already implemented for other sub-resources:

```typescript
// Example: verify user has access before creating comment
const transaction = await this.transactionsService.getTransactionWithVerifiedAccess(transactionId, user);
if (!transaction) throw new ForbiddenException();
```

Remove the TODO comment once the check is implemented.

### Proof of Concept

1. Register two accounts: `admin@org.com` (admin, creates transactions) and `attacker@org.com` (regular verified user with no relationship to any transaction).
2. As admin, create a transaction. Note the returned `id`, e.g. `42`.
3. As `attacker@org.com`, authenticate and obtain a JWT.
4. Send:
   ```
   POST /transactions/42/comments
   Authorization: Bearer <attacker_jwt>
   Content-Type: application/json

   { "content": "Injected comment by unauthorized user" }
   ```
5. **Expected (secure)**: `403 Forbidden` — attacker has no relationship to transaction 42.
6. **Actual**: `201 Created` — comment is persisted to the database and visible to all legitimate participants of transaction 42. [1](#0-0)

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L103-113)
```typescript
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
