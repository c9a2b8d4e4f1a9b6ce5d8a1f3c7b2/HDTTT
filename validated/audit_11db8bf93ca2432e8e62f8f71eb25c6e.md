All code references check out. The vulnerability is confirmed.

---

Audit Report

## Title
Any Authenticated User Can Post and Read Comments on Transactions They Do Not Participate In

## Summary
`CommentsController` exposes `POST /transactions/:transactionId/comments` and `GET /transactions/:transactionId/comments` with only authentication/verification guards. No transaction-participation check exists in either the controller or `CommentsService`, allowing any verified user to inject comments into and read comments from any transaction in the system.

## Finding Description

**Affected file:** `back-end/apps/api/src/transactions/comments/comments.controller.ts`

The controller applies only `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — guards that confirm the caller is a logged-in, verified user, nothing more. A developer-acknowledged `TODO` comment at line 22 explicitly flags the missing participation check that was never implemented. [1](#0-0) 

`CommentsService.createComment` performs no transaction-participation check. It directly creates and persists the comment for any caller-supplied `transactionId`: [2](#0-1) 

`CommentsService.getTransactionComments` similarly performs no access check — it returns all comments for any `transactionId` passed in, with no user context at all: [3](#0-2) 

**Contrast with other transaction sub-resources:** `ObserversService.getTransactionObserversByTransactionId` explicitly throws `UnauthorizedException` when the caller is not the creator, observer, signer, or approver of the transaction: [4](#0-3) 

Comments are the only transaction sub-resource that omits this invariant entirely.

## Impact Explanation

- **Unauthorized state mutation:** Any verified user can inject arbitrary comment records into any transaction they have no relationship to, polluting the audit trail and potentially disrupting multi-signature workflows (e.g., injecting misleading instructions into a Hedera Council transaction).
- **Information disclosure:** Comments on private, in-progress transactions are readable by any authenticated user. Other endpoints correctly gate this data behind participation checks; comments do not.
- **Cross-tenant integrity break:** The system's trust model assumes only participants can interact with a transaction. The comments endpoints violate this invariant while every other sub-resource enforces it.

## Likelihood Explanation

- Attacker precondition: a valid, verified account — achievable through the normal signup flow.
- No privileged keys, leaked credentials, or internal network access required.
- Transaction IDs are sequential integers (`ParseIntPipe` on a plain integer PK), making enumeration trivial.
- The vulnerability is reachable via a single authenticated HTTP request.

## Recommendation

Add a participation check inside `CommentsService` before creating or returning comments, mirroring the pattern already used in `ObserversService.getTransactionObserversByTransactionId`:

1. In `createComment`: load the `Transaction` with its `creatorKey`, `observers`, `signers`, and approvers. Throw `UnauthorizedException` if the calling user is not among them.
2. In `getTransactionComments`: accept the calling `User` as a parameter and apply the same participation check before returning results.
3. In `getTransactionCommentById`: apply the same check after resolving the comment's parent transaction.
4. Remove the unresolved `TODO` comment once the guard is in place.

## Proof of Concept

```
# Step 1 – Attacker registers and verifies a normal account (standard product flow)

# Step 2 – Attacker enumerates a victim transaction ID (sequential integers)
TARGET_TX_ID=42

# Step 3 – Inject a comment into a transaction the attacker has no role in
curl -X POST https://<host>/transactions/$TARGET_TX_ID/comments \
  -H "Authorization: Bearer <attacker_jwt>" \
  -H "Content-Type: application/json" \
  -d '{"message": "Attacker-injected comment"}'
# → 201 Created; comment persisted to victim transaction

# Step 4 – Read all comments (including sensitive workflow notes from real participants)
curl https://<host>/transactions/$TARGET_TX_ID/comments \
  -H "Authorization: Bearer <attacker_jwt>"
# → 200 OK; full comment list returned with no participation check
```

### Citations

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L14-34)
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
