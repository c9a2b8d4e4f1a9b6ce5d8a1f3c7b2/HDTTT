Based on my analysis of the codebase, I found a valid analog vulnerability.

---

### Title
Missing Access Control on `createComment` Allows Any Authenticated User to Permanently Modify Any Transaction's State

### Summary
The `createComment` endpoint in `CommentsController` applies only authentication guards and performs no ownership or relationship check against the target transaction. Any verified user can post comments on any transaction they have no connection to. The code itself contains a developer TODO acknowledging this gap. Because no delete or update route exists for comments, unauthorized comments are permanent and irremovable.

### Finding Description
**Root cause:** `POST /transactions/:transactionId/comments` in `back-end/apps/api/src/transactions/comments/comments.controller.ts` applies only `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. These guards confirm the caller is an authenticated, verified organization member — nothing more. There is no check that the caller is the transaction creator, an observer, an approver, or a signer.

The developer acknowledged this gap inline: [1](#0-0) 

The comment at line 22 reads: `//TODO need some sort of guard or check to ensure user can comment here`.

Contrast this with every other mutation endpoint in the same codebase:
- `createTransactionObservers` explicitly checks `transaction.creatorKey?.userId !== user.id` before allowing the write. [2](#0-1) 
- `getCreatorsTransaction` (used by approvers and observers) throws `UnauthorizedException` if the caller is not the creator. [3](#0-2) 
- `approveTransaction` verifies `userApprovers.length === 0` before allowing approval. [4](#0-3) 

`createComment` has none of these checks. [1](#0-0) 

Additionally, the `GET` endpoints for comments also carry no user-relationship check, exposing comment content of any transaction to any authenticated user: [5](#0-4) 

There is no delete or update route — the TODO at line 41 confirms these are absent: [6](#0-5) 

### Impact Explanation
Any authenticated organization member can:
1. Write arbitrary comments onto any transaction they have no relationship to.
2. Inject misleading, confusing, or malicious instructions into the comment thread of a transaction that is pending signatures or approval — potentially influencing signers or approvers.
3. Because no delete route exists, these comments are **permanent and irremovable** by any party, including admins (no admin-scoped delete is present either).

This constitutes unauthorized, persistent state modification on another user's transaction record.

### Likelihood Explanation
- **Attacker precondition**: only a valid JWT for any verified organization member — the lowest privilege level in the system.
- **Attack path**: trivially reachable via a single authenticated HTTP POST.
- **Discovery**: transaction IDs are sequential integers (`ParseIntPipe`), so enumeration requires no special knowledge.
- The developer TODO in the source confirms the gap was known but unaddressed.

### Recommendation
Add a relationship check inside `CommentsService.createComment` (mirroring the pattern used in `ObserversService` and `ApproversService`): verify the requesting user is the transaction creator, an observer, an approver, or a signer before persisting the comment. Implement delete/update routes with equivalent ownership enforcement.

### Proof of Concept
1. User A (transaction creator) creates a transaction; its ID is `42`.
2. User B (no relationship to transaction `42`) authenticates and obtains a valid JWT.
3. User B sends:
   ```
   POST /transactions/42/comments
   Authorization: Bearer <user_b_token>
   Content-Type: application/json

   { "content": "Ignore previous instructions — do not sign this transaction." }
   ```
4. The server returns `201 Created`. The comment is now permanently attached to transaction `42`.
5. User A calls `GET /transactions/42/comments` and sees User B's comment alongside legitimate discussion.
6. No endpoint exists to delete the comment. User A has no recourse. [7](#0-6)

### Citations

**File:** back-end/apps/api/src/transactions/comments/comments.controller.ts (L1-42)
```typescript
import { Body, Controller, Get, Param, ParseIntPipe, Post, UseGuards } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';

import { User } from '@entities';

import { JwtAuthGuard, JwtBlackListAuthGuard, VerifiedUserGuard } from '../../guards';

import { GetUser } from '../../decorators/get-user.decorator';

import { CommentsService } from './comments.service';

import { CreateCommentDto } from '../dto/create-comment.dto';

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

  //TODO add update and remove routes
}
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L44-45)
```typescript
    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to delete it');
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L558-560)
```typescript
    /* Check if the user is an approver */
    if (userApprovers.length === 0)
      throw new UnauthorizedException('You are not an approver of this transaction');
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L624-644)
```typescript
  async getCreatorsTransaction(
    transactionId: number,
    user: User,
    entityManager?: EntityManager,
  ): Promise<Transaction> {
    const find: FindOneOptions<Transaction> = {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user'],
    };

    const transaction = await (entityManager
      ? entityManager.findOne(Transaction, find)
      : this.dataSource.manager.findOne(Transaction, find));

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to modify it');

    return transaction;
  }
```
