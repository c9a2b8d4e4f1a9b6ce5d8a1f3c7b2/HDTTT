The code is confirmed. Here is the audit report:

---

Audit Report

## Title
Any Authenticated Transaction Creator Can Delete Approvers Belonging to Other Users' Transactions

## Summary
The `DELETE /transactions/:transactionId/approvers/:id` endpoint verifies the caller is the creator of `:transactionId`, but then deletes the approver identified by `:id` without verifying that approver actually belongs to `:transactionId`. An attacker who owns any one transaction can delete approvers from any other transaction in the system.

## Finding Description

**Root cause — missing cross-ownership check in the delete path.**

The controller handler at `approvers.controller.ts` lines 102–113 performs two independent, unbound steps:

```typescript
await this.approversService.getCreatorsTransaction(transactionId, user); // checks caller owns :transactionId
await this.approversService.removeTransactionApprover(id);               // deletes approver by PK :id — no binding
``` [1](#0-0) 

The service method `removeTransactionApprover` only checks that the approver row exists, then soft-deletes it. It never asserts that `approver.transactionId === transactionId`:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);   // deletes unconditionally
  ...
}
``` [2](#0-1) 

**Contrast with the update path**, which correctly validates ownership before mutating. `updateTransactionApprover` first resolves the root node of the approver, then explicitly asserts the root's `transactionId` matches the URL parameter, and only then re-runs `getCreatorsTransaction` against the approver's actual transaction:

```typescript
if (rootNode.transactionId !== transactionId)
  throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);
await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
``` [3](#0-2) 

The delete path has no equivalent guard.

**Exploit flow:**
1. Attacker (User A) creates Transaction 1 — they become its creator.
2. Victim (User B) creates Transaction 2 and adds approvers (approver IDs are sequential integers, easily enumerable).
3. Attacker sends:
   ```
   DELETE /transactions/1/approvers/<victim_approver_id>
   ```
4. `getCreatorsTransaction(1, userA)` succeeds — User A owns Transaction 1. [4](#0-3) 
5. `removeTransactionApprover(<victim_approver_id>)` soft-deletes the approver from Transaction 2 with no further check. [2](#0-1) 

## Impact Explanation
An attacker can silently remove all approvers from any transaction they do not own. The approval workflow is the primary authorization gate before a transaction is executed on the Hedera network. Gutting it reduces a multi-party approval requirement to zero approvers, potentially allowing a transaction to proceed to execution without the intended oversight. This is an unauthorized state mutation with direct impact on transaction integrity and multi-signature security guarantees. [1](#0-0) 

## Likelihood Explanation
The precondition is minimal: the attacker only needs a valid JWT (a registered, verified account) and must have created at least one transaction (trivially achievable). Approver IDs are sequential database integers, making enumeration straightforward. No privileged role is required. The endpoint is a standard REST `DELETE` call. [5](#0-4) 

## Recommendation
In `removeTransactionApprover` (or in the controller handler before calling it), after fetching the approver by `id`, assert that the approver's root transaction matches the authorized `:transactionId`. Mirror the pattern already used in `updateTransactionApprover`:

```typescript
// In the controller or service, after getCreatorsTransaction:
const approver = await this.approversService.getTransactionApproverById(id);
if (!approver) throw new BadRequestException(ErrorCodes.ANF);

const rootNode = await this.approversService.getRootNodeFromNode(approver.id);
if (!rootNode || rootNode.transactionId !== transactionId)
  throw new UnauthorizedException('Approver does not belong to the authorized transaction');

await this.approversService.removeTransactionApprover(id);
``` [3](#0-2) 

## Proof of Concept

```
# Step 1: Authenticate as User A (attacker), obtain JWT
POST /auth/login  { "email": "attacker@example.com", "password": "..." }
# → JWT_A

# Step 2: User A creates Transaction 1 (becomes creator)
POST /transactions  { ... }  Authorization: Bearer JWT_A
# → { "id": 1 }

# Step 3: Authenticate as User B (victim), obtain JWT
POST /auth/login  { "email": "victim@example.com", "password": "..." }
# → JWT_B

# Step 4: User B creates Transaction 2 and adds an approver
POST /transactions  { ... }  Authorization: Bearer JWT_B
# → { "id": 2 }
POST /transactions/2/approvers  { "approversArray": [{ "userId": 3 }] }  Authorization: Bearer JWT_B
# → [{ "id": 7, "transactionId": 2, "userId": 3 }]

# Step 5: Attacker deletes victim's approver (id=7) using their own transactionId=1
DELETE /transactions/1/approvers/7  Authorization: Bearer JWT_A
# → HTTP 200: true
# Approver id=7 (belonging to Transaction 2) is now soft-deleted.
```

`getCreatorsTransaction(1, userA)` passes because User A owns Transaction 1. `removeTransactionApprover(7)` then deletes approver 7 — which belongs to Transaction 2 — with no further check. [6](#0-5)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L31-36)
```typescript
@ApiTags('Transaction Approvers')
@Controller('transactions/:transactionId?/approvers')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
@Serialize(TransactionApproverDto)
export class ApproversController {
  constructor(private approversService: ApproversService) {}
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L386-394)
```typescript
        const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
        if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

        /* Verifies that the root transaction is the same as the param */
        if (rootNode.transactionId !== transactionId)
          throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

        /* Verifies that the user is the creator of the transaction */
        await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L533-544)
```typescript
  /* Removes the transaction approver by id */
  async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);

    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const result = await this.removeNode(approver.id);

    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);

    return result;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L623-644)
```typescript
  /* Get the transaction by id and verifies that the user is the creator */
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
