### Title
Transaction Creator Can Manipulate Approver Structure After Approval Process Has Started, Bypassing Multi-Approval Security

### Summary
The `getCreatorsTransaction` guard used to protect all approver mutation endpoints (`createTransactionApprovers`, `updateTransactionApprover`, `removeTransactionApprover`) checks only that the caller is the transaction creator — it never checks the transaction's current status. This allows the creator to add, remove, or restructure approvers (including lowering the threshold) while a transaction is already in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`, effectively bypassing the multi-approval workflow that is the core security control of Organization Mode.

### Finding Description

**Root cause — `getCreatorsTransaction` has no status guard:** [1](#0-0) 

The function only enforces `creatorKey.userId === user.id`. It never inspects `transaction.status`. Every approver-mutation path calls this function as its sole authorization check:

- `createTransactionApprovers` — line 239 calls `getCreatorsTransaction` [2](#0-1) 

- `updateTransactionApprover` — line 394 calls `getCreatorsTransaction` [3](#0-2) 

- `removeTransactionApprover` (controller) — line 108 calls `getCreatorsTransaction`, then immediately removes the approver [4](#0-3) 

**Exploit flow (concrete):**

1. Alice (creator) creates a transaction and sets up an approver tree: threshold node requiring 3-of-3 approvals from Bob, Carol, and Dave.
2. Bob and Carol approve (`approveTransaction`). Dave reviews the transaction and refuses to approve.
3. Alice calls `DELETE /transactions/:id/approvers/:daveApproverId`. The controller calls `getCreatorsTransaction` (passes — Alice is creator, no status check), then `removeTransactionApprover` soft-deletes Dave's record. [5](#0-4) 
4. Alice calls `PATCH /transactions/:id/approvers/:thresholdNodeId` with `{ threshold: 2 }`. `updateTransactionApprover` passes the creator check, finds 2 remaining children, and the threshold `2 <= 2` validation passes — threshold is lowered. [6](#0-5) 
5. The transaction now has 2-of-2 approvals satisfied. The scheduler's `processTransactionStatus` promotes it to `WAITING_FOR_EXECUTION` and it is submitted to the Hedera network.

The transaction status states that are vulnerable are `WAITING_FOR_SIGNATURES` and `WAITING_FOR_EXECUTION` — both are considered "in-progress" and both allow approver mutations: [7](#0-6) 

### Impact Explanation

The multi-approver workflow is the primary security control in Organization Mode. It exists to ensure that high-stakes Hedera transactions (account creation, file updates, HBAR transfers) cannot be submitted by a single actor. By manipulating the approver tree after the approval process has started, the creator can:

- Remove approvers who have rejected or are expected to reject.
- Lower the threshold to match only the approvals already collected.
- Replace a non-compliant approver with a colluding one and collect their approval.

This constitutes an **unauthorized state change** — the transaction proceeds to execution with a weaker approval requirement than the one the approvers originally agreed to review. The integrity of the entire multi-signature coordination model is broken.

### Likelihood Explanation

The attacker is the transaction creator — a normal authenticated user with no special privileges. The attack requires only standard API calls (`DELETE` and `PATCH` on the approvers endpoint) that are already part of the documented workflow. No cryptographic break, no leaked credentials, and no admin access are needed. Any creator who faces a blocking approver can execute this unilaterally.

### Recommendation

Add a status guard inside `getCreatorsTransaction` (or as a separate check at the top of each mutation method) that rejects modifications when the transaction is in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`:

```typescript
// In getCreatorsTransaction or each mutation entry point:
const IMMUTABLE_STATUSES = [
  TransactionStatus.WAITING_FOR_SIGNATURES,
  TransactionStatus.WAITING_FOR_EXECUTION,
  TransactionStatus.EXECUTED,
  TransactionStatus.EXPIRED,
  TransactionStatus.CANCELED,
  TransactionStatus.ARCHIVED,
];
if (IMMUTABLE_STATUSES.includes(transaction.status)) {
  throw new BadRequestException('Approver structure cannot be modified once the approval process has started');
}
```

This mirrors the fix applied in the RocketPool analog: once a process is active, its parameters must be frozen.

### Proof of Concept

**Preconditions:** Alice is a registered organization user and the creator of transaction `#42`. Bob (userId=2) and Carol (userId=3) have approved. Dave (userId=4, approverId=7) has not approved. The threshold node (approverId=5) requires 3-of-3.

```
# Step 1 — Remove the blocking approver (Dave)
DELETE /transactions/42/approvers/7
Authorization: Bearer <alice_token>
# → 200 OK (no status check, Alice is creator)

# Step 2 — Lower the threshold from 3 to 2
PATCH /transactions/42/approvers/5
Authorization: Bearer <alice_token>
Content-Type: application/json
{ "threshold": 2 }
# → 200 OK (2 <= 2 remaining children, passes validation)

# Result: transaction now has 2-of-2 approvals satisfied.
# Scheduler promotes it to WAITING_FOR_EXECUTION and submits to Hedera.
``` [1](#0-0) [4](#0-3) [6](#0-5)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-240)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);

```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L393-395)
```typescript
        /* Verifies that the user is the creator of the transaction */
        await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);

```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L467-488)
```typescript
        } else if (typeof dto.threshold === 'number') {
          /* Check if the approver is a tree */
          if (typeof approver.threshold !== 'number' || typeof approver.userId === 'number')
            throw new Error(this.APPROVER_NOT_TREE);

          /* Check if the approver threshold is less or equal to the number of approvers */
          if (
            approver.approvers &&
            (dto.threshold > approver.approvers.length || dto.threshold === 0)
          )
            throw new Error(this.THRESHOLD_LESS_OR_EQUAL_APPROVERS(approver.approvers.length));

          /* Update the threshold */
          if (approver.threshold !== dto.threshold) {
            await transactionalEntityManager.update(TransactionApprover, approver.id, {
              threshold: dto.threshold,
            });
            approver.threshold = dto.threshold;
            updated = true;

            return approver;
          }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L534-544)
```typescript
  async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);

    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const result = await this.removeNode(approver.id);

    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);

    return result;
  }
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

**File:** front-end/src/renderer/utils/transactionStatusGuards.ts (L1-12)
```typescript
import { TransactionStatus } from '@shared/interfaces';

export const isInProgressStatus = (status: TransactionStatus | null | undefined): boolean =>
  [TransactionStatus.NEW, TransactionStatus.WAITING_FOR_EXECUTION, TransactionStatus.WAITING_FOR_SIGNATURES]
    .includes(status as TransactionStatus);

export const isSignableStatus = (status: TransactionStatus | null | undefined): boolean =>
  status === TransactionStatus.WAITING_FOR_SIGNATURES;

export const isApprovableStatus = (status: TransactionStatus | null | undefined): boolean =>
  [TransactionStatus.WAITING_FOR_SIGNATURES, TransactionStatus.WAITING_FOR_EXECUTION].includes(
    status as TransactionStatus,
```
