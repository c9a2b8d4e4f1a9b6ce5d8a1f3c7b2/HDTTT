Based on my investigation of the codebase, I have found a valid analog vulnerability.

---

### Title
Transaction Creator Can Modify Approver Structure on In-Progress Transactions, Bypassing Multi-Signature Requirements

### Summary
The `removeTransactionApprover` and `updateTransactionApprover` functions in `approvers.service.ts` do not check the current transaction status before allowing the transaction creator to remove or reassign approvers. A transaction creator (a normal, unprivileged user) can remove approvers who have already signed, or change the `userId` of an approver to invalidate existing signatures, after a transaction has entered `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` status. This allows the creator to unilaterally bypass the multi-signature approval structure that other parties agreed to participate in.

### Finding Description

**Root Cause:**

In `back-end/apps/api/src/transactions/approvers/approvers.service.ts`, both `removeTransactionApprover` and `updateTransactionApprover` verify only that the caller is the transaction creator, but perform no check on the current transaction status before mutating the approver tree.

`removeTransactionApprover` (lines 534–544):

```ts
async removeTransactionApprover(id: number): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);
  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(...);
  return result;
}
``` [1](#0-0) 

`updateTransactionApprover` (lines 367–530) similarly performs no status guard before mutating `userId`, `threshold`, or `listId` of an approver: [2](#0-1) 

The controller calls `getCreatorsTransaction` (a creator-identity check only) and then immediately calls `removeTransactionApprover` with no status gate:

```ts
await this.approversService.getCreatorsTransaction(transactionId, user);
await this.approversService.removeTransactionApprover(id);
``` [3](#0-2) 

By contrast, `approveTransaction` correctly enforces a status check before accepting signatures:

```ts
if (
  transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
  transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
)
  throw new BadRequestException(ErrorCodes.TNRA);
``` [4](#0-3) 

This asymmetry means approvals are gated on status, but approver mutations are not.

**Exploit Flow:**

1. Alice (creator) creates a transaction requiring a 2-of-3 threshold approver tree.
2. Bob and Carol (approvers) sign and approve the transaction; it enters `WAITING_FOR_EXECUTION`.
3. Alice calls `DELETE /transactions/:transactionId/approvers/:id` to remove Bob and Carol's approver records, or calls `PATCH` to change their `userId` to a user she controls, resetting their `signature`/`approved` fields to `undefined`.
4. The approval tree now reflects 0 valid signatures against a reduced or zeroed threshold.
5. Alice can now satisfy the (now-mutated) approval requirement alone and trigger execution — bypassing the multi-party agreement.

The `updateTransactionApprover` path that changes `userId` explicitly clears `userKeyId`, `signature`, and `approved` on the record:

```ts
const data: DeepPartial<TransactionApprover> = {
  userId: dto.userId,
  userKeyId: undefined,
  signature: undefined,
  approved: undefined,
};
``` [5](#0-4) 

This means changing an approver's `userId` actively erases the existing signature, making the previously-collected approval disappear from the record.

### Impact Explanation

A transaction creator can unilaterally invalidate collected approvals or remove approvers after the multi-sig workflow has begun. This breaks the core security invariant of the approval system: that a transaction cannot be executed without the agreed-upon set of approvals. In an organizational context where transactions represent fund transfers or critical Hedera account operations, this allows a single user (the creator) to bypass the multi-party control that the organization relies on.

### Likelihood Explanation

The attacker is the transaction creator — a normal, authenticated user with no special privileges beyond having created the transaction. The attack path is through standard, documented REST API endpoints (`DELETE /transactions/:id/approvers/:id` and `PATCH /transactions/:id/approvers/:id`). No leaked credentials, admin access, or cryptographic breaks are required. Any creator who wishes to circumvent an approval they set up can do so at any point after the transaction is created.

### Recommendation

In both `removeTransactionApprover` and `updateTransactionApprover`, add a status guard that rejects mutations when the transaction is in `WAITING_FOR_SIGNATURES`, `WAITING_FOR_EXECUTION`, or any terminal state. Only allow approver-tree modifications when the transaction is in `WAITING_FOR_SIGNATURES` at most, and only before any approver has submitted a signature. Concretely:

```ts
if (
  transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES ||
  existingApprovers.some(a => a.signature != null)
) {
  throw new BadRequestException('Cannot modify approvers after signing has begun');
}
```

### Proof of Concept

1. Create a transaction with a 2-of-2 approver requirement (users B and C).
2. Have user B approve the transaction (transaction enters `WAITING_FOR_SIGNATURES`).
3. As the creator (user A), call:
   ```
   DELETE /transactions/{txId}/approvers/{approverIdForB}
   DELETE /transactions/{txId}/approvers/{approverIdForC}
   ```
4. Add a single new approver pointing to a key user A controls.
5. Approve as user A.
6. Observe the transaction proceeds to execution with only user A's approval, despite the original 2-of-2 requirement.

The relevant service entry points are `removeTransactionApprover` and `updateTransactionApprover` in: [6](#0-5) [1](#0-0)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L108-109)
```typescript
  }

```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L367-531)
```typescript
  async updateTransactionApprover(
    id: number,
    dto: UpdateTransactionApproverDto,
    transactionId: number,
    user: User,
  ): Promise<TransactionApprover> {
    try {
      let updated = false;

      const approver = await this.dataSource.transaction(async transactionalEntityManager => {
        /* Check if the dto updates only one thing */
        if (Object.keys(dto).length > 1 || Object.keys(dto).length === 0)
          throw new Error(this.INVALID_UPDATE_APPROVER);

        /* Verifies that the approver exists */
        const approver = await this.getTransactionApproverById(id, transactionalEntityManager);
        if (!approver) throw new BadRequestException(ErrorCodes.ANF);

        /* Gets the root approver */
        const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
        if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

        /* Verifies that the root transaction is the same as the param */
        if (rootNode.transactionId !== transactionId)
          throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

        /* Verifies that the user is the creator of the transaction */
        await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);

        /* Check if the parent approver exists and has threshold */
        if (dto.listId === null || typeof dto.listId === 'number') {
          if (dto.listId === null) {
            /* Return if the approver is already a root */
            if (approver.listId === null) return approver;

            /* Get the parent approver */
            const parent = await transactionalEntityManager.findOne(TransactionApprover, {
              relations: ['approvers'],
              where: { id: approver.listId },
            });

            /* Set the list id to null and set the transaction id */
            await transactionalEntityManager.update(TransactionApprover, approver.id, {
              listId: null,
              transactionId: rootNode.transactionId,
            });
            approver.listId = null;
            approver.transactionId = rootNode.transactionId;
            updated = true;

            if (parent) {
              const newParentApproversLength = parent.approvers.length - 1;

              /* Soft delete the parent if there are no more children */
              if (newParentApproversLength === 0) {
                await transactionalEntityManager.softRemove(TransactionApprover, parent);
              } else if (newParentApproversLength < parent.threshold) {
                /* Update the parent threshold if the current one is more than the children */
                await transactionalEntityManager.update(TransactionApprover, parent.id, {
                  threshold: newParentApproversLength,
                });
              }
            }

            return approver;
          }

          /* Get the new parent */
          const newParent = await transactionalEntityManager.findOne(TransactionApprover, {
            relations: ['approvers'],
            where: { id: dto.listId },
          });

          /* Check if the new parent exists and is tree */
          if (!newParent) throw new Error(this.PARENT_APPROVER_NOT_FOUND);
          if (typeof newParent.threshold !== 'number') throw new Error(this.THRESHOLD_REQUIRED);

          /* Check if the new parent is not a child of the approver */
          const approverList = await this.getTransactionApproversById(
            approver.id,
            transactionalEntityManager,
          );
          if (approverList.some(a => a.id === dto.listId))
            throw new Error(this.CANNOT_SET_CHILD_AS_PARENT);

          /* Check if the parent's root transaction is the same */
          const parentRoot = await this.getRootNodeFromNode(dto.listId, transactionalEntityManager);
          if (parentRoot?.transactionId !== transactionId)
            throw new Error(this.ROOT_TRANSACTION_NOT_SAME);

          /* Update the list id and sets the transaction id to null */
          await transactionalEntityManager.update(TransactionApprover, approver.id, {
            listId: dto.listId,
            transactionId: null,
          });
          approver.listId = dto.listId;
          approver.transactionId = null;
          updated = true;

          return approver;
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
        } else if (typeof dto.userId === 'number') {
          /* Check if the approver is a tree */
          if (typeof approver.threshold === 'number') throw new Error(this.APPROVER_IS_TREE);

          /* Check if the user exists */
          const userCount = await transactionalEntityManager.count(User, {
            where: { id: dto.userId },
          });
          if (userCount === 0) throw new Error(this.USER_NOT_FOUND(dto.userId));

          /* Update the user */
          if (approver.userId !== dto.userId) {
            const data: DeepPartial<TransactionApprover> = {
              userId: dto.userId,
              userKeyId: undefined,
              signature: undefined,
              approved: undefined,
            };

            approver.userKeyId = undefined;
            approver.signature = undefined;
            approver.approved = undefined;

            await transactionalEntityManager.update(TransactionApprover, approver.id, data);
            approver.userId = dto.userId;
            updated = true;

            return approver;
          }
        }

        return approver;
      });

      if (updated) {
        emitTransactionUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);
      }

      return approver;
    } catch (error) {
      throw new BadRequestException(error.message);
    }
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L584-588)
```typescript
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);
```
