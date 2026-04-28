### Title
Creator Can Reduce Approval Threshold After Approvals Are Collected, Bypassing Multi-Signature Requirement

### Summary
The `updateTransactionApprover` function in `approvers.service.ts` allows the transaction creator to lower the threshold of an approver tree at any time, with no check on transaction status or whether approvals have already been recorded. This is the direct analog to the external report: just as `token.balanceOf` counts frozen tokens that cannot actually be used, the approval-threshold check counts approvals that were given against a higher threshold — approvals that would not have been sufficient under the original requirement — once the creator silently reduces the threshold to match what has already been collected.

### Finding Description

In `back-end/apps/api/src/transactions/approvers/approvers.service.ts`, the `updateTransactionApprover` function handles threshold updates at lines 467–488:

```typescript
} else if (typeof dto.threshold === 'number') {
  if (typeof approver.threshold !== 'number' || typeof approver.userId === 'number')
    throw new Error(this.APPROVER_NOT_TREE);

  if (
    approver.approvers &&
    (dto.threshold > approver.approvers.length || dto.threshold === 0)
  )
    throw new Error(this.THRESHOLD_LESS_OR_EQUAL_APPROVERS(approver.approvers.length));

  if (approver.threshold !== dto.threshold) {
    await transactionalEntityManager.update(TransactionApprover, approver.id, {
      threshold: dto.threshold,
    });
    ...
  }
}
``` [1](#0-0) 

The only validation is that the new threshold must be `≤ children.length` and `> 0`. There is **no check on**:
1. The current transaction status (the creator can call this while the transaction is in `WAITING_FOR_SIGNATURES`)
2. Whether any child approvers have already recorded `approved = true`

The `getApproversByTransactionId` SQL query that feeds the status-evaluation pipeline only filters by `deletedAt IS NULL` on the `transaction_approver` table — it does not re-validate whether the stored `approved` values were given against the original threshold:

```sql
select * from approverList
where approverList."deletedAt" is null
``` [2](#0-1) 

The chain-service scheduler (`updateTransactions`) periodically calls `processTransactionStatus` over all transactions in `WAITING_FOR_SIGNATURES` / `WAITING_FOR_EXECUTION`. Once the threshold is lowered, the next scheduler tick will see the stored approvals satisfy the new (lower) threshold and advance the transaction to `WAITING_FOR_EXECUTION`. [3](#0-2) 

### Impact Explanation

A malicious transaction creator can unilaterally execute a transaction that was supposed to require approval from N designated approvers by collecting only K < N approvals and then reducing the threshold to K. The entire purpose of the organization-mode approval workflow — preventing a single actor from executing high-value or governance transactions without multi-party consent — is defeated. The creator can do this silently; the approvers who have not yet approved receive no indication that the threshold was changed.

### Likelihood Explanation

The attack requires only that the attacker be the creator of the transaction, which is a normal, unprivileged role reachable by any authenticated organization member. No admin keys, leaked secrets, or out-of-band access are needed. The API endpoint `PATCH /transactions/{transactionId}/approvers/{id}` is publicly documented and the payload is a single JSON field. The attack is deterministic and reproducible.

### Recommendation

In `updateTransactionApprover`, before allowing a threshold change, verify that:
1. The transaction is still in `NEW` or `WAITING_FOR_SIGNATURES` status **and** no child approver has yet recorded a non-null `approved` value; **or**
2. When the threshold is changed, all existing `approved` / `signature` / `userKeyId` values on child approvers are cleared (invalidated), forcing re-approval under the new threshold.

Option 2 is safer because it preserves flexibility while ensuring approvals are always given against the current threshold.

### Proof of Concept

1. Authenticate as **User X** (creator). Create a transaction and add an approver tree:
   ```
   POST /transactions/{txId}/approvers
   { "approversArray": [{ "threshold": 2, "approvers": [{ "userId": A }, { "userId": B }] }] }
   ```
2. Authenticate as **User A**. Submit approval:
   ```
   POST /transactions/{txId}/approvers/approve
   { "userKeyId": ..., "signature": "...", "approved": true }
   ```
   At this point `approved = true` is stored for User A's `transaction_approver` row; threshold is still 2 →

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L92-107)
```typescript
    return (entityManager || this.repo).query(
      `
      with recursive approverList as
        (
          select * from transaction_approver 
          where "transactionId" = $1
            union all
              select approver.* from transaction_approver as approver
              join approverList on approverList."id" = approver."listId"
        )
      select * from approverList
      where approverList."deletedAt" is null
        ${userId ? 'and approverList."userId" = $2' : ''}
      `,
      userId ? [transactionId, userId] : [transactionId],
    );
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

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L130-161)
```typescript
  /* Checks if the signers are enough to sign the transactions and update their statuses */
  async updateTransactions(from: Date, to?: Date) {
    //Get the transaction, creatorKey, groupItem, and group. We need the group info upfront
    //in order to determine if the group needs to be processed together
    const transactions = await this.transactionRepo.find({
      where: {
        status: In([
          TransactionStatus.WAITING_FOR_SIGNATURES,
          TransactionStatus.WAITING_FOR_EXECUTION,
        ]),
        validStart: to ? Between(from, to) : MoreThan(from),
      },
      relations: {
        creatorKey: true,
        groupItem: {
          group: true,
        },
      },
      order: {
        validStart: 'ASC',
      },
    });

    const results = await processTransactionStatus(this.transactionRepo, this.transactionSignatureService, transactions);

    if (results.size > 0) {
      const events = Array.from(results.keys(), id => ({ entityId: id }));
      emitTransactionStatusUpdate(this.notificationsPublisher, events);
    }

    return transactions;
  }
```
