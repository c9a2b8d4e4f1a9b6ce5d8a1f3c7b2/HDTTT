The code confirms all claims. Here is the audit report:

---

Audit Report

## Title
Creator Can Self-Approve Their Own Transaction, Bypassing Multi-Party Authorization

## Summary
The Hedera Transaction Tool's approval workflow has no guard preventing a transaction creator from designating themselves as an approver and then submitting their own approval. The two-party authorization requirement collapses to a single party, allowing any creator to unilaterally satisfy the approval requirement.

## Finding Description

**Step 1 — Creator adds themselves as an approver.**

`createTransactionApprovers` in `approvers.service.ts` first verifies the caller is the creator via `getCreatorsTransaction`: [1](#0-0) 

It then checks only that the designated `userId` exists in the `User` table: [2](#0-1) 

There is no check of the form `if (dtoApprover.userId === user.id) throw ...`. The creator's own `userId` passes all validation and is persisted as a `TransactionApprover` record.

**Step 2 — Creator approves their own transaction.**

`approveTransaction` fetches all approvers, filters for `a.userId === user.id`, and proceeds if the list is non-empty: [3](#0-2) 

There is no check that `user.id !== transaction.creatorKey.userId`. The creator's self-approval record satisfies the filter, and the approval is written: [4](#0-3) 

**Step 3 — No database-level constraint.**

The `TransactionApprover` entity defines `userId` as a simple nullable column with no constraint preventing it from matching the transaction creator's `userId`: [5](#0-4) 

## Impact Explanation
The approval system exists to enforce multi-party authorization before a transaction is executed. A creator who self-approves satisfies the approval requirement alone. The chain service will treat the approval as met and proceed to execution. Any organizational policy mandating independent sign-off from a second party is silently bypassed. The creator can unilaterally execute transactions that were supposed to require external authorization.

## Likelihood Explanation
Every authenticated user who creates a transaction is a potential attacker. No elevated privileges, leaked credentials, or external dependencies are required. The attack requires only two standard API calls (`POST /transactions/:id/approvers` and `POST /transactions/:id/approvers/approve`) that are part of the normal product workflow. It is trivially reproducible by any organization member.

## Recommendation
In `createTransactionApprovers`, after verifying the caller is the creator, add an explicit check rejecting any `dtoApprover.userId` that equals the creator's own `user.id`:

```typescript
if (dtoApprover.userId === user.id)
  throw new Error('The transaction creator cannot be designated as an approver');
```

This check should be applied recursively to nested approvers as well. Additionally, consider adding a corresponding guard in `approveTransaction` that rejects approval if `user.id === transaction.creatorKey.userId`, as defense-in-depth.

## Proof of Concept

```
# 1. Creator (userId=42) creates a transaction → transactionId=7

# 2. Creator adds themselves as the sole approver
POST /transactions/7/approvers
Authorization: Bearer <creator_token>
Body: { "approversArray": [{ "userId": 42 }] }
→ 201 Created (no error)

# 3. Creator approves their own transaction with a valid signature
POST /transactions/7/approvers/approve
Authorization: Bearer <creator_token>
Body: { "userKeyId": <keyId>, "signature": <validSig>, "approved": true }
→ 200 true (no error)

# Result: approval requirement is fully satisfied by the creator alone.
# The transaction proceeds to execution without any independent second-party sign-off.
```

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L239-239)
```typescript
    await this.getCreatorsTransaction(transactionId, user);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L271-277)
```typescript
          if (typeof dtoApprover.userId === 'number') {
            const userCount = await transactionalEntityManager.count(User, {
              where: { id: dtoApprover.userId },
            });

            if (userCount === 0) throw new Error(this.USER_NOT_FOUND(dtoApprover.userId));
          }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L553-560)
```typescript
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);

    /* If user is approver, filter the records that belongs to the user */
    const userApprovers = approvers.filter(a => a.userId === user.id);

    /* Check if the user is an approver */
    if (userApprovers.length === 0)
      throw new UnauthorizedException('You are not an approver of this transaction');
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L599-609)
```typescript
    await this.dataSource.transaction(async transactionalEntityManager => {
      await transactionalEntityManager
        .createQueryBuilder()
        .update(TransactionApprover)
        .set({
          userKeyId: dto.userKeyId,
          signature: dto.signature,
          approved: dto.approved,
        })
        .whereInIds(userApprovers.map(a => a.id))
        .execute();
```

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L56-61)
```typescript
  @ManyToOne(() => User, user => user.approvableTransactions, { nullable: true })
  @JoinColumn({ name: 'userId' })
  user?: User;

  @Column({ nullable: true })
  userId?: number;
```
