### Title
Single Approval Satisfies Multiple Threshold Slots Due to Cross-Branch Duplicate Approver Placement

### Summary
The `isNode` duplicate-check in `createTransactionApprovers` only prevents adding the same user to the **same parent node** (`listId`). It does not prevent the same user from being placed in **different branches** of the approver tree. When `approveTransaction` is called, it bulk-updates **all** approver records belonging to that user in a single query, causing one approval to simultaneously satisfy multiple threshold slots across different branches. A malicious transaction creator can exploit this to make a transaction appear to require N unique approvals while actually requiring fewer.

### Finding Description

**Root cause — `isNode` only checks same-parent uniqueness:** [1](#0-0) 

The `where` clause matches on `listId` + `userId` + `transactionId`. Adding User A under `listId=10` and then under `listId=20` produces two different queries; neither returns a count > 0 for the other, so both insertions succeed. The same user can therefore occupy multiple leaf nodes across different branches of the same transaction's approver tree.

**Compounding issue — existing approval is copied to new branches on creation:** [2](#0-1) 

When the creator adds a user who has **already approved** to a new branch, `getApproversByTransactionId` returns the existing record and its `signature`, `userKeyId`, and `approved` fields are immediately copied into the new record. The new branch is retroactively satisfied without any action from the approver.

**Approval bulk-update covers all slots for the user:** [3](#0-2) 

`userApprovers` collects every `TransactionApprover` row where `userId === user.id` across the entire tree. The duplicate-approval guard uses `every`:

```typescript
if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
```

If none have a signature yet, the guard passes. The subsequent `whereInIds(userApprovers.map(a => a.id))` bulk-update then stamps the signature on **all** of the user's slots simultaneously — one HTTP call, multiple threshold slots satisfied.

**Exploit flow:**

1. Creator creates a transaction and sets up an approver tree: threshold node with `threshold=2`, three children — User A at `listId=parentNode`, User A again at `listId=parentNode` (blocked by `isNode`) — but User A at `listId=parentNode1` and User A at `listId=parentNode2` (two different parent nodes, each allowed).
2. More concretely: root threshold node (threshold=2) → child threshold node 1 (threshold=1) → User A; child threshold node 2 (threshold=1) → User A; child threshold node 3 (threshold=1) → User B.
3. User A calls `POST /transactions/:id/approvers/approve` once.
4. `userApprovers` = [record in branch 1, record in branch 2]; both get the signature.
5. Both child threshold nodes are now satisfied; the root threshold of 2 is met.
6. Transaction proceeds to execution without User B's approval, despite the displayed structure implying 2-of-3 independent approvers are required.

### Impact Explanation
A malicious transaction creator can design an approver tree that visually and structurally implies a higher approval threshold than is actually enforced. Organizational members who inspect the tree see "threshold 2 of 3" and believe two independent parties must approve. In reality, a single user's approval satisfies two slots simultaneously, allowing the transaction to execute with fewer unique approvals than intended. This undermines the integrity of the multi-party approval governance model — the core security property of the organizational workflow.

### Likelihood Explanation
The attacker is the transaction creator, a role available to any authenticated organization user with no elevated privileges. The exploit requires only crafting a specific approver tree structure via the documented `POST /transactions/:id/approvers` API. No race conditions, cryptographic breaks, or external dependencies are required. Any creator who wants to reduce the effective approval threshold while concealing that reduction can do so deterministically.

### Recommendation

1. **Enforce global uniqueness of `userId` per transaction in `isNode`**: Change the check to query for any existing approver record with the same `userId` and `transactionId` (regardless of `listId`), not just the same parent.

```typescript
// Proposed fix in isNode:
const find = {
  where: {
    userId: typeof approver.userId === 'number' ? approver.userId : null,
    transactionId: transactionId,  // always scope to transaction
  },
};
```

2. **Remove the signature-copy behavior** at lines 318–329. A new approver slot should always start unsigned; copying an existing approval into a new slot is the mechanism that enables the retroactive-satisfaction attack.

3. **Validate uniqueness of `userId` values across the entire submitted tree** before any insertions, rejecting trees that contain the same `userId` in more than one leaf node.

### Proof of Concept

```
POST /transactions/:txId/approvers
{
  "approversArray": [
    {
      "threshold": 2,
      "approvers": [
        {
          "threshold": 1,
          "approvers": [{ "userId": 42 }]   // User A in branch 1
        },
        {
          "threshold": 1,
          "approvers": [{ "userId": 42 }]   // User A in branch 2 — isNode does NOT block this
        },
        {
          "threshold": 1,
          "approvers": [{ "userId": 99 }]   // User B in branch 3
        }
      ]
    }
  ]
}
```

User A calls `POST /transactions/:txId/approvers/approve` once with a valid signature.

`approveTransaction` executes:
- `userApprovers` = [row for User A in branch 1, row for User A in branch 2]
- `every(a => a.signature)` → false (neither has a signature yet) → guard passes
- `whereInIds([id_branch1, id_branch2])` → both rows updated with User A's signature

Both branch-1 and branch-2 threshold nodes are now `approved=true`. The root threshold of 2 is satisfied. User B's approval is never required. The transaction advances to execution. [4](#0-3) [5](#0-4) [2](#0-1)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L318-329)
```typescript
          if (typeof dtoApprover.userId === 'number') {
            const userApproverRecords = await this.getApproversByTransactionId(
              transactionId,
              dtoApprover.userId,
              transactionalEntityManager,
            );

            if (userApproverRecords.length > 0) {
              data.signature = userApproverRecords[0].signature;
              data.userKeyId = userApproverRecords[0].userKeyId;
              data.approved = userApproverRecords[0].approved;
            }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L553-609)
```typescript
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);

    /* If user is approver, filter the records that belongs to the user */
    const userApprovers = approvers.filter(a => a.userId === user.id);

    /* Check if the user is an approver */
    if (userApprovers.length === 0)
      throw new UnauthorizedException('You are not an approver of this transaction');

    /* Check if the user has already approved the transaction */
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);

    /* Ensures the user keys are passed */
    await attachKeys(user, this.dataSource.manager);
    if (user.keys.length === 0) return false;

    const signatureKey = user.keys.find(key => key.id === dto.userKeyId);

    /* Gets the public key that the signature belongs to */
    const publicKey = PublicKey.fromString(signatureKey?.publicKey);

    /* Get the transaction body */
    const transaction = await this.dataSource.manager.findOne(Transaction, {
      where: { id: transactionId },
      relations: { creatorKey: true, observers: true },
    });

    /* Check if the transaction exists */
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    /* Checks if the transaction is requires approval */
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    /* Verify the signature matches the transaction */
    if (
      !verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTransaction, dto.signature, publicKey)
    )
      throw new BadRequestException(ErrorCodes.SNMP);

    /* Update the approver with the signature */
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L647-665)
```typescript
  async isNode(
    approver: CreateTransactionApproverDto,
    transactionId: number,
    entityManager?: EntityManager,
  ) {
    const find: FindManyOptions<TransactionApprover> = {
      where: {
        listId: typeof approver.listId === 'number' ? approver.listId : null,
        userId: typeof approver.userId === 'number' ? approver.userId : null,
        threshold:
          typeof approver.threshold === 'number' && approver.threshold !== 0
            ? approver.threshold
            : null,
        transactionId: typeof approver.listId === 'number' ? null : transactionId,
      },
    };

    const count = await (entityManager || this.repo).count(TransactionApprover, find);
    return count > 0 && typeof approver.userId === 'number';
```
