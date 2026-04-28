I have now read the actual code. Let me verify the exact behavior of the `isNode` check and the `createTransactionApprovers` duplicate-user path.

All three code paths are confirmed by the actual source. The vulnerability is real.

---

## Audit Report

## Title
Single User Approval Satisfies Multiple Threshold Positions via Duplicate Approver Entries

## Summary
A malicious transaction creator can insert the same `userId` under multiple distinct threshold-group nodes (different `listId` values). Because `isNode` only guards against duplicate `(listId, userId)` pairs, the insertion succeeds. When that user calls `approveTransaction` once, every one of their `TransactionApprover` records is updated in a single bulk query, simultaneously satisfying all threshold groups they occupy and collapsing a multi-party threshold to a single-party approval.

## Finding Description

**Root cause 1 — `isNode` only prevents duplicate `(listId, userId)` pairs**

`isNode` in `approvers.service.ts` builds its duplicate-detection query using the specific `listId` of the incoming node:

```typescript
where: {
  listId: typeof approver.listId === 'number' ? approver.listId : null,
  userId: typeof approver.userId === 'number' ? approver.userId : null,
  ...
  transactionId: typeof approver.listId === 'number' ? null : transactionId,
},
``` [1](#0-0) 

The guard fires only when the same user already exists **under the same parent**. Inserting the same `userId` under a different `listId` (a different threshold group) produces a different query key and passes the check. [2](#0-1) 

**Root cause 2 — duplicate insertion is not blocked; existing approval data is merely copied**

When `createTransactionApprovers` detects that the user already exists somewhere in the tree (lines 318-330), it copies the existing signature/approval state into the new record — but does **not** throw or abort. The `insert` at line 336 proceeds unconditionally:

```typescript
if (userApproverRecords.length > 0) {
  data.signature = userApproverRecords[0].signature;
  data.userKeyId = userApproverRecords[0].userKeyId;
  data.approved   = userApproverRecords[0].approved;
}
// ... insert proceeds regardless
await transactionalEntityManager.insert(TransactionApprover, approver);
``` [3](#0-2) 

**Root cause 3 — `approveTransaction` bulk-updates every record belonging to the user**

`approveTransaction` collects **all** `TransactionApprover` rows for the calling user across the entire recursive tree and stamps them all with the same signature in one query:

```typescript
const userApprovers = approvers.filter(a => a.userId === user.id);
// ...
await transactionalEntityManager
  .createQueryBuilder()
  .update(TransactionApprover)
  .set({ userKeyId: dto.userKeyId, signature: dto.signature, approved: dto.approved })
  .whereInIds(userApprovers.map(a => a.id))
  .execute();
``` [4](#0-3) 

The "already approved" guard at line 563 (`userApprovers.every(a => a.signature)`) only blocks a second call after **all** records are signed — it does not prevent the first call from signing multiple positions simultaneously. [5](#0-4) 

## Impact Explanation
Any authenticated user who can create transactions can bypass the organization's multi-party approval policy entirely. By placing a single colluding user under every required threshold group, that user's one approval call satisfies all groups at once, allowing high-value or administrative transactions to execute without the consent of the other designated approvers.

## Likelihood Explanation
No elevated privileges are required. Any authenticated transaction creator can craft the malicious approver tree via a standard API call to `POST /transactions/:id/approvers`, then call `POST /transactions/:id/approvers/approve` once. No cryptographic weakness, race condition, or special timing is involved — only a crafted JSON payload.

## Recommendation

1. **Enforce per-transaction uniqueness of `userId`** in `createTransactionApprovers`: after the `isNode` check, query `getApproversByTransactionId(transactionId, dtoApprover.userId)` and throw if any record is returned (the existing copy-and-continue logic at lines 318-330 should become a hard rejection). [6](#0-5) 

2. **Limit `approveTransaction` to updating only one record per call**: instead of bulk-updating all `userApprovers`, require the caller to specify which approver position they are signing (e.g., by `approver.id`) and update only that record. [7](#0-6) 

## Proof of Concept

```
POST /transactions/42/approvers
{
  "approversArray": [
    {
      "threshold": 2,
      "approvers": [
        {
          "threshold": 1,
          "approvers": [{ "userId": 99 }]   // Alice under Group A (listId = A)
        },
        {
          "threshold": 1,
          "approvers": [{ "userId": 99 }]   // Alice under Group B (listId = B)
        }
      ]
    }
  ]
}
```

Both leaf insertions pass `isNode` because their `listId` values differ (A ≠ B). [1](#0-0) 

```
POST /transactions/42/approvers/approve   (called once, as Alice)
{ "userKeyId": 7, "signature": "...", "approved": true }
```

`userApprovers` now contains both Alice records (Group A leaf and Group B leaf). Both are updated in the single `whereInIds` query. Group A threshold (1-of-1) is met; Group B threshold (1-of-1) is met; root threshold (2-of-2) is met — with only Alice's single approval call. [4](#0-3)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L249-251)
```typescript
          /* Check if the approver already exists */
          if (await this.isNode(dtoApprover, transactionId, transactionalEntityManager))
            throw new Error(this.APPROVER_ALREADY_EXISTS);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L318-336)
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
          }

          /* Create approver */
          const approver = transactionalEntityManager.create(TransactionApprover, data);

          /* Insert approver */
          await transactionalEntityManager.insert(TransactionApprover, approver);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L556-609)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L652-665)
```typescript
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
