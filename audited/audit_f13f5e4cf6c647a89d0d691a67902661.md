### Title
TOCTOU Race Condition in `approveTransaction` Allows Stale Approval to Overwrite a Reassigned Approver Slot

### Summary
`approveTransaction` in `approvers.service.ts` reads the approver list outside any database transaction, then writes the approval inside a separate database transaction keyed only by record ID. If the transaction creator reassigns an approver slot between the read and the write, the displaced approver's signature is written into the now-reassigned slot, marking the new approver as having consented without their knowledge.

### Finding Description
`approveTransaction` (`approvers.service.ts` lines 547–621) follows this sequence:

1. **Read** – `getVerifiedApproversByTransactionId` fetches all approver records and filters to those where `userId === user.id`. This read is **outside** any DB transaction. [1](#0-0) 

2. **Check** – if every record already has a signature, reject as already-approved. [2](#0-1) 

3. **Async gap** – `attachKeys`, a `findOne` for the transaction, and `verifyTransactionBodyWithoutNodeAccountIdSignature` all execute before the write. [3](#0-2) 

4. **Write** – the approval is persisted using `.whereInIds(userApprovers.map(a => a.id))` — filtered **only by record ID**, not by `userId`. [4](#0-3) 

Concurrently, `updateTransactionApprover` (only callable by the transaction creator) can change the `userId` of an approver record and clear its signature in a single DB transaction: [5](#0-4) 

**Race window exploit ordering:**

| Time | Bob's request | Creator's request |
|------|--------------|-------------------|
| T1 | Reads record ID=5 → `userId=Bob`, `signature=null` → passes check | — |
| T2 | — | Updates record ID=5 → `userId=Charlie`, `signature=null` (committed) |
| T3 | Writes `signature=Bob_sig`, `approved=true` to record ID=5 (no `userId` guard) | — |

**Final DB state:** record ID=5 has `userId=Charlie`, `signature=Bob_sig`, `approved=true`. Charlie's approver slot is now marked as approved without Charlie ever submitting a signature.

### Impact Explanation
Any downstream logic that checks whether an approver slot has a signature to determine threshold satisfaction will count Charlie's slot as approved. If this satisfies the required threshold, the Hedera transaction (which may be a token transfer, account update, or any other operation) is submitted to the network without Charlie's actual consent. The displaced approver (Bob) effectively forges Charlie's approval.

### Likelihood Explanation
The attacker must be a legitimate approver (Bob) for the target transaction. The creator must be in the process of reassigning Bob's slot to another user. Bob must observe or anticipate the creator's `PATCH /transactions/:id/approvers/:id` call and race his `POST /transactions/:id/approvers/approve` request so that his write lands after the creator's update commits. The async gap between the read and write in `approveTransaction` (three awaited operations) widens the race window, making this feasible under normal API load without any special tooling.

### Recommendation
Add a `userId` guard to the update query so the write is a no-op if the record has

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L499-517)
```typescript
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
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L552-556)
```typescript
    /* Get all the approvers */
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);

    /* If user is approver, filter the records that belongs to the user */
    const userApprovers = approvers.filter(a => a.userId === user.id);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L562-563)
```typescript
    /* Check if the user has already approved the transaction */
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L565-596)
```typescript
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
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L599-610)
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
    });
```
