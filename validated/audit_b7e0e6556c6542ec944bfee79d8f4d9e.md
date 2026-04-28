Audit Report

## Title
Race Condition in `approveTransaction` Allows Replaced Approver to Corrupt Organizational Approval State

## Summary
`approveTransaction` in `approvers.service.ts` reads the approver list and performs its "already approved" guard outside a database transaction, then writes the approval inside a separate database transaction using stale record IDs. If the transaction creator replaces approver Bob with Charlie between Bob's read and Bob's write, Bob's signature and `approved=true` are committed to Charlie's approver record — corrupting the organizational approval workflow and allowing a transaction to advance without Charlie's actual consent.

## Finding Description

**Root cause — TOCTOU between read and write in `approveTransaction`:**

The approver list is fetched at line 553 via `getVerifiedApproversByTransactionId`, and the "already approved" guard fires at line 563 — both **outside** any database transaction. [1](#0-0) 

The write at lines 599–610 opens a **separate** DB transaction and updates rows using `.whereInIds(userApprovers.map(a => a.id))` — the IDs captured from the stale read. There is no re-validation of `userId` ownership inside the write transaction. [2](#0-1) 

**Concurrent mutation path — `updateTransactionApprover` changes `userId` with no transaction-status guard:**

When the creator replaces Bob with Charlie, the record's `userId`, `signature`, and `approved` are cleared — but the record's primary key (`id`) is unchanged. `updateTransactionApprover` contains no check that the transaction is in a terminal or locked status, so this mutation can happen at any time while the transaction is `WAITING_FOR_SIGNATURES`. [3](#0-2) 

**Race window:**

```
Bob calls approveTransaction
  → line 553: reads approver record {id:5, userId:Bob, signature:null}
  → line 563: passes guard (no signature yet)
  ← [PAUSE — async I/O gap]

Creator calls updateTransactionApprover({userId: Charlie})
  → DB transaction commits: record {id:5, userId:Charlie, signature:null, approved:null}

Bob's request resumes
  → line 599: opens DB transaction
  → whereInIds([5]) — same ID, now owned by Charlie
  → writes {userKeyId:Bob's key, signature:Bob's sig, approved:true}
  → commits

Result: record {id:5, userId:Charlie, signature:Bob's sig, approved:true}
```

## Impact Explanation

Charlie's approver record now carries Bob's cryptographic signature and `approved=true` without Charlie ever acting. The organizational approval workflow — the tool's mechanism for multi-party authorization of Hedera transactions — is corrupted:

- The system considers Charlie's approval slot satisfied.
- If the approval threshold is met by this corrupted state, the transaction advances to `WAITING_FOR_EXECUTION` without Charlie's actual consent.
- The creator's intent (requiring Charlie's approval) is silently bypassed.

The notification and status-update events at lines 612–618 fire based on the now-corrupted `approved` values, propagating the false state to all observers. [4](#0-3) 

## Likelihood Explanation

- Bob is a **normal authenticated user** — no privileged access required.
- Bob only needs to submit his approval request while the creator's `updateTransactionApprover` call is in-flight. In a multi-user organization, Bob may be notified (via WebSocket/email) that he is being replaced and can act immediately.
- The race window spans a full async I/O round-trip (DB read → network → DB write), making it wide enough to exploit deliberately or accidentally under load.
- No blockchain front-running is required; this is a standard HTTP API race against a PostgreSQL backend.

## Recommendation

Wrap the entire `approveTransaction` flow — from the initial approver read through the final write — in a single serializable database transaction with a `SELECT ... FOR UPDATE` lock on the approver rows. Specifically:

1. Move `getVerifiedApproversByTransactionId` (line 553) and the "already approved" guard (line 563) **inside** the `this.dataSource.transaction(...)` block that currently starts at line 599.
2. Inside that transaction, re-fetch the approver rows with a pessimistic write lock (e.g., TypeORM's `{ lock: { mode: 'pessimistic_write' } }`) so that a concurrent `updateTransactionApprover` call blocks until the approval write completes.
3. After re-fetching inside the transaction, re-validate that each approver record's `userId` still matches `user.id` before writing. If any record's `userId` has changed, abort with an appropriate error.
4. In `updateTransactionApprover`, add a guard that prevents changing `userId` when the transaction is in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` status, or alternatively acquire a lock on the approver row before mutating it. [5](#0-4) 

## Proof of Concept

```
1. Creator creates a transaction with approver Bob (record id=5, userId=Bob).
2. Bob sends POST /transactions/{id}/approvers/approve with a valid signature.
3. Server executes line 553: reads {id:5, userId:Bob, signature:null} — Bob passes the guard at line 563.
4. Before the server reaches line 599, creator sends PATCH /transactions/{id}/approvers/5 with {userId: Charlie}.
   - updateTransactionApprover commits: {id:5, userId:Charlie, signature:null, approved:null}.
5. Bob's request resumes at line 599:
   - Opens a new DB transaction.
   - Executes: UPDATE transaction_approver SET userKeyId=<Bob's key>, signature=<Bob's sig>, approved=true WHERE id IN (5)
   - Commits successfully — no userId check inside the write transaction.
6. DB state: {id:5, userId:Charlie, userKeyId=Bob's key, signature=Bob's sig, approved=true}
7. If threshold is now met, the transaction advances to WAITING_FOR_EXECUTION without Charlie's consent.
```

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L500-514)
```typescript
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
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L547-610)
```typescript
  async approveTransaction(
    dto: ApproverChoiceDto,
    transactionId: number,
    user: User,
  ): Promise<boolean> {
    /* Get all the approvers */
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
    });
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L612-618)
```typescript
    const notificationEvent = [{ entityId: transaction.id }];

    if (!dto.approved || userApprovers.every(a => a.approved)) {
      emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
    } else {
      emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
    }
```
