### Title
TOCTOU Race Condition in `approveTransaction` Allows an Approver to Submit Conflicting Votes and Overwrite Their Own Approval

### Summary
The `approveTransaction` function in `ApproversService` performs a duplicate-approval check by reading the `signature` field from a snapshot fetched outside any database lock or transaction. Two concurrent HTTP requests from the same authenticated approver can both pass this guard simultaneously, then both write to the `transaction_approver` row. Because the update carries no `WHERE signature IS NULL` guard and the `TransactionApprover` entity has no unique constraint preventing re-approval, the second write silently overwrites the first, allowing an approver to flip their vote (`approved: true` → `approved: false` or vice versa) after the fact and corrupt the approval state machine.

### Finding Description

**Root cause — TOCTOU between check and write**

In `back-end/apps/api/src/transactions/approvers/approvers.service.ts`, `approveTransaction` follows this sequence:

1. **Read** (line 553): fetch all approvers from the DB into an in-memory snapshot.
2. **Check** (line 563): guard against double-approval by inspecting the snapshot — `if (userApprovers.every(a => a.signature)) throw`.
3. **Write** (lines 599–610): open a DB transaction and `UPDATE transaction_approver SET signature=…, approved=… WHERE id IN (…)`.

The check (step 2) and the write (step 3) are **not atomic**. There is no `SELECT … FOR UPDATE`, no advisory lock, and no `WHERE signature IS NULL` condition on the `UPDATE`. Two concurrent requests that arrive before either write completes will both see `signature = null` in their snapshot, both pass the guard, and both proceed to write. [1](#0-0) [2](#0-1) 

**No database-level guard**

The `TransactionApprover` entity declares no unique constraint on `(userId, transactionId)` and no partial unique index on `(userId, transactionId) WHERE signature IS NOT NULL`. The `signature` and `approved` columns are simply nullable with no uniqueness enforcement. [3](#0-2) 

**Stale snapshot corrupts notification logic**

After the write, the notification branch at line 614 evaluates `userApprovers.every(a => a.approved)` against the **pre-write** snapshot (where `approved` is still `undefined`/`null`). This means the status-update event (`emitTransactionStatusUpdate`) may not fire even when the approval threshold has been reached, stalling the transaction lifecycle. [4](#0-3) 

**Exploit flow**

1. Attacker is a legitimate approver for transaction T.
2. Attacker sends two concurrent POST requests to `POST /transactions/:id/approvers/approve`:
   - Request A: `{ approved: true, signature: sigA, userKeyId: k }`
   - Request B: `{ approved: false, signature: sigB, userKeyId: k }`
3. Both requests call `getVerifiedApproversByTransactionId` and read `signature = null` from the DB.
4. Both pass the guard at line 563.
5. Both proceed through signature verification (both signatures are valid — they sign the same transaction body).
6. Request A writes `approved=true, signature=sigA`.
7. Request B writes `approved=false, signature=sigB`, overwriting A.
8. The final DB state records the approver as having **rejected** the transaction, even though they submitted an approval first (or vice versa).

The attacker controls which write lands last by timing or by sending the "flip" request with a slight delay after the first passes the guard. [5](#0-4) 

### Impact Explanation

- **Approval state manipulation**: An approver can effectively cast two votes — one approve and one reject — and control which one persists. This can flip a transaction from approved to rejected (or vice versa), directly affecting whether a Hedera transaction is submitted to the network.
- **Threshold bypass / block**: In a multi-approver threshold setup, a malicious approver can approve to satisfy a threshold, then immediately race to overwrite with a rejection, causing the threshold to no longer be met and permanently stalling the transaction.
- **Notification desync**: The stale-snapshot bug in the notification branch means `emitTransactionStatusUpdate` may not fire after a legitimate approval, leaving the chain service unaware that the transaction is ready for execution.

Severity: **High** — directly affects the integrity of the multi-signature approval workflow and can prevent or corrupt Hedera transaction execution.

### Likelihood Explanation

- **Attacker preconditions**: The attacker must be a registered user who has been assigned as an approver for a transaction. This is a normal, non-privileged role in the organization workflow.
- **Exploit complexity**: Sending two concurrent HTTP requests is trivial from any HTTP client. No special tooling, network position, or cryptographic capability is required beyond possessing a valid session token and a key that can sign the transaction body.
- **No rate limiting or idempotency key** is present on the `/approve` endpoint. [6](#0-5) 

### Recommendation

1. **Add a `WHERE signature IS NULL` condition to the UPDATE** so that a second concurrent write is a no-op if the first already committed:

   ```sql
   UPDATE transaction_approver
   SET signature = $1, approved = $2, userKeyId = $3
   WHERE id IN (…) AND signature IS NULL
   ```

   In TypeORM QueryBuilder:
   ```typescript
   .update(TransactionApprover)
   .set({ userKeyId: dto.userKeyId, signature: dto.signature, approved: dto.approved })
   .whereInIds(userApprovers.map(a => a.id))
   .andWhere('signature IS NULL')   // ← atomic guard
   .execute();
   ```
   Check the affected row count; if 0, the approval was already recorded and the request should be rejected.

2. **Move the duplicate-approval check inside the DB transaction** using `SELECT … FOR UPDATE` (pessimistic locking) so the read and write are atomic.

3. **Re-fetch `userApprovers` after the write** (or use the `approved` value from `dto`) when deciding which notification event to emit, to eliminate the stale-snapshot bug at line 614.

4. **Add a partial unique index** at the database level as a defence-in-depth measure:
   ```sql
   CREATE UNIQUE INDEX uq_approver_signed
     ON transaction_approver (transaction_id, user_id)
     WHERE signature IS NOT NULL AND deleted_at IS NULL;
   ```

### Proof of Concept

```
# Precondition: user U is an approver for transaction T (id=42), key id=7
# U has a valid session cookie and can produce two valid signatures sigA, sigB

# Fire both requests concurrently (e.g. with curl --parallel or two async fetch calls)

curl -X POST https://api/transactions/42/approvers/approve \
  -H "Cookie: session=..." \
  -d '{"userKeyId":7,"signature":"<sigA>","approved":true}' &

curl -X POST https://api/transactions/42/approvers/approve \
  -H "Cookie: session=..." \
  -d '{"userKeyId":7,"signature":"<sigB>","approved":false}' &

wait

# Expected (correct) behaviour: second request returns 400 TAP (already approved)
# Actual behaviour: both return 200; DB row ends up with whichever write landed last.
# If the "approved:false" write lands second, the transaction is recorded as rejected
# despite the approver having submitted an approval.
``` [7](#0-6) [2](#0-1)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L547-621)
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

    const notificationEvent = [{ entityId: transaction.id }];

    if (!dto.approved || userApprovers.every(a => a.approved)) {
      emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
    } else {
      emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
    }

    return true;
  }
```

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L17-65)
```typescript
@Entity()
@Index(['transactionId'])
@Index(['userId'])
export class TransactionApprover {
  @PrimaryGeneratedColumn()
  id: number;

  /* If the approver has a listId, then transactionId should be null */
  @ManyToOne(() => Transaction, transaction => transaction.approvers, {
    nullable: true,
  })
  @JoinColumn({ name: 'transactionId' })
  transaction?: Transaction;

  @Column({ nullable: true })
  transactionId?: number;

  @ManyToOne(() => TransactionApprover, approverList => approverList.approvers, {
    nullable: true,
  })
  @JoinColumn({ name: 'listId' })
  list?: TransactionApprover;

  @Column({ nullable: true })
  listId?: number;

  @Column({ nullable: true })
  threshold?: number;

  @ManyToOne(() => UserKey, userKey => userKey.approvedTransactions, { nullable: true })
  @JoinColumn({ name: 'userKeyId' })
  userKey?: UserKey;

  @Column({ nullable: true })
  userKeyId?: number;

  @Column({ type: 'bytea', nullable: true })
  signature?: Buffer;

  @ManyToOne(() => User, user => user.approvableTransactions, { nullable: true })
  @JoinColumn({ name: 'userId' })
  user?: User;

  @Column({ nullable: true })
  userId?: number;

  @Column({ nullable: true })
  approved?: boolean;

```

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L65-73)
```typescript
  @Post('/approve')
  @OnlyOwnerKey<ApproverChoiceDto>('userKeyId')
  approveTransaction(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() body: ApproverChoiceDto,
  ): Promise<boolean> {
    return this.approversService.approveTransaction(body, transactionId, user);
  }
```
