After thorough investigation of the codebase, I can identify a valid analog vulnerability.

---

### Title
Removed User's `TransactionApprover` Records Persist, Enabling Stale Approval Rights After Re-Registration

### Summary
When a user is removed from the organization via `removeUser`, their `TransactionApprover` records are not cleaned up. Because the system supports restoring a deleted user's account with the same user ID when re-invited by an admin, the re-registered user silently retains all previously assigned approval rights for in-flight transactions — without the admin's explicit intent.

### Finding Description

`removeUser` in `users.service.ts` soft-deletes the user and their `UserKey` records, but does **not** touch `TransactionApprover` records:

```typescript
async removeUser(id: number): Promise<boolean> {
  // ...
  await this.repo.manager.softDelete(UserKey, { userId: id });  // keys cleaned up
  await this.repo.softRemove(user);                             // user cleaned up
  // TransactionApprover records for this userId: NOT cleaned up
  return true;
}
``` [1](#0-0) 

When an admin re-invites the same email address, `createUser` detects the soft-deleted record and **restores the same user ID** with `deletedAt: null`:

```typescript
if (user) {
  if (!user.deletedAt) throw new UnprocessableEntityException('Email already exists.');
  return this.updateUser(user, { email, password, status: UserStatus.NEW, deletedAt: null });
}
``` [2](#0-1) 

This is confirmed by the e2e test `"(POST) should restore deleted user's account"`, which shows the restored user gets the same `id` and `createdAt` as before: [3](#0-2) 

The approver query in `getApproversByTransactionId` only filters on the approver record's own `deletedAt`, not on the associated user's `deletedAt`:

```sql
select * from approverList
where approverList."deletedAt" is null
``` [4](#0-3) 

So after re-registration, the user's old `TransactionApprover` rows are immediately visible and active again. Once the user adds a new key, `approveTransaction` will:
1. Find their approver records via `getVerifiedApproversByTransactionId`
2. Load their new key via `attachKeys`
3. Verify the signature against the transaction bytes (which passes for any valid key)
4. Record the approval [5](#0-4) 

**Attack sequence:**
1. Admin adds User B as an approver for Transaction T (threshold-based approval workflow)
2. Admin removes User B (`DELETE /users/:id`) — intending to revoke all access
3. `TransactionApprover` rows for User B remain in the database, not soft-deleted
4. Admin later re-invites User B for a different purpose (`POST /auth/signup` with same email)
5. User B is restored with the same user ID; their old approver records are immediately active
6. User B registers a new key and calls `POST /transactions/:id/approvers/approve`
7. User B's approval is accepted for Transaction T — without the admin realizing this stale right was retained

### Impact Explanation
A re-registered user retains approval authority over transactions they were assigned to before removal. In a multi-signature workflow where approvals gate execution of Hedera transactions (fund transfers, account updates, etc.), this means a user the admin believed was fully offboarded can still influence whether a transaction proceeds. The admin's mental model — "I removed this user, they have no rights" — is violated silently.

### Likelihood Explanation
Requires the admin to re-invite the same email address after removal. This is a realistic operational scenario (e.g., a contractor is offboarded and later re-engaged, or a user is removed and re-added after a dispute). The system explicitly supports this flow and the e2e tests confirm it works. No attacker-controlled action is needed beyond re-registration.

### Recommendation
In `removeUser`, also soft-delete (or hard-delete) all `TransactionApprover` records belonging to the user:

```typescript
async removeUser(id: number): Promise<boolean> {
  const user = await this.getUser({ id });
  if (!user) throw new BadRequestException(ErrorCodes.UNF);

  // Soft-delete all user keys
  await this.repo.manager.softDelete(UserKey, { userId: id });

+ // Remove all pending approver assignments for this user
+ await this.repo.manager.delete(TransactionApprover, { userId: id });

  await this.repo.softRemove(user);
  return true;
}
```

Alternatively, `getApproversByTransactionId` should join against the `user` table and filter out rows where the user's `deletedAt` is not null, so stale approver records for soft-deleted users are never surfaced.

### Proof of Concept

1. Admin creates Transaction T with User B as a required approver.
2. Admin calls `DELETE /users/:userBId` — User B is soft-deleted, keys are soft-deleted, but `transaction_approver` rows with `userId = userBId` remain with `deletedAt = null`.
3. Admin calls `POST /auth/signup` with User B's email — `createUser` restores the same row (`deletedAt = null`, same `id`).
4. User B logs in, calls `POST /user-keys` to register a new public key.
5. User B signs the transaction bytes locally with the new private key.
6. User B calls `POST /transactions/:transactionId/approvers/approve` with `{ userKeyId: <newKeyId>, signature: <sig>, approved: true }`.
7. `approveTransaction` finds User B's approver record (never cleaned up), verifies the signature, and records the approval — Transaction T advances toward execution. [1](#0-0) [6](#0-5)

### Citations

**File:** back-end/apps/api/src/users/users.service.ts (L36-39)
```typescript
    if (user) {
      if (!user.deletedAt) throw new UnprocessableEntityException('Email already exists.');
      return this.updateUser(user, { email, password, status: UserStatus.NEW, deletedAt: null });
    }
```

**File:** back-end/apps/api/src/users/users.service.ts (L156-170)
```typescript
  async removeUser(id: number): Promise<boolean> {
    const user = await this.getUser({ id });

    if (!user) {
      throw new BadRequestException(ErrorCodes.UNF);
    }

    // Soft-delete all user keys first
    await this.repo.manager.softDelete(UserKey, { userId: id });

    // Then soft-delete the user
    await this.repo.softRemove(user);

    return true;
  }
```

**File:** back-end/apps/api/test/spec/auth.e2e-spec.ts (L135-159)
```typescript
    it("(POST) should restore deleted user's account", async () => {
      const userRepo = await getRepository(User);
      const usersEndpoint = new Endpoint(server, '/users');
      const loginEndpoint = new Endpoint(server, '/auth/login');

      const user = await getUser('userNew');

      await usersEndpoint.delete(`${user.id}`, adminAuthToken).expect(200);

      await endpoint
        .post({ email: user.email }, null, adminAuthToken)
        .expect(201)
        .then(res => {
          expect(res.body).toEqual({
            id: expect.any(Number),
            email: user.email,
            createdAt: user.createdAt.toISOString(),
          });
        });

      const hashed = await hash(dummyNew.password);
      await userRepo.update({ id: user.id }, { password: hashed });

      await loginEndpoint.post({ email: user.email, password: dummyNew.password }).expect(200);
    });
```

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L546-621)
```typescript
  /* Approves a transaction */
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
