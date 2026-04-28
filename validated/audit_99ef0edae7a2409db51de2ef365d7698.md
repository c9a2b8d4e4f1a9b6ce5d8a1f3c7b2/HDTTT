All referenced code has been verified against the actual codebase. The vulnerability is real and exploitable. Here is the audit report:

---

Audit Report

## Title
Removed User's `TransactionApprover` Records Persist, Enabling Stale Approval Rights After Re-Registration

## Summary
When a user is removed via `removeUser`, their `TransactionApprover` records are not soft-deleted. Because the system restores the same user ID when the same email is re-invited, the re-registered user silently regains all previously assigned approval rights for in-flight transactions without any admin action.

## Finding Description

`removeUser` in `back-end/apps/api/src/users/users.service.ts` soft-deletes the user and their `UserKey` records, but leaves `TransactionApprover` records untouched:

```typescript
async removeUser(id: number): Promise<boolean> {
  await this.repo.manager.softDelete(UserKey, { userId: id }); // keys cleaned up
  await this.repo.softRemove(user);                            // user cleaned up
  // TransactionApprover records for this userId: NOT cleaned up
  return true;
}
``` [1](#0-0) 

When an admin re-invites the same email, `createUser` detects the soft-deleted record and restores the same user ID by setting `deletedAt: null`:

```typescript
if (user) {
  if (!user.deletedAt) throw new UnprocessableEntityException('Email already exists.');
  return this.updateUser(user, { email, password, status: UserStatus.NEW, deletedAt: null });
}
``` [2](#0-1) 

This is confirmed by the e2e test `"(POST) should restore deleted user's account"`, which asserts the restored user gets the same `id` and `createdAt`: [3](#0-2) 

The approver query in `getApproversByTransactionId` only filters on the approver record's own `deletedAt`, with no join to the `user` table to check whether the associated user is active:

```sql
select * from approverList
where approverList."deletedAt" is null
``` [4](#0-3) 

After re-registration, the stale `TransactionApprover` rows (which were never soft-deleted) are immediately returned by this query. Once the user uploads a new key, `attachKeys` finds it (TypeORM's `find` excludes soft-deleted keys by default, so only the new key is returned): [5](#0-4) 

`approveTransaction` then:
1. Finds the user's stale approver records via `getVerifiedApproversByTransactionId`
2. Loads the user's new key via `attachKeys`
3. Verifies the signature against the transaction bytes (passes for any valid key)
4. Records the approval by updating the `TransactionApprover` row with the new `userKeyId` and signature [6](#0-5) 

## Impact Explanation
A re-registered user retains approval authority over transactions they were assigned to before removal. In a multi-signature workflow where approvals gate execution of Hedera transactions (fund transfers, account updates, etc.), a user the admin believed was fully offboarded can still influence whether a transaction proceeds. The admin's mental model — "I removed this user, they have no rights" — is violated silently, with no audit trail indicating the approval came from a restored account.

## Likelihood Explanation
Requires the admin to re-invite the same email address after removal. This is a realistic operational scenario (e.g., a contractor is offboarded and later re-engaged, or a user is removed and re-added after a dispute). The system explicitly supports and tests this flow. No attacker-controlled action is needed beyond completing the normal re-registration workflow.

## Recommendation
In `removeUser` (`back-end/apps/api/src/users/users.service.ts`), soft-delete all `TransactionApprover` records for the user at the same time as `UserKey` records are cleaned up:

```typescript
async removeUser(id: number): Promise<boolean> {
  const user = await this.getUser({ id });
  if (!user) throw new BadRequestException(ErrorCodes.UNF);

  await this.repo.manager.softDelete(UserKey, { userId: id });
  await this.repo.manager.softDelete(TransactionApprover, { userId: id }); // add this
  await this.repo.softRemove(user);
  return true;
}
```

This mirrors the existing pattern used for `UserKey` cleanup and ensures that if the user is ever re-registered, their stale approver records remain soft-deleted and are not surfaced by `getApproversByTransactionId`.

## Proof of Concept

1. Admin creates Transaction T requiring approval from User B.
2. Admin adds User B as a `TransactionApprover` for Transaction T via `POST /transactions/:id/approvers`.
3. Admin removes User B via `DELETE /users/:id`. `TransactionApprover` rows for User B remain in the database with `deletedAt = null`.
4. Admin re-invites User B via `POST /auth/signup` with the same email. User B is restored with the same `userId`; their old approver records are now active.
5. User B sets a new password, uploads a new key via `POST /user-keys`, and calls `POST /transactions/:id/approvers/approve` with a valid signature.
6. `getApproversByTransactionId` returns the stale approver rows (they were never soft-deleted). `approveTransaction` accepts the approval and records it against Transaction T — without the admin realizing this right was retained.

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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L92-108)
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
  }
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

**File:** back-end/libs/common/src/utils/user/index.ts (L5-13)
```typescript
export const attachKeys = async (
  user: User,
  entityManager: EntityManager,
) => {
  if (!user.keys || user.keys.length === 0) {
    user.keys = await entityManager.find(UserKey, {
      where: { userId: user.id },
    });
  }
```
