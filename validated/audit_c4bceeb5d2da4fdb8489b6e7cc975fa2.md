### Title
Transaction Creator Can Add Themselves as Approver and Self-Approve, Bypassing Multi-Party Governance

### Summary
The `createTransactionApprovers` function in `approvers.service.ts` only verifies that the caller is the transaction creator before allowing approver assignment, but does not prevent the creator from designating themselves as an approver. The subsequent `approveTransaction` function similarly performs no check that the approving user is not the transaction creator. This allows a creator to unilaterally satisfy the approval requirement for their own transaction, defeating the entire purpose of the multi-party approval workflow.

### Finding Description

**Vulnerability class**: Authorization bypass (self-approval / role conflation)

**Root cause — `createTransactionApprovers`** [1](#0-0) 

The function gate-keeps on `getCreatorsTransaction` (only the creator may call it), but then proceeds to accept any `userId` in the DTO — including the creator's own `user.id` — without any exclusion check: [2](#0-1) 

The only validation performed on `dtoApprover.userId` is that the referenced user exists in the database. There is no guard of the form `if (dtoApprover.userId === user.id) throw ...`.

**Root cause — `approveTransaction`** [3](#0-2) 

The function checks that the caller is listed as an approver and has not already approved, but never checks whether the caller is also the transaction creator. Because the creator was able to insert themselves as an approver in the previous step, this check passes without issue.

**End-to-end exploit path**:
1. Attacker (a normal authenticated user) calls `POST /transactions` to create a transaction that requires organizational approval before execution.
2. Attacker calls `POST /transactions/:id/approvers` with `approversArray: [{ userId: <own user id> }]`. The `getCreatorsTransaction` guard passes because the attacker is the creator. No check prevents `userId === creatorId`.
3. Attacker calls `POST /transactions/:id/approvers/approve` with a valid signature. The `approveTransaction` function finds the attacker in the approver list, verifies the signature, and records approval.
4. If the attacker is the sole required approver (or satisfies a threshold), the transaction advances to `WAITING_FOR_EXECUTION` or executes — without any other organization member having reviewed or approved it.

### Impact Explanation

The approval system is the core governance control of Organization Mode. Its purpose is to enforce that sensitive Hedera transactions (account updates, node operations, large fund transfers, system file changes) cannot be executed by a single actor. By self-approving, the creator collapses a multi-party control into a single-party action. Depending on the threshold configuration, this can allow a single malicious or compromised user to execute arbitrary Hedera transactions — including `AccountUpdateTransaction` (key rotation), `NodeUpdateTransaction`, or token/HBAR transfers — without any peer review. [4](#0-3) 

### Likelihood Explanation

Any authenticated, verified organization member who can create transactions can trigger this. No privileged access, leaked credentials, or external dependencies are required. The attacker only needs a valid JWT and a registered key. The steps are entirely within normal API flows and require no special tooling.

### Recommendation

In `createTransactionApprovers`, after confirming the creator, reject any `userId` that matches the creator's own `user.id`:

```typescript
// In createTransactionApprovers, inside createApprover():
if (typeof dtoApprover.userId === 'number' && dtoApprover.userId === user.id) {
  throw new Error('Transaction creator cannot be designated as an approver');
}
```

Additionally, add a symmetric guard in `approveTransaction` as defense-in-depth:

```typescript
// In approveTransaction(), after fetching the transaction:
if (transaction.creatorKey?.userId === user.id) {
  throw new UnauthorizedException('Transaction creator cannot approve their own transaction');
}
``` [5](#0-4) 

### Proof of Concept

**Preconditions**: Two organization accounts exist — `Alice` (attacker/creator) and `Bob` (intended approver). The organization policy requires at least one approver before execution.

1. Alice authenticates and obtains a JWT.
2. Alice calls `POST /transactions` with a crafted `AccountUpdateTransaction` body (e.g., rotating the account key to one she controls). The transaction is saved with status `WAITING_FOR_SIGNATURES`.
3. Alice calls `POST /transactions/{id}/approvers` with body:
   ```json
   { "approversArray": [{ "userId": <Alice's userId> }] }
   ```
   This succeeds because Alice is the creator and no self-designation check exists.
4. Alice calls `POST /transactions/{id}/approvers/approve` with:
   ```json
   { "userKeyId": <Alice's keyId>, "signature": "<valid sig>", "approved": true }
   ```
   This succeeds because Alice is found in the approver list.
5. The transaction status advances. Alice has satisfied the approval requirement without Bob or any other member reviewing the transaction.
6. Alice calls `PATCH /transactions/execute/{id}` (if manual) or waits for automatic execution.

**Expected outcome**: The transaction executes on the Hedera network with only Alice's unilateral approval, bypassing the organization's multi-party governance model entirely. [6](#0-5)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-239)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L245-251)
```typescript
        const createApprover = async (dtoApprover: CreateTransactionApproverDto) => {
          /* Validate Approver's DTO */
          this.validateApprover(dtoApprover);

          /* Check if the approver already exists */
          if (await this.isNode(dtoApprover, transactionId, transactionalEntityManager))
            throw new Error(this.APPROVER_ALREADY_EXISTS);
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L547-563)
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
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L583-596)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L598-610)
```typescript
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
