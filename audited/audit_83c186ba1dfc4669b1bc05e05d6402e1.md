### Title
Manual Transaction Permanently Locked When Creator Account Is Removed — Overly Strict Access Control on `executeTransaction`

### Summary
The `PATCH /transactions/execute/:id` endpoint in the API service enforces creator-only access via `getTransactionForCreator`, making the transaction creator a single point of failure for manual transaction execution. If the creator's account is removed from the organization (a routine admin operation), any manual transaction they created is permanently stuck in `WAITING_FOR_EXECUTION` state with no recovery path — not even for admins. The same creator-only gate also blocks `cancelTransaction` and `archiveTransaction`, leaving the record unresolvable.

### Finding Description

**Root cause — `getTransactionForCreator` enforces creator-only access with no admin bypass:** [1](#0-0) 

```typescript
async getTransactionForCreator(id: number, user: User) {
  const transaction = await this.getTransactionById(id);
  if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

  if (transaction.creatorKey?.userId !== user?.id)
    throw new UnauthorizedException('Only the creator has access to this transaction');

  return transaction;
}
```

This function is called unconditionally by all three lifecycle-management operations:

- `executeTransaction` [2](#0-1) 
- `archiveTransaction` [3](#0-2) 
- `cancelTransaction` / `cancelTransactionWithOutcome` [4](#0-3) 

The controller exposes these as unelevated `PATCH` endpoints with no admin-override path: [5](#0-4) 

**The scheduler explicitly skips manual transactions**, so they are never auto-executed: [6](#0-5) 

```typescript
addExecutionTimeout(transaction: Transaction) {
  ...
  if (transaction.isManual) return;   // manual transactions are intentionally excluded
  ...
}
```

**Exploit flow:**

1. User A (creator) submits a manual transaction (`isManual: true`) via `POST /transactions`.
2. Multiple other organization members sign it; the transaction reaches `WAITING_FOR_EXECUTION`.
3. An admin removes User A via `DELETE /users/:id` (a routine, legitimate admin operation).
4. User A can no longer authenticate; `PATCH /transactions/execute/:id`, `/cancel/:id`, and `/archive/:id` all throw `401 Unauthorized` for every caller because `transaction.creatorKey?.userId` no longer matches any active user.
5. The transaction record is permanently stuck. The chain service never touches it. No recovery endpoint exists.

The e2e test suite itself confirms the creator-only enforcement is intentional and absolute: [7](#0-6) 

### Impact Explanation

A fully-signed manual transaction that has collected signatures from multiple organization members becomes permanently unresolvable. The transaction bytes stored in the database can never be submitted to Hedera, and the record cannot be canceled or archived. All signing effort is wasted. In organizations that use manual transactions for high-value or time-sensitive Hedera operations (e.g., treasury transfers, account updates), this constitutes a permanent operational lock with no in-system recovery path.

**Severity: Medium** — no on-chain funds are directly locked (the transaction was never submitted), but the signed transaction is irrecoverable and the organization's workflow is permanently disrupted for that record.

### Likelihood Explanation

The trigger is a normal, expected admin operation: removing a departed employee or a compromised account. No attacker capability is required. Any organization that:
- uses manual transactions, **and**
- ever removes a user who created one

will hit this silently. The admin has no warning that removing the user will permanently lock their pending manual transactions.

### Recommendation

Remove the creator-only gate from `executeTransaction` (and optionally `cancelTransaction`/`archiveTransaction`) and replace it with a broader authorization check — for example, allow any organization admin to trigger execution/cancellation of any transaction, mirroring the fix applied in the referenced `collectFees` PR 315. The destination of execution is fixed (the Hedera network), so permitting any admin to trigger it does not introduce a privilege-escalation risk.

```typescript
// Instead of:
const transaction = await this.getTransactionForCreator(id, user);

// Use:
const transaction = await this.getTransactionById(id);
if (!transaction) throw new BadRequestException(ErrorCodes.TNF);
if (transaction.creatorKey?.userId !== user?.id && !user.admin)
  throw new UnauthorizedException('Only the creator or an admin can execute this transaction');
```

### Proof of Concept

1. Register two users: `creator` and `admin`.
2. As `creator`, `POST /transactions` with `isManual: true`.
3. As `creator`, upload a valid signature via `POST /transactions/:id/signers`.
4. As `admin`, `DELETE /users/:creatorId` — this succeeds (HTTP 200).
5. Attempt `PATCH /transactions/execute/:id` as `admin` → **HTTP 401** (`Only the creator has access to this transaction`).
6. Attempt `PATCH /transactions/cancel/:id` as `admin` → **HTTP 401**.
7. Attempt `PATCH /transactions/archive/:id` as `admin` → **HTTP 401**.
8. Confirm the transaction record remains in `WAITING_FOR_EXECUTION` indefinitely with no recovery path.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L659-663)
```typescript
  async cancelTransactionWithOutcome(
    id: number,
    user: User,
  ): Promise<CancelTransactionOutcome> {
    const transaction = await this.getTransactionForCreator(id, user);
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L708-709)
```typescript
  async archiveTransaction(id: number, user: User): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L736-737)
```typescript
  async executeTransaction(id: number, user: User): Promise<boolean> {
    const transaction = await this.getTransactionForCreator(id, user);
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L879-891)
```typescript
  async getTransactionForCreator(id: number, user: User) {
    const transaction = await this.getTransactionById(id);

    if (!transaction) {
      throw new BadRequestException(ErrorCodes.TNF);
    }

    if (transaction.creatorKey?.userId !== user?.id) {
      throw new UnauthorizedException('Only the creator has access to this transaction');
    }

    return transaction;
  }
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L280-286)
```typescript
  @Patch('/execute/:id')
  async executeTransaction(
    @GetUser() user,
    @Param('id', ParseIntPipe) id: number,
  ): Promise<boolean> {
    return this.transactionsService.executeTransaction(id, user);
  }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L352-358)
```typescript
  addExecutionTimeout(transaction: Transaction) {
    const name = `execution_timeout_${transaction.id}`;

    if (this.schedulerRegistry.doesExist('timeout', name)) return;

    if (transaction.isManual) return;

```

**File:** back-end/apps/api/test/spec/transaction.e2e-spec.ts (L936-944)
```typescript
    it('(PATCH) should fail if not creator', async () => {
      const transactionsEndpoint = new Endpoint(server, '/transactions');
      const transaction = await createTransaction(user, localnet1003);
      const { body: newTransaction } = await transactionsEndpoint
        .post({ ...transaction, isManual: true }, null, userAuthToken)
        .expect(201);

      await endpoint.patch(null, newTransaction.id.toString(), adminAuthToken).expect(401);
    });
```
