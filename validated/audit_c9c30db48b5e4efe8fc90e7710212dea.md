### Title
TOCTOU Race Condition in `approveTransaction` Allows Approver to Bypass "Already Approved" Guard and Submit Conflicting Votes

### Summary
The `approveTransaction` function in `approvers.service.ts` reads the approver state from the database **outside** the write transaction, creating a Time-of-Check-Time-of-Use (TOCTOU) window. Two concurrent HTTP requests from the same authenticated approver can both pass the "already approved" guard and both write conflicting approval states (`approved: true` / `approved: false`), with the last write winning non-deterministically. This is the direct analog of the ERC20 approve/transferFrom race condition: a check-then-act pattern with no atomic protection between the read and the write.

### Finding Description

In `back-end/apps/api/src/transactions/approvers/approvers.service.ts`, the `approveTransaction` function performs its guard check and its write in two separate, uncoordinated database operations:

**Step 1 — Read (outside any transaction or lock):** [1](#0-0) 

`getVerifiedApproversByTransactionId` issues a plain `SELECT` with no `FOR UPDATE` lock. The result is stored in `userApprovers`. The guard `if (userApprovers.every(a => a.signature))` uses this snapshot.

**Step 2 — Write (inside a separate transaction, but no re-check):** [2](#0-1) 

The write transaction does **not** re-read the approver rows under a lock before updating. It blindly applies the update to the IDs collected in Step 1.

**The gap:** Between the `SELECT` at line 553 and the `UPDATE` at line 600–609, there is no pessimistic lock, no optimistic version check, and no re-validation inside the write transaction. Two concurrent requests from the same user both read `signature = NULL`, both pass the guard at line 563, and both proceed to write. The last write wins.

The controller endpoint is publicly reachable by any authenticated approver with no concurrency control: [3](#0-2) 

### Impact Explanation

An approver (malicious normal user) can:

1. Send two concurrent `POST /transactions/:id/approvers/approve` requests — one with `approved: true`, one with `approved: false` — before either has written to the database.
2. Both requests read `signature = NULL` and pass the guard.
3. Both write. The last write wins, producing a non-deterministic final approval state.

**Concrete consequence:** If Request A (`approved: true`) writes first and the approval threshold is met, the notification system fires `emitTransactionStatusUpdate`, which triggers the chain scheduler to move the transaction toward execution. Request B (`approved: false`) then overwrites the approver record. The transaction's on-chain execution state and the stored approver record are now inconsistent — the transaction may execute despite the stored record showing a rejection, or the threshold re-evaluation may flip the status back, causing an unexpected state transition.

Additionally, the guard that is supposed to prevent an approver from voting twice (`ErrorCodes.TAP`) is rendered ineffective under concurrent load, allowing an approver to overwrite their own vote at will by racing two requests before either commits. [4](#0-3) 

### Likelihood Explanation

- **Attacker profile:** A malicious approver — a normal authenticated user with no elevated privileges. This is explicitly in scope per `RESEARCHER.md` ("Malicious normal user abusing valid product/protocol flows").
- **Preconditions:** The attacker must be a designated approver for the target transaction. No admin access, no leaked credentials, no network-level access required.
- **Exploit mechanics:** Sending two concurrent HTTP requests is trivially achievable with any HTTP client (`Promise.all`, `curl` with `&`, etc.). No special tooling needed.
- **Window size:** The TOCTOU window spans multiple async `await` calls (DB reads, key attachment, signature verification) — a window of tens to hundreds of milliseconds, easily exploitable without precise timing.

### Recommendation

Move the "already approved" check **inside** the write transaction and acquire a pessimistic row-level lock on the approver rows before reading:

```typescript
await this.dataSource.transaction(async em => {
  // Re-read with FOR UPDATE to serialize concurrent approvals
  const rows = await em.query(
    `SELECT * FROM transaction_approver WHERE id = ANY($1) FOR UPDATE`,
    [userApprovers.map(a => a.id)],
  );
  if (rows.every((r: any) => r.signature !== null)) {
    throw new BadRequestException(ErrorCodes.TAP);
  }
  await em.createQueryBuilder()
    .update(TransactionApprover)
    .set({ userKeyId: dto.userKeyId, signature: dto.signature, approved: dto.approved })
    .whereInIds(rows.map((r: any) => r.id))
    .execute();
});
```

This collapses the check and the write into a single atomic, serialized operation, eliminating the TOCTOU window.

### Proof of Concept

**Preconditions:** User `Alice` is a designated approver for transaction ID `42`. Her approver record has `signature = NULL`.

**Steps:**

```typescript
// Send two concurrent requests before either commits
const [r1, r2] = await Promise.all([
  fetch('POST /transactions/42/approvers/approve', {
    body: { userKeyId: aliceKeyId, signature: aliceSig, approved: true }
  }),
  fetch('POST /transactions/42/approvers/approve', {
    body: { userKeyId: aliceKeyId, signature: aliceSig, approved: false }
  }),
]);
// Both return HTTP 200. The DB row for Alice's approver now has
// approved = <whichever request committed last> — non-deterministic.
```

**Expected (correct) behavior:** The second request should receive `ErrorCodes.TAP` (already approved).

**Actual behavior:** Both requests succeed. The final `approved` value is determined by commit order, not by Alice's intent. If the threshold was met by the `approved: true` write and the chain scheduler fired before the `approved: false` write committed, the transaction proceeds to execution with an inconsistent approver record.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L552-563)
```typescript
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
