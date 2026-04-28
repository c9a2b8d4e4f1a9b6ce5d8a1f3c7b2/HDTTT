The code at the referenced lines is confirmed. Let me verify a few more details before rendering the final verdict.

All four required checks pass. The code confirms the exact pattern described.

- **Line 553**: `getVerifiedApproversByTransactionId` is called outside any DB transaction — stale snapshot at T1. [1](#0-0) 
- **Line 563**: Guard uses that stale `userApprovers` — no re-read inside the write transaction. [2](#0-1) 
- **Lines 599–610**: The `UPDATE` is unconditional — no `WHERE signature IS NULL`, no pessimistic lock, no optimistic-lock version check. [3](#0-2) 
- **Line 614**: Notification branch also uses the stale pre-write `userApprovers`, so the wrong event type can be emitted. [4](#0-3) 
- Nothing in `SECURITY.md` excludes this class of vulnerability; the attacker is a normal authenticated user and the attack requires no privileged access. [5](#0-4) 

---

# Audit Report

## Title
TOCTOU in `approveTransaction` Allows an Approver to Bypass the "Already Approved" Guard and Overwrite Their Approval Decision

## Summary
`approveTransaction` in `approvers.service.ts` reads approver state (including whether a signature already exists) outside any database transaction, checks a guard against that stale snapshot, then performs an unconditional `UPDATE` inside a separate transaction. Two concurrent requests from the same legitimate approver can both pass the guard and the second write will silently overwrite the first, allowing the approver to flip their committed decision — including reversing `approved: true` to `approved: false` — after the system believed the decision was locked in.

## Finding Description

**Root cause — stale read before guarded write:**

In `approveTransaction` (`back-end/apps/api/src/transactions/approvers/approvers.service.ts`, lines 547–621):

```
Line 553: const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);
          // DB read #1 — outside any transaction, snapshot at T1

Line 556: const userApprovers = approvers.filter(a => a.userId === user.id);

Line 563: if (userApprovers.every(a => a.signature))   // guard uses T1 snapshot
              throw new BadRequestException(ErrorCodes.TAP);

          // ... async work: attachKeys, findOne for transaction, signature verification ...

Lines 599–610: await this.dataSource.transaction(async transactionalEntityManager => {
                 await transactionalEntityManager
                   .createQueryBuilder()
                   .update(TransactionApprover)
                   .set({ userKeyId: dto.userKeyId, signature: dto.signature, approved: dto.approved })
                   .whereInIds(userApprovers.map(a => a.id))
                   .execute();
               });
               // DB write — inside a transaction, at T2
```

Three compounding defects:
1. The guard read (line 553) is outside the write transaction — no serializable isolation between check and write.
2. There is no re-read of the approver row inside the write transaction.
3. The `UPDATE` has no conditional clause (`WHERE signature IS NULL` or a version/timestamp column), so it overwrites unconditionally.

The same structural pattern exists in `uploadSignatureMaps` in `signers.service.ts`: `loadTransactionData` reads transaction status and existing signers at T1 (lines 131–152), `validateTransactionStatus` checks the stale status, and `persistSignatureChanges` writes at T2 (lines 317–341) — a canceled transaction between T1 and T2 will still have signatures persisted against it.

## Impact Explanation

In a multi-signature approval workflow the integrity of each approver's decision is a core invariant. By racing two concurrent HTTP POST requests to `/transactions/:id/approvers/approve`, a legitimate approver can:

- **Flip `approved: true` → `approved: false`** after the system has already recorded their approval, preventing a transaction from reaching its approval threshold and blocking execution.
- **Flip `approved: false` → `approved: true`** after the system has already recorded their rejection, pushing a transaction past its approval threshold when it should have been blocked.
- **Overwrite the stored signature** with a signature from a different key, corrupting the cryptographic audit trail.
- **Trigger incorrect notifications**: the notification branch at line 614 evaluates `userApprovers.every(a => a.approved)` against the stale pre-write snapshot, so `emitTransactionStatusUpdate` vs. `emitTransactionUpdate` may be emitted incorrectly, causing downstream state inconsistency in connected clients.

## Likelihood Explanation

The attacker is a **normal authenticated user** who is already a designated approver — no elevated privileges are required. Sending two concurrent HTTP requests is trivially achievable (`Promise.all` in a browser, two parallel `curl` calls, any HTTP client). The race window between the guard read (line 553) and the write commit (lines 599–610) spans multiple async DB calls (`attachKeys`, `findOne` for the transaction, signature verification), making it wide and reliably exploitable without any special timing.

## Recommendation

**Primary fix — move the guard read inside the write transaction with a pessimistic row lock:**

```typescript
await this.dataSource.transaction(async em => {
  // Re-read with a row-level lock so no concurrent request can interleave
  const lockedApprovers = await em
    .createQueryBuilder(TransactionApprover, 'a')
    .setLock('pessimistic_write')
    .where('a.id IN (:...ids)', { ids: userApprovers.map(a => a.id) })
    .getMany();

  if (lockedApprovers.every(a => a.signature))
    throw new BadRequestException(ErrorCodes.TAP);

  await em.createQueryBuilder()
    .update(TransactionApprover)
    .set({ userKeyId: dto.userKeyId, signature: dto.signature, approved: dto.approved })
    .where('id IN (:...ids) AND signature IS NULL', { ids: lockedApprovers.map(a => a.id) })
    .execute();
});
```

**Secondary fix — add a conditional `WHERE signature IS NULL` clause** as a defense-in-depth measure even if the lock is in place, so a concurrent commit that slips through still cannot overwrite an already-set signature.

**For `signers.service.ts`** — re-validate transaction status inside `persistSignatureChanges`'s write transaction before committing, or use `SELECT FOR UPDATE` on the transaction row.

## Proof of Concept

```typescript
// Attacker is a legitimate approver for transactionId = 42
const url = `/transactions/42/approvers/approve`;

const [resA, resB] = await Promise.all([
  fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ userKeyId: keyId, signature: sigA, approved: true }),
  }),
  fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ userKeyId: keyId, signature: sigB, approved: false }),
  }),
]);

// Both requests pass the guard at line 563 because both read signature = NULL at line 553.
// Request A commits first  → approved = true,  signature = sigA
// Request B commits second → approved = false, signature = sigB  (overwrites A)
// Final DB state: approved = false — approval has been reversed.
console.log(await resA.json()); // { success: true }
console.log(await resB.json()); // { success: true }
```

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L553-553)
```typescript
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L563-563)
```typescript
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L614-618)
```typescript
    if (!dto.approved || userApprovers.every(a => a.approved)) {
      emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
    } else {
      emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
    }
```

**File:** SECURITY.md (L1-55)
```markdown
# Common Vulnerability Exclusion List

## Out of Scope & Rules

These are the default impacts recommended to projects to mark as out of scope for their bug bounty program. The actual list of out-of-scope impacts differs from program to program.

### General

- Impacts requiring attacks that the reporter has already exploited themselves, leading to damage.
- Impacts caused by attacks requiring access to leaked keys/credentials.
- Impacts caused by attacks requiring access to privileged addresses (governance, strategist), except in cases where the contracts are intended to have no privileged access to functions that make the attack possible.
- Impacts relying on attacks involving the depegging of an external stablecoin where the attacker does not directly cause the depegging due to a bug in code.
- Mentions of secrets, access tokens, API keys, private keys, etc. in GitHub will be considered out of scope without proof that they are in use in production.
- Best practice recommendations.
- Feature requests.
- Impacts on test files and configuration files, unless stated otherwise in the bug bounty program.

### Smart Contracts / Blockchain DLT

- Incorrect data supplied by third-party oracles.
- Impacts requiring basic economic and governance attacks (e.g. 51% attack).
- Lack of liquidity impacts.
- Impacts from Sybil attacks.
- Impacts involving centralization risks.

Note: This does not exclude oracle manipulation/flash-loan attacks.

### Websites and Apps

- Theoretical impacts without any proof or demonstration.
- Impacts involving attacks requiring physical access to the victim device.
- Impacts involving attacks requiring access to the local network of the victim.
- Reflected plain text injection (e.g. URL parameters, path, etc.).
- This does not exclude reflected HTML injection with or without JavaScript.
- This does not exclude persistent plain text injection.
- Any impacts involving self-XSS.
- Captcha bypass using OCR without impact demonstration.
- CSRF with no state-modifying security impact (e.g. logout CSRF).
- Impacts related to missing HTTP security headers (such as `X-FRAME-OPTIONS`) or cookie security flags (such as `httponly`) without demonstration of impact.
- Server-side non-confidential information disclosure, such as IPs, server names, and most stack traces.
- Impacts causing only the enumeration or confirmation of the existence of users or tenants.
- Impacts caused by vulnerabilities requiring unprompted, in-app user actions that are not part of the normal app workflows.
- Lack of SSL/TLS best practices.
- Impacts that only require DDoS.
- UX and UI impacts that do not materially disrupt use of the platform.
- Impacts primarily caused by browser/plugin defects.
- Leakage of non-sensitive API keys (e.g. Etherscan, Infura, Alchemy, etc.).
- Any vulnerability exploit requiring browser bugs for exploitation (e.g. CSP bypass).
- SPF/DMARC misconfigured records.
- Missing HTTP headers without demonstrated impact.
- Automated scanner reports without demonstrated impact.
- UI/UX best practice recommendations.
- Non-future-proof NFT rendering.

## Prohibited Activities
```
