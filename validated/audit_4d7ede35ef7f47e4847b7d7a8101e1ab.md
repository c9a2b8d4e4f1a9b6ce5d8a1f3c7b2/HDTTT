Based on my code review, I can now produce the audit report. The primary claim is confirmed by the code. The secondary claim about `removeTransactionApprover` having "no authorization check at all" is inaccurate — the controller at line 108 calls `getCreatorsTransaction` before delegating to the service — but this does not affect the validity of the primary finding.

---

Audit Report

## Title
Transaction Creator Can Lower Approver Threshold After Partial Approval, Bypassing Multi-Approval Requirement

## Summary
`updateTransactionApprover` in `approvers.service.ts` allows the transaction creator to modify a threshold-type approver node's `threshold` value at any point in the transaction lifecycle, including after approvals have already been collected. Because no transaction-status guard is present, a creator can retroactively lower the required approval count to match the number of approvals already received, causing the transaction to be treated as fully approved without the originally-required number of sign-offs.

## Finding Description

**Root cause — missing status guard in `updateTransactionApprover`**

The function enforces only these invariants before writing a new threshold:

1. Caller is the transaction creator (`getCreatorsTransaction`, line 394).
2. The target node is a threshold-type node (line 469).
3. The new threshold is `≥ 1` and `≤ number of children` (lines 473–477). [1](#0-0) 

There is **no check** that the transaction is in a pre-approval state. The function proceeds to write the new threshold unconditionally: [2](#0-1) 

After the write, `emitTransactionUpdate` is fired, triggering downstream status recalculation with the new, lower threshold: [3](#0-2) 

**Contrast with `approveTransaction`**, which correctly gates on transaction status before allowing any approval action: [4](#0-3) 

**Secondary issue — `createTransactionApprovers` also missing a status guard**

`createTransactionApprovers` calls `getCreatorsTransaction` (line 239) but has no status check. Furthermore, when a new approver node is created for a `userId` that already has an approval record for the transaction, the service copies the existing `signature`/`approved` values into the new node: [5](#0-4) 

This means a creator can add a new approver node for a user who has already approved, inflating the apparent approval count without that user re-approving.

## Impact Explanation
A malicious transaction creator can unilaterally reduce the number of approvals required for their own transaction after the approval round has begun. In an organizational multi-signature workflow, this defeats the entire purpose of the approval gate: a single actor (the creator) can force a transaction to execution that the organization's policy required multiple independent parties to authorize. Depending on the transaction type (e.g., large HBAR transfers, account key rotations), this can result in unauthorized fund movement or unauthorized account changes on the Hedera network.

## Likelihood Explanation
The attacker is the transaction creator — a normal, authenticated user with no elevated privileges beyond owning the transaction. The exploit requires only a standard authenticated API call (`PATCH /transactions/{id}/approvers/{approverId}`) with a crafted `threshold` value. No special tooling, timing, or collusion is needed. The window of opportunity is the entire duration between transaction creation and final execution.

## Recommendation

1. **Add a transaction-status guard at the top of `updateTransactionApprover`** (and `createTransactionApprovers`). Before any write, fetch the transaction and reject the request if its status is not `WAITING_FOR_SIGNATURES` (i.e., if any approvals have already been collected or the transaction has advanced past the initial setup phase). Mirror the pattern already used in `approveTransaction`:

```typescript
if (transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES)
  throw new BadRequestException(ErrorCodes.TNRA);
```

2. **For `createTransactionApprovers`**, apply the same status guard so that new approver nodes cannot be injected after approvals have begun.

3. **Do not copy existing `signature`/`approved` values** when creating a new approver node (lines 318–329). A newly added approver should always start in an unapproved state, requiring a fresh approval action.

## Proof of Concept

1. Creator creates a transaction and sets up a threshold approver group: `threshold = 3`, children = [Alice, Bob, Carol].
2. Alice and Bob approve (`approved = true`, signatures stored).
3. Carol has not yet approved.
4. Creator calls:
   ```
   PATCH /transactions/{txId}/approvers/{groupId}
   Body: { "threshold": 2 }
   ```
5. `updateTransactionApprover` writes `threshold = 2` with no status check. [6](#0-5) 
6. `emitTransactionUpdate` fires; the approval-status evaluator now sees `approvals (2) >= threshold (2)` → **approved**.
7. The transaction advances to execution without Carol's approval, bypassing the originally-required 3-of-3 sign-off.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L318-329)
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
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L467-488)
```typescript
        } else if (typeof dto.threshold === 'number') {
          /* Check if the approver is a tree */
          if (typeof approver.threshold !== 'number' || typeof approver.userId === 'number')
            throw new Error(this.APPROVER_NOT_TREE);

          /* Check if the approver threshold is less or equal to the number of approvers */
          if (
            approver.approvers &&
            (dto.threshold > approver.approvers.length || dto.threshold === 0)
          )
            throw new Error(this.THRESHOLD_LESS_OR_EQUAL_APPROVERS(approver.approvers.length));

          /* Update the threshold */
          if (approver.threshold !== dto.threshold) {
            await transactionalEntityManager.update(TransactionApprover, approver.id, {
              threshold: dto.threshold,
            });
            approver.threshold = dto.threshold;
            updated = true;

            return approver;
          }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L523-525)
```typescript
      if (updated) {
        emitTransactionUpdate(this.notificationsPublisher, [{ entityId: transactionId }]);
      }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L584-588)
```typescript
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);
```
