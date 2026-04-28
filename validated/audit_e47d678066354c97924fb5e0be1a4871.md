### Title
Approver Can Reject a Transaction Already in `WAITING_FOR_EXECUTION` State, Permanently Blocking Execution

### Summary
The `approveTransaction` function in `approvers.service.ts` permits both approvals and rejections (`approved: false`) when a transaction is in `WAITING_FOR_EXECUTION` status — the state where all required signatures are collected and the transaction is ready to be submitted to the Hedera network. An approver who has not yet cast their vote can submit a rejection after the approval threshold is already met, moving the transaction to `REJECTED` and permanently preventing execution. This is the direct analog of the Llama M-02 finding.

### Finding Description
**Root cause — missing state guard for rejections in `WAITING_FOR_EXECUTION`:**

In `approvers.service.ts`, the only status guard before recording an approver's choice is:

```typescript
if (
  transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
  transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
)
  throw new BadRequestException(ErrorCodes.TNRA);
``` [1](#0-0) 

This guard applies identically to both `approved: true` and `approved: false`. There is no additional check that blocks a rejection once the transaction has already advanced to `WAITING_FOR_EXECUTION`.

**How `WAITING_FOR_EXECUTION` is reached:**

`SignersService.uploadSignatureMaps` calls `processTransactionStatus`. When the collected `signatureMap` satisfies the `ThresholdKey` requirements, the status is automatically promoted to `WAITING_FOR_EXECUTION`, meaning the transaction is ready for the `chain` service to submit to Hedera. [2](#0-1) 

**How a rejection in `WAITING_FOR_EXECUTION` causes permanent damage:**

After the approver record is updated with `approved: false`, the code at line 614 unconditionally emits `emitTransactionStatusUpdate` whenever `!dto.approved`:

```typescript
if (!dto.approved || userApprovers.every(a => a.approved)) {
  emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
}
``` [3](#0-2) 

This triggers the notification/receiver service to re-evaluate the transaction status. The receiver service maps the resulting `REJECTED` status to a terminal notification type, and the transaction is permanently moved to `REJECTED` — a terminal state from which there is no recovery path. [4](#0-3) 

**The "already voted" guard does not protect against this:**

The only guard that could prevent a second vote is:

```typescript
if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
``` [5](#0-4) 

This only blocks an approver who has **already** submitted a choice. An approver who has not yet voted — which is the normal case when a threshold (e.g., 2-of-3) is met before all approvers respond — can still submit `approved: false` after the transaction reaches `WAITING_FOR_EXECUTION`.

**The front-end confirms this is an exposed, reachable flow:**

The `ApproveTransactionController.vue` renders a "Reject transaction" button for any transaction in an approvable status, and `isApprovableStatus` explicitly returns `true` for `WAITING_FOR_EXECUTION`: [6](#0-5) 

### Impact Explanation
A transaction that has satisfied its approval threshold and is queued for Hedera network submission can be permanently killed by any single approver who has not yet cast their vote. The transaction moves to the terminal `REJECTED` state. The transaction creator, signers, and observers lose the ability to execute the transaction. There is no recovery path — the transaction cannot be re-queued or re-approved. In an organization managing time-sensitive Hedera operations (e.g., fee schedule updates, token operations), this causes irreversible loss of the intended on-chain action.

### Likelihood Explanation
The attacker must be a legitimately assigned approver for the target transaction — a role granted by the transaction creator to any organization member. In any threshold approval scheme (e.g., 2-of-3), at least one approver will routinely not have voted by the time the threshold is met. That approver can intentionally or accidentally submit a rejection after `WAITING_FOR_EXECUTION` is reached. No admin keys, no leaked credentials, and no privileged access beyond the normal approver role are required. The attack path is directly exposed through the standard REST API endpoint and the front-end UI.

### Recommendation
Add an explicit guard inside `approveTransaction` that blocks rejections once the transaction has already advanced to `WAITING_FOR_EXECUTION`. Rejections should only be permitted during the active approval window (`WAITING_FOR_SIGNATURES`):

```typescript
// After the existing status check:
if (!dto.approved && transaction.status === TransactionStatus.WAITING_FOR_EXECUTION) {
  throw new BadRequestException('Rejection window has closed: transaction is already ready for execution');
}
```

This mirrors the fix applied in the Llama protocol: disapprovals (rejections) are only valid while the action has not yet become executable.

### Proof of Concept

**Setup:** Organization with a 2-of-3 approver threshold on transaction T.

1. Approver A and Approver B both submit `approved: true`. The threshold (2) is met.
2. `processTransactionStatus` promotes T to `WAITING_FOR_EXECUTION`.
3. Approver C (who has not yet voted, so `userApprovers.every(a => a.signature)` is `false`) calls:
   ```
   PATCH /transactions/approvers/{transactionId}/approve
   Body: { userKeyId: <C's key>, signature: <valid sig>, approved: false }
   ```
4. The status guard at lines 584–588 passes because `WAITING_FOR_EXECUTION` is explicitly allowed.
5. Approver C's record is updated with `approved: false`.
6. `emitTransactionStatusUpdate` fires (line 614–615).
7. The receiver service re-evaluates T and sets status to `REJECTED`.
8. The `chain` service never submits T to Hedera. The transaction is permanently dead. [7](#0-6)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L563-563)
```typescript
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L583-620)
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
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.spec.ts (L1244-1251)
```typescript
      const transaction = {
        id: 1,
        status: TransactionStatus.WAITING_FOR_EXECUTION,
        transactionBytes: sdkTransaction.toBytes(),
        mirrorNetwork: 'testnet',
        creatorKey: { userId: user.id },
        observers: [{ userId: 1 }, { userId: 2 }],
      };
```

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L1049-1050)
```typescript
      const syncType = this.getInAppNotificationType(transaction.status);
      const emailType = this.getEmailNotificationType(transaction.status);
```

**File:** front-end/src/tests/renderer/pages/TransactionDetails/transactionStatusGuards.spec.ts (L71-75)
```typescript
  test('WAITING_FOR_EXECUTION is in-progress and approvable but not signable', () => {
    expect(isInProgressStatus(TransactionStatus.WAITING_FOR_EXECUTION)).toBe(true);
    expect(isSignableStatus(TransactionStatus.WAITING_FOR_EXECUTION)).toBe(false);
    expect(isApprovableStatus(TransactionStatus.WAITING_FOR_EXECUTION)).toBe(true);
  });
```
