Based on my code review, all critical claims are verified against the actual source. Here is the audit report:

---

Audit Report

## Title
Missing `cutoffAt` Deadline Enforcement in Signature Upload and Approval Flows

## Summary
The `Transaction` entity defines a `cutoffAt` field representing the creator-specified signing deadline. Neither `SignersService.validateTransactionStatus()` nor `ApproversService.approveTransaction()` checks this field against the current time, allowing signers and approvers to submit valid signatures after the creator's intended deadline has passed.

## Finding Description

The `Transaction` entity declares `cutoffAt` as a nullable `Date` column: [1](#0-0) 

This value is accepted from the creator and persisted at transaction creation time: [2](#0-1) 

However, `SignersService.validateTransactionStatus()` — the gating function called before every signature upload — only checks the status enum and SDK-level expiry. There is no comparison of `transaction.cutoffAt` against the current time: [3](#0-2) 

The same omission exists in `ApproversService.approveTransaction()`. After verifying approver identity and transaction status, the method proceeds to record the approval signature without ever checking `cutoffAt`: [4](#0-3) 

The status check at lines 584–588 only guards against terminal states (`EXECUTED`, `CANCELED`, etc.). A transaction in `WAITING_FOR_SIGNATURES` with an expired `cutoffAt` passes this check unconditionally. [5](#0-4) 

## Impact Explanation
**Medium.** The creator's `cutoffAt` deadline is silently ignored. A transaction intended to be frozen at a specific time can still accumulate signatures and be pushed into `WAITING_FOR_EXECUTION` — and subsequently submitted to the Hedera network — after the creator's intended deadline. For time-sensitive multi-sig workflows (e.g., governance votes, time-bounded fund transfers), this breaks the creator's explicit intent and the integrity of the signing window.

## Likelihood Explanation
**Medium.** The `cutoffAt` field is optional (nullable), so this only affects transactions where the creator explicitly sets a deadline. Any authenticated signer or approver with a valid key can trigger this after the deadline passes, with no privileged access required beyond normal participation in the transaction.

## Recommendation
Add a `cutoffAt` guard in both `validateTransactionStatus` (signers) and `approveTransaction` (approvers). For example, in `validateTransactionStatus`:

```typescript
if (transaction.cutoffAt && new Date() > transaction.cutoffAt) {
  return ErrorCodes.TC; // Transaction cutoff exceeded
}
```

And in `approveTransaction`, after the status check at line 588:

```typescript
if (transaction.cutoffAt && new Date() > transaction.cutoffAt) {
  throw new BadRequestException(ErrorCodes.TC);
}
```

A new error code (e.g., `TC` — Transaction Cutoff) should be added to the `ErrorCodes` enum. The same guard should be applied to `TransactionsService.importSignatures()` if it follows the same pattern.

## Proof of Concept

1. Creator calls `POST /transactions` with `cutoffAt` set to `T+5min`.
2. At `T+6min` (after cutoff), a signer calls `POST /transactions/:id/signers` with a valid signature map.
3. `validateTransactionStatus` is invoked:
   - `transaction.status === WAITING_FOR_SIGNATURES` → passes
   - `isExpired(sdkTransaction)` → false (Hedera SDK validity window, typically 3 minutes from `validStart`, may still be open or the transaction may have been created with a future `validStart`)
   - `cutoffAt` is never checked → passes
4. The signature is persisted. If this is the threshold-completing signature, `processTransactionStatus` transitions the transaction to `WAITING_FOR_EXECUTION` and it is automatically submitted to the Hedera network — all after the creator's intended deadline. [6](#0-5) [3](#0-2)

### Citations

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L129-130)
```typescript
  @Column({ nullable: true })
  cutoffAt?: Date;
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L976-976)
```typescript
      cutoffAt: dto.cutoffAt,
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L173-175)
```typescript
          // Validate transaction status
          const statusError = this.validateTransactionStatus(transaction);
          if (statusError) return { id, error: statusError };
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L201-215)
```typescript
  private validateTransactionStatus(transaction: Transaction): string | null {
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    ) {
      return ErrorCodes.TNRS;
    }

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    if (isExpired(sdkTransaction)) {
      return ErrorCodes.TE;
    }

    return null;
  }
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
