The code evidence confirms the claim. All key facts check out:

1. `cutoffAt` is defined on the entity and accepted in the DTO.
2. `validateTransactionStatus()` only checks status and SDK expiry — never `cutoffAt`.
3. The same gap exists in `importSignatures()`.

---

Audit Report

## Title
Signatures Can Be Submitted After `cutoffAt` Deadline Has Passed

## Summary
The `Transaction` entity defines a `cutoffAt` field documented as "The timestamp at which the transaction can no longer be signed by the signers." Neither the `SignersService.validateTransactionStatus()` method nor the `importSignatures()` path in `TransactionsService` ever compares the current time against `cutoffAt`, making the deadline entirely unenforced.

## Finding Description

The `cutoffAt` column is declared as a nullable `Date` on the `Transaction` entity: [1](#0-0) 

It is accepted as an optional field in `CreateTransactionDto`: [2](#0-1) 

Its semantic meaning is explicitly documented: [3](#0-2) 

When a signer calls `uploadSignatureMaps()`, the only pre-acceptance validation is `validateTransactionStatus()`: [4](#0-3) 

This method checks only two things: whether the transaction status is `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`, and whether the Hedera SDK transaction has expired via `isExpired()`. There is **no comparison of `transaction.cutoffAt` against `Date.now()`**.

The transaction object loaded in `loadTransactionData()` does include `cutoffAt` (it is fetched from the DB with no field exclusions): [5](#0-4) 

But the field is never read or compared anywhere in the signing flow.

The same gap exists in `TransactionsService.importSignatures()`, which performs an identical status + expiry check with no `cutoffAt` guard: [6](#0-5) 

## Impact Explanation
A transaction creator sets `cutoffAt` to enforce a time-bounded signing window. Because neither signing path enforces this deadline, any authorized signer can submit valid signatures after it has passed. If the late signature is the threshold-completing one, `processTransactionStatus` will advance the transaction to `WAITING_FOR_EXECUTION` and it will be submitted to the Hedera network — after the creator explicitly intended to close the signing window. This is an integrity violation: the creator's access-control intent is silently bypassed.

## Likelihood Explanation
The only precondition is being an authenticated user who is a designated signer on a transaction that has `cutoffAt` set. No privilege escalation is required. The condition is trivially reachable: a signer simply submits their signature after the deadline (whether due to network delay, intentional timing, or any other reason). The endpoint `POST /transactions/signers` is reachable by any authenticated organization member listed as a signer.

## Recommendation
Add a `cutoffAt` check inside `validateTransactionStatus()` in `signers.service.ts` and the equivalent block in `importSignatures()` in `transactions.service.ts`. Before accepting a signature, if `transaction.cutoffAt` is set and `new Date() > transaction.cutoffAt`, reject the request with an appropriate error code (e.g., a new `ErrorCodes.TCD` — "Transaction Cutoff Deadline passed"). Example guard to add in `validateTransactionStatus()`:

```typescript
if (transaction.cutoffAt && new Date() > transaction.cutoffAt) {
  return ErrorCodes.TCD; // Transaction cutoff deadline has passed
}
```

The same guard should be added to the `importSignatures()` path in `transactions.service.ts` immediately after the expiry check.

## Proof of Concept
1. Creator calls `POST /transactions` with `cutoffAt` set to `T+1 minute`.
2. Signer waits until `T+2 minutes` (after the deadline).
3. Signer calls `POST /transactions/signers` with a valid `UploadSignatureMapDto`.
4. `validateTransactionStatus()` is called — it checks status (`WAITING_FOR_SIGNATURES` ✓) and `isExpired()` (false, since Hedera `validStart + transactionValidDuration` has not elapsed ✓).
5. No `cutoffAt` check is performed. The signature is accepted, persisted, and `processTransactionStatus` is invoked.
6. If this is the threshold-completing signature, the transaction advances to `WAITING_FOR_EXECUTION` and is submitted to the Hedera network, violating the creator's deadline.

### Citations

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L129-130)
```typescript
  @Column({ nullable: true })
  cutoffAt?: Date;
```

**File:** back-end/apps/api/src/transactions/dto/create-transaction.dto.ts (L30-33)
```typescript
  @Type(() => Date)
  @IsDate()
  @IsOptional()
  cutoffAt?: Date;
```

**File:** docs/database/tables/transaction.md (L22-22)
```markdown
| **cutoff_At**       | Timestamp | The timestamp at which the transaciton can no longer be signed by the signers.                                                                       |
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L131-133)
```typescript
    const transactions = await this.dataSource.manager.find(Transaction, {
      where: { id: In(transactionIds) },
    });
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L534-543)
```typescript
        /* Checks if the transaction is canceled */
        if (
          transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
          transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
        )
          throw new BadRequestException(ErrorCodes.TNRS);

        /* Checks if the transaction is expired */
        const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
        if (isExpired(sdkTransaction)) throw new BadRequestException(ErrorCodes.TE);
```
