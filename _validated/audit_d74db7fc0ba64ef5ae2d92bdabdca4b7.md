All referenced code has been verified. The claim is accurate across every cited location.

- `cutoffAt` is documented as a signing deadline [1](#0-0) 
- It is accepted as an optional DTO field [2](#0-1) 
- It is persisted at creation time [3](#0-2) 
- It is exposed in the response DTO [4](#0-3) 
- `validateTransactionStatus` in `signers.service.ts` never reads it [5](#0-4) 
- `importSignatures` in `transactions.service.ts` also never reads it [6](#0-5) 

Nothing in SECURITY.md excludes this — it is not a best-practice recommendation, not theoretical, and not out of scope for a web application access-control finding.

---

# Audit Report

## Title
`cutoffAt` Signing Deadline Is Stored But Never Enforced — Signers Can Submit Signatures After the Creator's Intended Cutoff

## Summary
The `cutoffAt` field on the `Transaction` entity is documented as the timestamp after which the transaction can no longer be signed. It is accepted at creation, persisted to the database, and returned in the transaction DTO — but it is never consulted during signature submission. Any authenticated signer can upload a valid signature after the cutoff has passed, bypassing the creator's intended signing window.

## Finding Description
**Root cause — `validateTransactionStatus` in `signers.service.ts` (lines 201–215):**

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

  return null;   // ← cutoffAt is never consulted
}
```

The function checks only the DB `status` column and the Hedera SDK's own 180-second validity window (`isExpired`). The application-level `cutoffAt` deadline is never read. [5](#0-4) 

The same omission exists in the secondary `importSignatures` path in `transactions.service.ts`, which checks `status` and `isExpired` but not `cutoffAt`: [6](#0-5) 

`cutoffAt` is defined on the entity as a nullable `Date` column: [7](#0-6) 

It is documented explicitly as "the timestamp at which the transaction can no longer be signed by the signers": [1](#0-0) 

It is accepted via `CreateTransactionDto` and persisted at creation: [2](#0-1) [3](#0-2) 

It is returned in the transaction response DTO, making it visible to all signers: [4](#0-3) 

**Call path for the primary attack surface:**

`POST /transactions/:id/signers` → `SignersController.uploadSignatureMap` → `SignersService.uploadSignatureMaps` → `validateAndProcessSignatures` → `validateTransactionStatus` (no `cutoffAt` check) → signatures accepted and persisted. [8](#0-7) 

## Impact Explanation
A transaction creator sets `cutoffAt` to define a hard deadline after which no further signatures should be accepted — for example, to ensure that if the required signatories have not signed by a certain time, the transaction will not proceed. Because `cutoffAt` is never enforced server-side, any signer who holds a required key can submit their signature at any time after the cutoff, potentially pushing the transaction over the required-signature threshold and causing it to be executed. This constitutes an unauthorized state change: the transaction transitions from "stalled / effectively abandoned" to `WAITING_FOR_EXECUTION` against the creator's explicit intent.

## Likelihood Explanation
The attacker preconditions are minimal: the attacker must be an authenticated organization user whose public key is among the required signers for the transaction. No privileged access is needed. The attack is a single standard API call (`POST /transactions/:id/signers`) with a valid signature map submitted after `cutoffAt`. There is no rate-limiting or additional guard that would prevent this. Any signer who is aware of the cutoff field (it is returned in the transaction DTO) can trivially exploit this.

## Recommendation
Add a `cutoffAt` check inside `validateTransactionStatus` in `back-end/apps/api/src/transactions/signers/signers.service.ts` and the equivalent block in `importSignatures` in `back-end/apps/api/src/transactions/transactions.service.ts`:

```typescript
if (transaction.cutoffAt && new Date() > transaction.cutoffAt) {
  return ErrorCodes.TC; // Transaction Cutoff (new or existing error code)
}
```

This check should be inserted after the status check and before (or alongside) the `isExpired` check, so that it is evaluated on every signature submission attempt.

## Proof of Concept
1. Creator calls `POST /transactions` with `cutoffAt` set to `T+1 minute`.
2. Wait until `T+1 minute` has elapsed.
3. Signer calls `POST /transactions/:id/signers` with a valid `signatureMap`.
4. Server calls `validateTransactionStatus`, which checks only `status` (`WAITING_FOR_SIGNATURES`) and `isExpired` (false, since the Hedera SDK validity window is 180 seconds from `validStart`, independent of `cutoffAt`).
5. Both checks pass; the signature is persisted and `processTransactionStatus` is called.
6. If the new signature meets the threshold, the transaction status transitions to `WAITING_FOR_EXECUTION` — after the creator's intended cutoff.

### Citations

**File:** docs/database/tables/transaction.md (L22-22)
```markdown
| **cutoff_At**       | Timestamp | The timestamp at which the transaciton can no longer be signed by the signers.                                                                       |
```

**File:** back-end/apps/api/src/transactions/dto/create-transaction.dto.ts (L30-33)
```typescript
  @Type(() => Date)
  @IsDate()
  @IsOptional()
  cutoffAt?: Date;
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L452-452)
```typescript
            cutoffAt: data.cutoffAt,
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

**File:** back-end/apps/api/src/transactions/dto/transaction.dto.ts (L46-47)
```typescript
  @Expose()
  cutoffAt?: Date;
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L155-199)
```typescript
  private async validateAndProcessSignatures(
    dto: UploadSignatureMapDto[],
    user: User,
    transactionMap: Map<number, Transaction>,
    signersByTransaction: Map<number, Set<number>>
  ) {
    // Build user key lookup once
    const userKeyMap = new Map<string, UserKey>();
    for (const key of user.keys) {
      userKeyMap.set(key.publicKey, key);
    }

    return Promise.all(
      dto.map(async ({ id, signatureMap: map }) => {
        try {
          const transaction = transactionMap.get(id);
          if (!transaction) return { id, error: ErrorCodes.TNF };

          // Validate transaction status
          const statusError = this.validateTransactionStatus(transaction);
          if (statusError) return { id, error: statusError };

          // Process signatures
          const { sdkTransaction, userKeys, isSameBytes } = await this.processTransactionSignatures(
            transaction,
            map,
            userKeyMap,
            signersByTransaction.get(id) || new Set()
          );

          return {
            id,
            transaction,
            sdkTransaction,
            userKeys,
            isSameBytes,
            error: null,
          };
        } catch (err) {
          console.error(`[TX ${id}] Error:`, err.message);
          return { id, error: err.message };
        }
      })
    );
  }
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

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L129-130)
```typescript
  @Column({ nullable: true })
  cutoffAt?: Date;
```
