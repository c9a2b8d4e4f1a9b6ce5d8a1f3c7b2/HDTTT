### Title
Silent Failure in Batch Signature Upload: `uploadSignatureMaps` Returns HTTP 201 on Per-Transaction Validation Errors Without Caller Notification

### Summary

`SignersService.uploadSignatureMaps` in `back-end/apps/api/src/transactions/signers/signers.service.ts` silently swallows per-transaction validation failures (transaction not found, wrong status, expired) and returns HTTP 201 with an empty `signers` array. The controller never checks whether any signatures were actually persisted before returning success to the caller. This is the direct analog of the external report: a function returns a zero/empty value instead of failing, and its caller does not validate the return before treating the operation as successful.

### Finding Description

**Root cause — two-layer silent discard:**

**Layer 1:** `validateAndProcessSignatures` wraps each per-transaction attempt in a `try/catch` and returns a plain object `{ id, error: err.message }` instead of propagating the exception. [1](#0-0) 

**Layer 2:** `persistSignatureChanges` iterates the results, logs the error string, and `continue`s — the failed transaction is silently dropped from all downstream processing. [2](#0-1) 

**Unchecked caller:** `uploadSignatureMaps` returns `{ signers: [], notificationReceiverIds: [] }` regardless of whether any signature was actually persisted. [3](#0-2) 

**Controller returns HTTP 201 unconditionally** after calling `uploadSignatureMaps`, with no check on whether `signers` is empty due to a real success (nothing new to add) or a silent failure (every transaction was rejected). [4](#0-3) 

The validation that is silently discarded includes: transaction not found (`ErrorCodes.TNF`), transaction in a non-signable status (`ErrorCodes.TNRS` — covers CANCELED, ARCHIVED, FAILED, EXECUTED, REJECTED), and transaction expired (`ErrorCodes.TE`). [5](#0-4) 

### Impact Explanation

Any client (front-end or API consumer) that submits a signature upload and receives HTTP 201 has no programmatic way to distinguish:

- **True success** — signature was accepted and persisted.
- **Silent failure** — every transaction in the batch was rejected (not found, wrong status, expired) and nothing was written.

In a multi-signature workflow, a user who believes they have signed a transaction (because they received 201) will not retry. If their signature was silently dropped, the transaction may never accumulate the required threshold of signatures, causing it to expire unexecuted. This is a state-integrity failure: the system's persisted state diverges from what the user and any downstream logic believe to be true. For organization-coordinated transactions requiring threshold key approval, this can permanently block execution of a transaction without any visible error.

### Likelihood Explanation

This is reachable by any authenticated user through the normal signing workflow. The most realistic trigger is a race condition: a transaction creator cancels or the transaction expires while a co-signer is in the process of uploading their signature map. The co-signer's POST to `/transactions/:id/signers` returns 201 with an empty body — indistinguishable from a legitimate "no new signers added" response. No privileged access is required; the attacker role is simply the transaction creator who cancels their own transaction while another party is signing.

### Recommendation

1. **Distinguish empty-by-design from empty-by-failure.** Return a structured response that includes per-transaction outcomes (success/error) so callers can detect which uploads were rejected and why.
2. **Return a non-2xx status (e.g., 400 or 207 Multi-Status) when all transactions in the batch fail validation**, rather than 201 with an empty array.
3. **Alternatively, throw a `BadRequestException` from `persistSignatureChanges`** when the entire batch is rejected, consistent with how the database-transaction failure is handled on line 344. [6](#0-5) 

### Proof of Concept

**Preconditions:** Two organization users, User A (transaction creator) and User B (required co-signer). A multi-sig transaction `TX-1` is in `WAITING_FOR_SIGNATURES` status.

1. User A cancels `TX-1` (sets status to `CANCELED`).
2. User B (unaware of the cancellation) signs the transaction bytes locally and POSTs to `POST /transactions/TX-1/signers` with a valid signature map.
3. Inside `validateAndProcessSignatures`, `validateTransactionStatus` returns `ErrorCodes.TNRS` because the status is `CANCELED`.
4. The result `{ id: TX-1, error: 'TNRS' }` is returned from the per-item handler.
5. `persistSignatureChanges` logs `[TX TX-1

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L99-124)
```typescript
  async uploadSignatureMaps(
    dto: UploadSignatureMapDto[],
    user: User,
  ): Promise<{ signers: TransactionSigner[]; notificationReceiverIds: number[] }> {
    // Load all necessary data
    const { transactionMap, signersByTransaction } = await this.loadTransactionData(dto);

    // Validate and process signatures
    const validationResults = await this.validateAndProcessSignatures(
      dto,
      user,
      transactionMap,
      signersByTransaction
    );

    // Persist changes to database
    const { transactionsToProcess, signers, notificationsToDismiss } = await this.persistSignatureChanges(validationResults, user);

    // Update transaction statuses and emit notifications
    await this.updateStatusesAndNotify(transactionsToProcess);

    return {
      signers: Array.from(signers),
      notificationReceiverIds: notificationsToDismiss,
    };
  }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L167-198)
```typescript
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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L282-286)
```typescript
    for (const result of validationResults) {
      if (result.error) {
        console.error(`[TX ${result.id}] Validation failed: ${result.error}`);
        continue;
      }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L342-344)
```typescript
    } catch (err) {
      console.error('Database transaction failed:', err);
      throw new BadRequestException(ErrorCodes.FST);
```

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L100-119)
```typescript
  @Post()
  @HttpCode(201)
  async uploadSignatureMap(
    @Body() body: UploadSignatureMapDto | UploadSignatureMapDto[],
    @GetUser() user: User,
    @Query('includeNotifications') includeNotifications?: boolean,
  ): Promise<TransactionSigner[] | UploadSignatureMapResponseDto> {
    const transformedSignatureMaps = await transformAndValidateDto(UploadSignatureMapDto, body);

    const { signers, notificationReceiverIds } = await this.signaturesService.uploadSignatureMaps(
      transformedSignatureMaps,
      user,
    );

    if (includeNotifications) {
      return { signers, notificationReceiverIds };
    }

    return signers;
  }
```
