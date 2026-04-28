### Title
Silent Key-Fetch Failure in `computeSignatureKey` Causes Empty `KeyList`, Allowing Unsigned Transactions to Advance to `WAITING_FOR_EXECUTION`

### Summary

`TransactionSignatureService.computeSignatureKey` silently swallows all mirror-node lookup errors, returning an empty `KeyList` when account-info fetches fail. The downstream `hasValidSignatureKey` function treats an empty `KeyList` as fully satisfied (threshold `undefined || 0 = 0`, so `0 >= 0 = true`). As a result, any transaction — regardless of how many signatures it actually carries — can be promoted from `WAITING_FOR_SIGNATURES` to `WAITING_FOR_EXECUTION` whenever the mirror node is transiently unavailable. This is a direct analog to CVE-2020-26240 (CWE-682): incorrect state-transition logic caused by a silent arithmetic/logic shortcut.

---

### Finding Description

**Root cause — silent error swallowing in `computeSignatureKey`**

Every key-fetch helper catches its own exception and returns without adding any key to the accumulator `KeyList`: [1](#0-0) 

`addSigningAccountKeys` does the same per-account: [2](#0-1) 

If every mirror-node call throws (network timeout, rate-limit, outage), `computeSignatureKey` returns a `new KeyList()` with zero entries.

**Root cause — `hasValidSignatureKey` treats empty `KeyList` as satisfied** [3](#0-2) 

For an empty `KeyList`: `keys = []`, `currentThreshold = 0`, `key.threshold` is `undefined`, so the expression evaluates to `undefined || 0 = 0`. The check becomes `0 >= 0 = true` — the empty key list is considered fully satisfied.

**State-transition path**

`processTransactionStatus` calls both functions in sequence: [4](#0-3) 

When `isAbleToSign = true` (from the empty-KeyList bypass) and `smartCollate` returns non-null (any transaction within the 6 KB size limit), `newStatus` is set to `WAITING_FOR_EXECUTION` and the DB is updated: [5](#0-4) 

**Two reachable trigger points**

1. **User-triggered**: `SignersController.uploadSignatureMap` (POST `/transactions/:id/signers`, authenticated normal user) → `SignersService.uploadSignatureMaps` → `updateStatusesAndNotify` → `processTransactionStatus`. [6](#0-5) 

2. **Scheduler-triggered**: `TransactionSchedulerService.updateTransactions` runs every 10 seconds for near-term transactions and calls `processTransactionStatus` directly. [7](#0-6) 

**Execution path continues the same flaw**

`ExecuteService.getValidatedSDKTransaction` also calls `computeSignatureKey` + `hasValidSignatureKey`: [8](#0-7) 

If the mirror node is still unavailable at execution time, the same empty-KeyList bypass passes, and the SDK transaction is submitted to Hedera without the required signatures. Hedera rejects it; the system marks the transaction `FAILED` — an unrecoverable terminal state.

---

### Impact Explanation

- **State corruption**: A transaction is promoted to `WAITING_FOR_EXECUTION` without the required threshold of signatures, violating the core invariant of the multi-signature workflow.
- **Permanent lock**: If the scheduler picks up the corrupted transaction and the mirror node is still down, the transaction is submitted unsigned, Hedera rejects it, and the system permanently marks it `FAILED`. The transaction cannot be retried or recovered.
- **Integrity failure**: The `TransactionSigner` records and `transactionBytes` in the DB reflect a state that does not match the actual signature requirements, breaking audit integrity.

---

### Likelihood Explanation

**Attacker preconditions (no privilege required)**:
- Hold a valid JWT (normal authenticated user).
- Upload a signature map to any transaction they are a signer on while the mirror node is transiently unavailable.

Mirror-node unavailability is a realistic condition: network partitions, rate-limiting, rolling restarts, or a targeted DDoS against the mirror node endpoint (which is a public service). The scheduler path requires no user action at all — it fires automatically every 10 seconds.

**Mitigating factor**: `AccountCacheService` may serve cached responses for recently-fetched accounts, reducing the window. However, cache misses (cold start, cache expiry, new accounts) leave the path fully open.

**Overall**: Low-to-moderate. Requires a transient infrastructure failure coinciding with a scheduler tick or a user upload, but the scheduler runs continuously, making the coincidence window non-negligible.

---

### Recommendation

1. **Fail closed in `computeSignatureKey`**: If any required key fetch fails, propagate the error rather than silently omitting the key. The function should throw (or return a typed error) so callers can abort the status transition.

2. **Fix the empty-KeyList bypass in `hasValidSignatureKey`**: Replace `key.threshold || keys.length` with an explicit null/undefined check:
   ```typescript
   const required = key.threshold != null ? key.threshold : keys.length;
   return currentThreshold >= required;
   ```
   An empty `KeyList` with no threshold should require zero signatures only if that is the explicit intent; otherwise it should be treated as "all keys required."

3. **Guard `processTransactionStatus` against empty key lists**: Before promoting a transaction, assert that `signatureKey.toArray().length > 0`. If the key list is empty, skip the status update and log a warning rather than treating it as satisfied.

---

### Proof of Concept

**Preconditions**: Authenticated user `U` is a signer on transaction `T` (status `WAITING_FOR_SIGNATURES`). Mirror node is unreachable (e.g., DNS failure, timeout).

**Steps**:

1. User `U` sends `POST /transactions/T/signers` with a valid (or even empty) `signatureMap`.
2. `SignersService.uploadSignatureMaps` loads `T`, validates status (`WAITING_FOR_SIGNATURES` ✓), processes signatures, persists changes.
3. `updateStatusesAndNotify` calls `processTransactionStatus([T])`.
4. `computeSignatureKey(T)` attempts mirror-node lookups for fee payer and signing accounts — all throw due to outage — all errors are caught and swallowed. Returns `new KeyList()` (empty).
5. `hasValidSignatureKey([...sdkTransaction._signerPublicKeys], emptyKeyList)`:
   - `keys = []`, `currentThreshold = 0`
   - `0 >= (undefined || 0)` → `0 >= 0` → `true`
6. `smartCollate(T, emptyKeyList)` — transaction is small, not over max size → returns SDK transaction (non-null).
7. `newStatus = WAITING_FOR_EXECUTION`. DB update: `UPDATE transaction SET status = 'WAITING FOR EXECUTION' WHERE id = T AND status = 'WAITING FOR SIGNATURES'` — succeeds.
8. Transaction `T` is now in `WAITING_FOR_EXECUTION` with insufficient signatures.
9. Scheduler picks up `T`, calls `collateAndExecute`, which calls `getValidatedSDKTransaction` → same empty-KeyList bypass → submits unsigned transaction to Hedera → Hedera returns `INVALID_SIGNATURE` → transaction permanently marked `FAILED`.

**Expected outcome**: Transaction `T` is permanently corrupted to `FAILED` state without ever having the required signatures, bypassing the multi-signature threshold enforcement.

### Citations

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L87-98)
```typescript
    try {
      const accountInfo = await this.accountCacheService.getAccountInfoForTransaction(
        transaction,
        feePayerAccount,
      );
      if (accountInfo?.key) {
        signatureKey.push(accountInfo.key);
      }
    } catch (error) {
      this.logger.error(`Failed to get fee payer key: ${error.message}`);
      return null;
    }
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L109-121)
```typescript
    for (const account of signingAccounts) {
      try {
        const accountInfo = await this.accountCacheService.getAccountInfoForTransaction(
          transaction,
          account,
        );
        if (accountInfo?.key) {
          signatureKey.push(accountInfo.key);
        }
      } catch (error) {
        this.logger.error(`Failed to get key for account ${account}: ${error.message}`);
      }
    }
```

**File:** back-end/libs/common/src/utils/sdk/key.ts (L31-46)
```typescript
export const hasValidSignatureKey = (publicKeys: string[], key: Key) => {
  if (key instanceof KeyList) {
    const keys = key.toArray();
    let currentThreshold = 0;

    keys.forEach(key => {
      if (hasValidSignatureKey(publicKeys, key)) {
        currentThreshold++;
      }
    });

    return currentThreshold >= (key.threshold || keys.length);
  } else if (key instanceof PublicKey) {
    return publicKeys.includes(key.toStringRaw());
  } else throw new Error(`Invalid key type`);
};
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L132-146)
```typescript
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    const signatureKey = await transactionSignatureService.computeSignatureKey(transaction);
    const isAbleToSign = hasValidSignatureKey(
      [...sdkTransaction._signerPublicKeys],
      signatureKey
    );

    let newStatus = TransactionStatus.WAITING_FOR_SIGNATURES;

    if (isAbleToSign) {
      const collatedTx = await smartCollate(transaction, signatureKey);
      if (collatedTx !== null) {
        newStatus = TransactionStatus.WAITING_FOR_EXECUTION;
      }
    }
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L157-173)
```typescript
  if (updatesByStatus.size > 0) {
    await Promise.all(
      Array.from(updatesByStatus.values()).map(async ({ newStatus, oldStatus, ids }) => {
        const result = await transactionRepo
          .createQueryBuilder()
          .update(Transaction)
          .set({ status: newStatus })
          .where('id IN (:...ids) AND status = :oldStatus', { ids, oldStatus })
          .returning('id')
          .execute();

        for (const row of result.raw) {
          statusChanges.set(row.id, newStatus);
        }
      })
    );
  }
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

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L87-97)
```typescript
  @Cron(CronExpression.EVERY_10_SECONDS, {
    name: 'status_update_between_now_and_three_minutes',
  })
  async handleTransactionsBetweenNowAndAfterThreeMinutes() {
    const transactions = await this.updateTransactions(
      this.getThreeMinutesBefore(),
      this.getThreeMinutesLater(),
    );

    await this.prepareTransactions(transactions);
  }
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L215-222)
```typescript
    /* Gets the signature key */
    const signatureKey = await this.transactionSignatureService.computeSignatureKey(transaction);

    /* Checks if the transaction has valid signatureKey */
    if (!hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey))
      throw new Error('Transaction has invalid signature.');

    return sdkTransaction;
```
