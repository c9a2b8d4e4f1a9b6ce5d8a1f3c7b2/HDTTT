All code references have been verified against the actual repository. Here is the result:

---

Audit Report

## Title
Unbounded Loop in `getTransactionsToSign` Causes Server-Side DoS via Unbounded Database Fetch and Per-Transaction Mirror Node Calls

## Summary
`TransactionsService.getTransactionsToSign` fetches all non-terminal transactions from the database with no row limit, then performs sequential async mirror node HTTP calls and cache claim/poll operations for every transaction before applying pagination. Any authenticated user with at least one registered key can trigger this endpoint to cause unbounded server resource consumption that scales linearly with the total number of active transactions in the system.

## Finding Description

**Unbounded database fetch** — In `back-end/apps/api/src/transactions/transactions.service.ts`, the `getTransactionsToSign` method issues a `repo.find()` call with no `take` limit: [1](#0-0) 

**Per-transaction async work** — Every returned transaction is then processed sequentially in a `for...of` loop calling `userKeysToSign`, which internally calls `userKeysRequiredToSign` → `keysRequiredToSign` → `transactionSignatureService.computeSignatureKey` → `accountCacheService.getAccountInfoForTransaction`, potentially triggering a mirror node HTTP fetch per transaction: [2](#0-1) 

**Post-loop pagination** — Pagination is applied only after the full loop completes: [3](#0-2) 

**Cache claim/poll loop** — When a cache miss or stale entry occurs, `CacheHelper.tryClaimRefresh` polls with `maxAttempts = 20` at `pollIntervalMs = 500ms` — up to **10 seconds of blocking per account lookup per transaction**: [4](#0-3) 

**Contrast with correct pattern** — `getTransactionsToApprove` correctly applies `skip: offset, take: limit` at the database level before any iteration: [5](#0-4) 

**Broad status filter** — The `whereForUser` filter excludes only EXECUTED, FAILED, EXPIRED, CANCELED, and ARCHIVED. Notably, `REJECTED` (which is in `terminalStatuses`) is **not** excluded, meaning REJECTED transactions are also included in the unbounded fetch: [6](#0-5) 

The call chain from `userKeysToSign` through to `computeSignatureKey` and `getAccountInfoForTransaction` is confirmed: [7](#0-6) [8](#0-7) [9](#0-8) 

## Impact Explanation
As the number of active transactions grows, each call to `GET /transactions/sign` causes the server to:
1. Load **all** non-terminal transactions from the database into memory (no row cap).
2. For each transaction, perform one or more async mirror node HTTP calls and cache claim/poll operations sequentially.
3. Block the Node.js event loop for the cumulative duration of all sequential `await` calls — potentially tens of minutes for hundreds of transactions with cold caches.

This results in request timeouts, memory exhaustion, and degraded service for all concurrent users. A single authenticated user repeatedly calling this endpoint can sustain the condition indefinitely.

## Likelihood Explanation
- Any verified/authenticated user with at least one registered key can call this endpoint — no special role is required. The early-exit guard at line 286 only skips users with zero keys.
- The condition worsens naturally as the platform grows; no adversarial setup is needed beyond having many active transactions.
- The `PaginationParams` decorator enforces `size <= 100` on other endpoints, but `getTransactionsToSign` bypasses this entirely by fetching all rows before slicing. [10](#0-9) 

## Recommendation
Apply database-level pagination **before** the iteration loop. Because `userKeysToSign` filtering must happen in application code (it requires mirror node data), a two-phase approach is needed:

1. Add `take` and `skip` to the initial `repo.find()` call to cap the number of rows loaded per request.
2. Accept that `totalItems` will be an estimate (e.g., count of all non-terminal transactions) rather than the exact count of transactions the user needs to sign, or implement a separate count query.
3. Alternatively, push the key-matching logic into the database using a pre-computed `publicKeys` column (already stored on the `Transaction` entity) to filter at the SQL level before fetching, then apply `take`/`skip`.

## Proof of Concept
1. Register as any authenticated user with at least one key.
2. Ensure the system has a large number of active (non-terminal) transactions (e.g., 500+).
3. Call `GET /transactions/sign?page=1&size=10`.
4. Observe that the server loads all 500+ transactions from the database, then performs up to 500+ sequential mirror node HTTP calls (each potentially blocking up to 10 seconds on cache contention) before returning 10 results.
5. Repeat the call in a loop; server response times degrade for all users and memory usage grows with each concurrent request. [11](#0-10)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L266-277)
```typescript
    const whereForUser: FindOptionsWhere<Transaction> = {
      ...where,
      status: Not(
        In([
          TransactionStatus.EXECUTED,
          TransactionStatus.FAILED,
          TransactionStatus.EXPIRED,
          TransactionStatus.CANCELED,
          TransactionStatus.ARCHIVED,
        ]),
      ),
    };
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L284-293)
```typescript
    /* Ensures the user keys are passed */
    await attachKeys(user, this.entityManager);
    if (user.keys.length === 0) {
      return {
        totalItems: 0,
        items: [],
        page,
        size,
      };
    }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L295-299)
```typescript
    const transactions = await this.repo.find({
      where: whereForUser,
      relations: ['groupItem'],
      order,
    });
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L301-309)
```typescript
    for (const transaction of transactions) {
      /* Check if the user should sign the transaction */
      try {
        const keysToSign = await this.userKeysToSign(transaction, user);
        if (keysToSign.length > 0) result.push({ transaction, keysToSign });
      } catch (error) {
        console.log(error);
      }
    }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L311-316)
```typescript
    return {
      totalItems: result.length,
      items: result.slice(offset, offset + limit),
      page,
      size,
    };
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L342-350)
```typescript
    const findOptions: FindManyOptions<Transaction> = {
      order,
      relations: {
        creatorKey: true,
        groupItem: true,
      },
      skip: offset,
      take: limit,
    };
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L875-877)
```typescript
  async userKeysToSign(transaction: Transaction, user: User, showAll: boolean = false) {
    return userKeysRequiredToSign(transaction, user, this.transactionSignatureService, this.entityManager, showAll);
  }
```

**File:** back-end/libs/common/src/transaction-signature/cache.helper.ts (L46-57)
```typescript
    const pollIntervalMs = 500;
    const uuid = randomUUID();

    // Generate parameterized UPSERT SQL using safe column/table names from entity metadata
    // CacheKey defines conflict target columns
    const { text: sql, values } = getUpsertRefreshTokenForCacheQuery(
      sqlBuilder,
      entity,
      key,
    );

    const maxAttempts = 20;
```

**File:** back-end/libs/common/src/transaction-signature/cache.helper.ts (L62-97)
```typescript
    while (attempt < maxAttempts) {
      if (attempt > 0) {
        // On retries: check for unclaimed row to short-circuit without claiming
        existing = await this.dataSource.manager.findOne(entity, { where: key as unknown as FindOptionsWhere<T> }) as T | null;
        if (existing && !existing.refreshToken) {
          // Unclaimed row found → we can use it (someone else finished updating)
          return { data: existing, claimed: false };
        }
      }

      // Attempt atomic claim via UPSERT:
      // - INSERT new row with our claimToken
      // - ON CONFLICT: steal if unclaimed or reclaimable (updatedAt < reclaim cutoff)
      // - Always returns current owner row
      const result = await this.dataSource.query(sql, [
        ...values,                      // key columns
        uuid,                           // our refreshToken
        new Date(Date.now() - reclaimAfterMs), // reclaim cutoff
      ]);

      // Safety check: ensure query returns exactly one row (protects against SQL errors)
      if (!Array.isArray(result) || result.length !== 1) {
        throw new Error('Unexpected number of rows returned from cache upsert/claim');
      }

      const claim = result[0] as T;

      if (claim.refreshToken === uuid) {
        // SUCCESS: we claimed ownership
        return { data: claim, claimed: true };
      }

      // FAILED: someone else claimed it first → wait and retry
      await new Promise(res => setTimeout(res, pollIntervalMs));
      attempt++;
    }
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L96-114)
```typescript
export const userKeysRequiredToSign = async (
  transaction: Transaction,
  user: User,
  transactionSignatureService: TransactionSignatureService,
  entityManager: EntityManager,
  showAll: boolean = false,
): Promise<number[]> => {
  await attachKeys(user, entityManager);
  if (user.keys.length === 0) return [];

  const userKeysRequiredToSign = await keysRequiredToSign(
    transaction,
    transactionSignatureService,
    entityManager,
    showAll,
    user.keys
  );

  return userKeysRequiredToSign.map(k => k.id);
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L38-62)
```typescript
  async computeSignatureKey(
    transaction: Transaction,
    showAll: boolean = false,
  ): Promise<KeyList> {
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    const transactionModel = TransactionFactory.fromTransaction(sdkTransaction);

    // Extract signature requirements from the transaction model
    const requirements = this.extractSignatureRequirements(transactionModel);

    // Build the key list
    const signatureKey = new KeyList();

    await this.addFeePayerKey(signatureKey, transaction, requirements.feePayerAccount);
    await this.addSigningAccountKeys(signatureKey, transaction, requirements.signingAccounts);
    await this.addReceiverAccountKeys(signatureKey, transaction, requirements.receiverAccounts, showAll);

    if (requirements.nodeId) {
      await this.addNodeKeys(signatureKey, transaction, requirements.nodeId);
    }

    signatureKey.push(...requirements.newKeys);

    return signatureKey;
  }
```
