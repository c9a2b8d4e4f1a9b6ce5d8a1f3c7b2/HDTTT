All claims have been verified against the actual source code. Here is the audit report:

---

Audit Report

## Title
Unbounded In-Memory Loop in `getTransactionsToSign` Enables Authenticated Resource Exhaustion DoS

## Summary
`getTransactionsToSign()` in `TransactionsService` fetches every active transaction from the database without a row limit, then iterates over all results performing per-transaction async I/O. The endpoint is live and reachable by any JWT-authenticated, verified user. As the number of active transactions grows, a single request causes unbounded memory consumption and event-loop starvation, degrading the shared NestJS process for all users.

## Finding Description

**Root cause 1 — no `take`/`skip` on the DB query.**

In `back-end/apps/api/src/transactions/transactions.service.ts`, the `repo.find()` call inside `getTransactionsToSign` carries no pagination parameters:

```ts
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no take / skip
});
``` [1](#0-0) 

By contrast, `getHistoryTransactions` correctly passes `skip: offset, take: limit` to the ORM: [2](#0-1) 

**Root cause 2 — unbounded sequential async loop over all returned rows.**

Every transaction returned by the query is processed one-by-one with `await`:

```ts
for (const transaction of transactions) {
  const keysToSign = await this.userKeysToSign(transaction, user);
  ...
}
``` [3](#0-2) 

`userKeysToSign` delegates to `userKeysRequiredToSign` → `keysRequiredToSign` → `computeSignatureKey`, which deserializes transaction bytes and calls `AccountCacheService.getAccountInfoForTransaction()` for each relevant account (fee payer, signing accounts, receiver accounts, node account). [4](#0-3) [5](#0-4) [6](#0-5) 

`AccountCacheService.getAccountInfoForTransaction()` consults a DB-backed cache first; when the cache is stale or missing it issues an outbound HTTP call to the mirror node. The default cache TTL is 10 seconds (`CACHE_STALE_THRESHOLD_MS`), so on the first request (or after TTL expiry) every account lookup triggers a live HTTP call. [7](#0-6) [8](#0-7) 

**Root cause 3 — pagination applied only after the full in-memory loop.**

The `size ≤ 100` guard in `PaginationParams` operates at the HTTP layer and only slices the already-computed result array; it is never forwarded to the DB query: [9](#0-8) [10](#0-9) 

**Root cause 4 — endpoint is live and guarded only by standard JWT + verified-user guards.**

Despite the `/* NO LONGER USED BY FRONT-END */` comment, the route `GET /transactions/sign` is fully registered and protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — the lowest privilege level in the system: [11](#0-10) [12](#0-11) 

## Impact Explanation

With N active transactions and M accounts per transaction:

1. **Memory spike** — all N transaction rows (including `transactionBytes` blobs and `groupItem` relations) are loaded into the Node.js heap simultaneously before any filtering occurs.
2. **Event-loop starvation** — the sequential `await` loop inside `for (const transaction of transactions)` holds the async queue for the duration of all per-transaction processing, blocking other concurrent requests.
3. **Mirror-node HTTP call burst** — on a cold or stale cache, up to N × M outbound HTTP calls are issued to the mirror node, potentially saturating the connection pool. Even with a warm cache, each iteration still performs multiple DB lookups.
4. **Cascading service degradation** — because NestJS runs in a single process, all other users' requests queue behind this one, causing timeouts across the entire API.

The impact worsens monotonically as the organization accumulates active transactions; there is no self-correcting mechanism.

## Likelihood Explanation

- **Attacker precondition**: a valid JWT token for any verified user — the lowest privilege level in the system.
- **Trigger**: a single `GET /transactions/sign?page=1&size=1` request. The `size=1` parameter does not limit the DB query; it only slices the final in-memory result.
- **No rate limiting** is visible on this endpoint in the reviewed code.
- The endpoint remains live despite the "NO LONGER USED BY FRONT-END" comment, making it an overlooked but fully functional attack surface.
- A malicious insider or a compromised low-privilege account is a realistic threat model for an enterprise multi-sig tool.

## Recommendation

1. **Push pagination into the DB query**: pass `take: limit` and `skip: offset` to `this.repo.find()` in `getTransactionsToSign`, mirroring the pattern used in `getHistoryTransactions`.
2. **Remove or disable the unused endpoint**: if the route is genuinely no longer needed, remove the `@Get('/sign')` handler entirely to eliminate the attack surface.
3. **Add a hard server-side cap**: even after adding `take`, enforce a maximum page size (e.g., 100) inside the service layer, not only in the decorator.
4. **Consider rate limiting**: apply a per-user rate limit on this and similar aggregate endpoints.

## Proof of Concept

```
# Authenticated as any verified user:
GET /transactions/sign?page=1&size=1
Authorization: Bearer <valid_jwt>
```

With N active transactions in the database, this single request causes the server to:
1. Load all N rows (including binary `transactionBytes`) into memory via `this.repo.find({ where: whereForUser, relations: ['groupItem'], order })` — no `take`/`skip`.
2. Iterate sequentially over all N rows, calling `userKeysToSign` (→ `computeSignatureKey` → mirror-node HTTP) for each.
3. Return only 1 item from the fully-computed in-memory result via `result.slice(0, 1)`.

Repeating this request concurrently amplifies heap pressure and event-loop starvation proportionally.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L227-236)
```typescript
    const findOptions: FindManyOptions<Transaction> = {
      where: {
        ...getWhere<Transaction>(filter),
        status: this.getHistoryStatusWhere(filter),
      },
      order,
      relations: ['groupItem', 'groupItem.group'],
      skip: offset,
      take: limit,
    };
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L875-877)
```typescript
  async userKeysToSign(transaction: Transaction, user: User, showAll: boolean = false) {
    return userKeysRequiredToSign(transaction, user, this.transactionSignatureService, this.entityManager, showAll);
  }
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L96-115)
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
};
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

**File:** back-end/libs/common/src/transaction-signature/account-cache.service.ts (L41-42)
```typescript
    this.cacheTtlMs = this.configService.get<number>('CACHE_STALE_THRESHOLD_MS', 10 * 1000);
    this.claimTimeoutMs = this.configService.get<number>('CACHE_CLAIM_TIMEOUT_MS', 10 * 1000);
```

**File:** back-end/libs/common/src/transaction-signature/account-cache.service.ts (L83-114)
```typescript
    const cached = await this.dataSource.manager.findOne(CachedAccount, {
      where: { account, mirrorNetwork },
    });

    if (this.hasCompleteData(cached) && isFresh(cached.updatedAt, this.cacheTtlMs)) {
      // Link to transaction even if using cache
      await this.linkTransactionToAccount(transaction.id, cached.id, isReceiver);
      return this.parseCachedAccount(cached);
    }

    // Cache is stale or doesn't exist - fetch new data
    this.logger.debug(`Fetching account ${account} from mirror node (cache ${cached ? 'stale' : 'missing'})`);

    // Try to claim the account for refresh, create the account row if none exists
    const { data: claimedAccount, claimed } = await this.tryClaimAccountRefresh(account, mirrorNetwork);

    if (!claimed) {
      // Link to transaction
      await this.linkTransactionToAccount(transaction.id, claimedAccount.id, isReceiver);

      if (this.hasCompleteData(claimedAccount)) {
        return this.parseCachedAccount(claimedAccount);
      }

      // No cached data
      // This should never happen
      return null;
    }

    const { data } = await this.performRefreshForClaimedAccount(claimedAccount, transaction.id, isReceiver);
    return data;
  }
```

**File:** back-end/libs/common/src/decorators/pagination-params.decorator.ts (L22-29)
```typescript
  if (size > 100) {
    throw new BadRequestException(ErrorCodes.IPP);
  }

  // calculate pagination parameters
  const limit = size;
  const offset = (page - 1) * limit;
  return { page, limit, size, offset };
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L54-57)
```typescript
@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L156-178)
```typescript
  /* Get all transactions to be signed by the user */
  /* NO LONGER USED BY FRONT-END */
  @ApiOperation({
    summary: 'Get transactions to sign',
    description: 'Get all transactions to be signed by the current user.',
  })
  @ApiResponse({
    status: 200,
  })
  @Get('/sign')
  @Serialize(withPaginatedResponse(TransactionToSignDto))
  getTransactionsToSign(
    @GetUser() user: User,
    @PaginationParams() paginationParams: Pagination,
    @SortingParams(transactionProperties) sort?: Sorting[],
    @FilteringParams({
      validProperties: transactionProperties,
      dateProperties: transactionDateProperties,
    })
    filter?: Filtering[],
  ) {
    return this.transactionsService.getTransactionsToSign(user, paginationParams, sort, filter);
  }
```
