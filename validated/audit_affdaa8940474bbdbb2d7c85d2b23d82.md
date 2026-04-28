All key claims are verified against the actual code. Here is the audit result:

---

Audit Report

## Title
Unbounded Transaction Fetch in `getTransactionsToSign` Causes Per-Transaction Processing and In-Memory Pagination, Enabling Resource Exhaustion DoS

## Summary
The `GET /transactions/sign` endpoint fetches every non-terminal transaction in the database with no row limit, then performs a sequential per-transaction `userKeysToSign` call (which invokes `computeSignatureKey`, potentially triggering external Hedera mirror-node HTTP requests when the account cache is stale or missing) for every row before applying pagination in memory. Any authenticated, verified user can trigger this endpoint.

## Finding Description

**Root cause — no `take` limit on the database query:**

In `getTransactionsToSign`, the repository `find` call has no `take` parameter, so it returns every non-terminal transaction in the entire system: [1](#0-0) 

**Sequential per-transaction async processing:**

For every row returned, `userKeysToSign` is called, which calls `computeSignatureKey` on `TransactionSignatureService`. This deserializes the transaction bytes and calls `accountCacheService.getAccountInfoForTransaction` for the fee-payer account, each signing account, each receiver account, and optionally the node admin key: [2](#0-1) 

The `AccountCacheService.getAccountInfoForTransaction` method first checks a local DB cache (TTL default 10 seconds). When the cache is fresh, no external HTTP call is made. However, when the cache is stale or missing — which is the case for any new transaction or after the 10-second TTL — it calls `mirrorNodeClient.fetchAccountInfo`, an outbound HTTP request to the Hedera mirror node: [3](#0-2) 

The loop is sequential (`for...of` with `await`), meaning all N transactions are processed one by one before any result is returned: [4](#0-3) 

**Pagination applied in-memory after full processing:**

The `PaginationParams` decorator enforces `size ≤ 100`, but that limit is only applied to the final `slice` — the entire table scan and per-row processing happens unconditionally first: [5](#0-4) [6](#0-5) 

**Developer-acknowledged absence of API-side limits:**

A comment in the same service file acknowledges the pattern of missing API-side limits: [7](#0-6) 

**Entry point — any verified user:**

The controller class is guarded only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. No admin role is required. The endpoint is still reachable despite being marked `/* NO LONGER USED BY FRONT-END */`: [8](#0-7) [9](#0-8) 

## Impact Explanation

A single `GET /transactions/sign?page=1&size=1` request causes the server to:

1. Load **all** non-terminal transactions from PostgreSQL into memory (no DB-level row limit).
2. Deserialize each transaction's bytes (`SDKTransaction.fromBytes`) for every row.
3. For each transaction, perform one or more `getAccountInfoForTransaction` calls — each of which does a DB lookup and, when the cache is stale or missing (e.g., for new transactions or after the 10-second TTL), issues an outbound HTTP request to the Hedera mirror node.
4. Hold all results in a JavaScript array before slicing to the requested page size.

With a large transaction backlog, this exhausts server heap memory, saturates the outbound mirror-node connection pool, and blocks the Node.js event loop — degrading or crashing the API service for all users. The caching layer (10-second TTL) partially mitigates the external HTTP call frequency, but does not mitigate the unbounded DB scan or the in-memory sequential processing of all rows.

## Likelihood Explanation

- **Attacker precondition:** A valid JWT for any verified organization user — a normal product account.
- **Trigger:** A single HTTP GET request to `/transactions/sign`.
- **Amplification:** The attacker does not need to create the transactions; any existing backlog of active transactions in the organization is sufficient. The attacker can also create transactions themselves (each requires a valid Hedera transaction signed with their own key, which is a low-cost operation).
- **No rate limiting** on this endpoint is visible in the codebase.
- The endpoint is marked as no longer used by the front-end, but remains fully accessible via the API.

## Recommendation

1. **Add a database-level `take` limit** to the `repo.find` call in `getTransactionsToSign`, matching the requested `limit` from pagination parameters. This is the primary fix.
2. **Refactor the query** to push the "does this user need to sign?" logic into the database (e.g., via a subquery or join on `CachedAccountKey`), eliminating the need to load and process every transaction in application memory.
3. **Consider deprecating or removing** the `/transactions/sign` endpoint entirely, given it is already marked as no longer used by the front-end, in favor of the newer `/transaction-nodes?collection=READY_TO_SIGN` endpoint which uses a proper SQL-level query.
4. **Add rate limiting** to this endpoint as a defense-in-depth measure.

## Proof of Concept

```
GET /transactions/sign?page=1&size=1
Authorization: Bearer <valid_jwt_for_any_verified_user>
```

With N non-terminal transactions in the system, the server will:
- Execute `SELECT * FROM transaction WHERE status NOT IN (...)` with no `LIMIT` clause, loading all N rows.
- Sequentially `await userKeysToSign(tx, user)` for each of the N rows, each calling `computeSignatureKey` which performs DB lookups and potentially outbound mirror-node HTTP calls.
- Return only 1 item in the response body, having processed all N transactions.

Repeating this request in a loop (or from multiple clients) amplifies the effect without any server-side throttle.

### Citations

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L575-576)
```typescript
    //Added a batch mechanism, probably should limit this on the api side of things
    const BATCH_SIZE = 500;
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

**File:** back-end/libs/common/src/transaction-signature/account-cache.service.ts (L83-113)
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
