### Title
Unbounded Full-Table Scan with Per-Row Async Work in `getTransactionsToSign` Enables Authenticated DoS

### Summary
`getTransactionsToSign` in `back-end/apps/api/src/transactions/transactions.service.ts` fetches every non-terminal transaction from the database with no row limit, then performs an expensive async operation (`userKeysToSign` → `computeSignatureKey` → account-cache lookups + DB queries) for each row in a sequential loop. Pagination is applied only after the loop completes. Any authenticated user can repeatedly call `GET /transactions/sign` to exhaust server CPU, memory, and database connections, causing service degradation or outage for all users.

### Finding Description

**Root cause — no `take` limit on the DB query:**

`getTransactions`, `getHistoryTransactions`, and `getTransactionsToApprove` all pass `take: limit` to TypeORM, bounding the DB result set to at most 100 rows. `getTransactionsToSign` does not:

```typescript
// back-end/apps/api/src/transactions/transactions.service.ts  lines 295-299
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no `take` here; returns every non-terminal transaction
});
``` [1](#0-0) 

**Root cause — per-row async work before pagination:**

The code then iterates over every returned row and calls `userKeysToSign` for each one:

```typescript
// lines 301-309
for (const transaction of transactions) {
  try {
    const keysToSign = await this.userKeysToSign(transaction, user);
    if (keysToSign.length > 0) result.push({ transaction, keysToSign });
  } catch (error) { console.log(error); }
}
``` [2](#0-1) 

Pagination is applied only after the loop:

```typescript
// line 313
items: result.slice(offset, offset + limit),
``` [3](#0-2) 

**Cost of each `userKeysToSign` call:**

`userKeysToSign` → `userKeysRequiredToSign` → `keysRequiredToSign`, which per transaction:
1. Deserializes `transactionBytes` via `SDKTransaction.fromBytes` (CPU)
2. Calls `transactionSignatureService.computeSignatureKey` which queries the Hedera account-cache service (potentially network I/O per unique account)
3. Issues a `entityManager.find(UserKey, ...)` DB query [4](#0-3) [5](#0-4) 

**Contrast with sibling methods that correctly bound the query:** [6](#0-5) [7](#0-6) 

**Pagination decorator enforces `size ≤ 100` but does not protect the DB query:** [8](#0-7) 

The decorator only limits what is returned to the caller; it has no effect on how many rows `repo.find` fetches.

**Reachable endpoint:** [9](#0-8) 

The `/transactions/sign` GET endpoint is authenticated but requires no elevated role.

### Impact Explanation

With N non-terminal transactions in the database, every call to `GET /transactions/sign` causes:
- One unbounded `SELECT` loading all N rows + their `groupItem` relations into Node.js heap
- N sequential async operations, each involving transaction deserialization, Hedera mirror-node account lookups, and a DB query

An attacker (or even a legitimate user in a busy deployment) can:
- **Exhaust heap memory** by triggering concurrent requests, each holding N large transaction objects
- **Exhaust the DB connection pool** with N concurrent `UserKey` queries per request
- **Starve the event loop** with N sequential awaits, blocking other requests
- **Cause request timeouts** that cascade into retries, amplifying load

Impact: full API service degradation or crash for all users. No data theft, but permanent availability loss until the server is restarted.

### Likelihood Explanation

- Precondition: valid authenticated session only (any registered, verified user)
- Attack: send repeated `GET /transactions/sign?page=1&size=1` requests
- No special knowledge, no admin access, no leaked credentials required
- Impact scales automatically as the platform grows — the more transactions exist, the worse each request becomes
- The endpoint is part of the normal application workflow, so rate-limiting is unlikely to be aggressive

### Recommendation

Apply the same pattern used by `getTransactions` and `getTransactionsToApprove`: push the filtering logic into the database query so that only the paginated slice is fetched and processed.

The cleanest fix is to add a correlated subquery (or a JOIN) that filters to only transactions where the user's keys are required, then apply `take: limit` and `skip: offset` at the DB level — eliminating the in-memory loop entirely. At minimum, add `take: limit` to the existing `repo.find` call to bound memory and loop iterations to the page size.

### Proof of Concept

1. Register and verify a user account on the API.
2. Create a large number of transactions (e.g., 10 000) in `WAITING_FOR_SIGNATURES` status via `POST /transactions`.
3. Repeatedly call:
   ```
   GET /transactions/sign?page=1&size=1
   Authorization: Bearer <token>
   ```
4. Observe: each request causes the server to load all 10 000 transaction rows into memory and execute 10 000 sequential `userKeysToSign` calls before returning a single result. Concurrent requests will multiply this load, exhausting heap and DB connections and causing 503 errors for all users.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L175-181)
```typescript
    const findOptions: FindManyOptions<Transaction> = {
      where: whereForUser,
      order,
      relations: ['creatorKey', 'groupItem', 'groupItem.group'],
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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L20-94)
```typescript
export const keysRequiredToSign = async (
  transaction: Transaction,
  transactionSignatureService: TransactionSignatureService,
  entityManager: EntityManager,
  showAll: boolean = false,
  userKeys?: UserKey[],
  cache?: Map<string, UserKey>,
): Promise<UserKey[]> => {
  if (!transaction) return [];

  /* Deserialize the transaction */
  const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

  // list of just public keys that have already signed the transaction
  const signerKeys = sdkTransaction._signerPublicKeys;

  const signature = await transactionSignatureService.computeSignatureKey(transaction, showAll);
  // flatten the key list to an array of public keys
  // and filter out any keys that have already signed the transaction
  const flatPublicKeys = flattenKeyList(signature)
    .map(pk => pk.toStringRaw())
    .filter(pk => !signerKeys.has(pk));

  if (flatPublicKeys.length === 0) return [];

  let results: UserKey[] = [];
  // Now if userKeys is provided, filter out any keys that are not in the flatPublicKeys array
  // this way a user requesting required keys will only see their own keys that are required
  // Otherwise, fetch all UserKeys that are in flatPublicKeys
  if (userKeys) {
    results = userKeys.filter(publicKey =>
        flatPublicKeys.includes(publicKey.publicKey)
    );
  } else {
    if (cache) {
      const cachedKeys: Set<UserKey> = new Set();
      const missingPublicKeys: Set<string> = new Set();

      for (const publicKey of flatPublicKeys) {
        const cached = cache.get(publicKey);
        if (cached) {
          cachedKeys.add(cached);
        } else {
          missingPublicKeys.add(publicKey);
        }
      }

      let fetchedKeys: UserKey[] = [];
      if (missingPublicKeys.size > 0) {
        try {
          fetchedKeys = await entityManager.find(UserKey, {
            where: { publicKey: In([...missingPublicKeys]) },
            relations: ['user'],
          });
          // Store fetched keys in cache
          for (const key of fetchedKeys) {
            cache.set(key.publicKey, key);
          }
        } catch (error) {
          console.error('Error fetching missing user keys:', error);
          throw error;
        }
      }

      results = [...cachedKeys, ...fetchedKeys];
    } else {
      results = await entityManager.find(UserKey, {
        where: { publicKey: In(flatPublicKeys) },
        relations: ['user'],
      });
    }
  }

  return results;
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

**File:** back-end/libs/common/src/decorators/pagination-params.decorator.ts (L22-24)
```typescript
  if (size > 100) {
    throw new BadRequestException(ErrorCodes.IPP);
  }
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L116-132)
```typescript
  @ApiResponse({
    status: 200,
  })
  @Get()
  @Serialize(withPaginatedResponse(TransactionDto))
  getTransactions(
    @GetUser() user: User,
    @PaginationParams() paginationParams: Pagination,
    @SortingParams(transactionProperties) sort?: Sorting[],
    @FilteringParams({
      validProperties: transactionProperties,
      dateProperties: transactionDateProperties,
    })
    filter?: Filtering[],
  ): Promise<PaginatedResourceDto<Transaction>> {
    return this.transactionsService.getTransactions(user, paginationParams, sort, filter);
  }
```
