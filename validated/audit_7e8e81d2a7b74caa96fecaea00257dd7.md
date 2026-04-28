### Title
`getTransactionsToSign` Fetches and Processes All Pending Transactions Without a DB-Level Limit, Enabling Authenticated DoS

### Summary

`getTransactionsToSign` in `transactions.service.ts` fetches every non-terminal transaction from the database with no `take` limit, then iterates over the entire result set calling the expensive `userKeysToSign` per transaction before applying pagination in memory. As the number of pending transactions grows, each request to `GET /transactions/sign` consumes proportionally more CPU, memory, and time, eventually causing request timeouts and server-wide degradation. Any authenticated user can trigger this endpoint.

### Finding Description

**Root cause — no DB-level limit on the fetch:**

In `getTransactionsToSign`, the database query at line 295 uses `this.repo.find({where: whereForUser, relations: ['groupItem'], order})` with no `take` property, so it returns every non-terminal transaction in the system. [1](#0-0) 

Compare this to `getTransactions` (line 175–181) and `getHistoryTransactions` (line 227–236), which both pass `skip: offset, take: limit` directly to the ORM query and never load the full table. [2](#0-1) 

**Root cause — O(N) expensive per-transaction work inside the loop:**

After loading all N transactions, the function iterates over every one and calls `userKeysToSign` (line 301–309): [3](#0-2) 

`userKeysToSign` delegates to `userKeysRequiredToSign` → `keysRequiredToSign`, which per transaction:
1. Deserializes raw bytes via `SDKTransaction.fromBytes` (CPU).
2. Calls `transactionSignatureService.computeSignatureKey`, which itself calls `SDKTransaction.fromBytes` a second time, then makes async calls to `accountCacheService.getAccountInfoForTransaction` and optionally `nodeCacheService.getNodeInfoForTransaction` (network/DB I/O).
3. Issues a `UserKey` DB query for the matching public keys. [4](#0-3) [5](#0-4) 

**Pagination is applied only after the full loop:**

The `page`/`limit` parameters accepted by the function are used only at line 313 (`result.slice(offset, offset + limit)`), after all N transactions have already been processed. Passing `page=1&size=10` does not reduce the server-side work at all. [6](#0-5) 

**The endpoint is still live:**

The controller exposes `GET /transactions/sign` to any authenticated, verified user. The comment "NO LONGER USED BY FRONT-END" confirms the front-end has moved on, but the route remains open and callable by any API client. [7](#0-6) 

### Impact Explanation

Each call to `GET /transactions/sign` forces the NestJS API process to:
- Load the entire pending-transaction table into memory.
- Deserialize every transaction's raw bytes twice.
- Issue one or more async I/O calls (mirror-node / DB) per transaction.

With thousands of pending transactions (realistic in an active multi-org deployment), a single request can hold the Node.js event loop for seconds, exhaust the DB connection pool, and cause HTTP timeouts. Repeated calls from one attacker degrade or deny service for all other users sharing the same API instance. Because the work is proportional to the global count of pending transactions — not the requesting user's transactions — the attacker's cost is constant while the server's cost grows unboundedly.

### Likelihood Explanation

- **Attacker precondition:** A valid JWT (any registered, verified user). No admin role required.
- **Trigger:** A single `GET /transactions/sign` HTTP request.
- **Amplification:** The attacker can flood the endpoint in a tight loop; each request is independently expensive.
- **Natural growth:** Even without a deliberate attacker, a large organization accumulating thousands of pending transactions will eventually make this endpoint unusably slow for legitimate users.

### Recommendation

Apply the DB-level `take`/`skip` limit before the loop, mirroring the pattern used by `getTransactions` and `getHistoryTransactions`. The key-matching logic must then be pushed into the query (e.g., pre-filter by the user's known public keys in SQL) rather than done in application code after a full table scan. If the per-transaction `computeSignatureKey` call cannot be avoided, it should be executed only on the already-paginated slice, not on the entire result set. Additionally, consider removing or rate-limiting the endpoint entirely given the front-end no longer uses it.

### Proof of Concept

1. Register and verify a user account on the API.
2. Ensure the system has a large number of pending (non-terminal) transactions (e.g., 10 000).
3. Obtain a JWT via `POST /auth/login`.
4. Send repeated requests:
   ```
   GET /transactions/sign?page=1&size=1
   Authorization: Bearer <jwt>
   ```
5. Observe: despite `size=1`, the server loads and processes all 10 000 transactions before returning one result. Response time scales linearly with the total pending-transaction count. Under sustained load the API becomes unresponsive for all users. [8](#0-7)

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L252-317)
```typescript
  async getTransactionsToSign(
    user: User,
    { page, limit, size, offset }: Pagination,
    sort?: Sorting[],
    filter?: Filtering[],
  ): Promise<
    PaginatedResourceDto<{
      transaction: Transaction;
      keysToSign: number[];
    }>
  > {
    const where = getWhere<Transaction>(filter);
    const order = getOrder(sort);

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

    const result: {
      transaction: Transaction;
      keysToSign: number[];
    }[] = [];

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

    const transactions = await this.repo.find({
      where: whereForUser,
      relations: ['groupItem'],
      order,
    });

    for (const transaction of transactions) {
      /* Check if the user should sign the transaction */
      try {
        const keysToSign = await this.userKeysToSign(transaction, user);
        if (keysToSign.length > 0) result.push({ transaction, keysToSign });
      } catch (error) {
        console.log(error);
      }
    }

    return {
      totalItems: result.length,
      items: result.slice(offset, offset + limit),
      page,
      size,
    };
  }
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
