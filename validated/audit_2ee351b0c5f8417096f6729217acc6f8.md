All claims are verified against the actual code. Let me confirm the `getUsers` controller access level quickly.

All claims are verified. The vulnerability is real and accurately described. Here is the audit report:

---

Audit Report

## Title
Unbounded In-Memory Array Accumulation in `getTransactionsToSign` Causes Authenticated DoS

## Summary
`getTransactionsToSign` in `back-end/apps/api/src/transactions/transactions.service.ts` fetches every non-terminal transaction in the organization from the database with no row limit, loads all rows into the Node.js heap, and then performs two rounds of protobuf deserialization plus cryptographic key-tree traversal per row before slicing for pagination. Any authenticated user can trigger this full scan by calling `GET /transactions/sign`, exhausting server memory and CPU.

## Finding Description

**Unbounded database fetch.** The `whereForUser` filter in `getTransactionsToSign` excludes only terminal statuses; it contains no user-scoping predicate. The subsequent `repo.find()` call passes no `take` or `skip`:

```typescript
// transactions.service.ts lines 266–299
const whereForUser: FindOptionsWhere<Transaction> = {
  ...where,
  status: Not(In([EXECUTED, FAILED, EXPIRED, CANCELED, ARCHIVED])),
  // ← no userId / creatorKey / signers / observers filter
};

const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no take, no skip
});
```

This returns every non-terminal transaction across the entire organization. [1](#0-0) 

**Double deserialization per row.** For each fetched transaction, `userKeysToSign` → `userKeysRequiredToSign` → `keysRequiredToSign` calls `SDKTransaction.fromBytes` once: [2](#0-1) 

Then `computeSignatureKey` calls `SDKTransaction.fromBytes` a second time: [3](#0-2) 

This means every row incurs two protobuf deserializations plus mirror-node account/node cache lookups for key-tree traversal.

**Pagination applied after full load.** The slice happens on the in-memory result array, not at the database layer:

```typescript
// transactions.service.ts lines 311–316
return {
  totalItems: result.length,
  items: result.slice(offset, offset + limit),
  page,
  size,
};
``` [4](#0-3) 

**Contrast with correctly paginated endpoints.** `getTransactions` and `getHistoryTransactions` both pass `skip: offset, take: limit` directly into the database query: [5](#0-4) [6](#0-5) 

**Endpoint access.** The controller exposes `GET /transactions/sign` with only `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` at the class level — no admin privilege required. The endpoint is annotated `/* NO LONGER USED BY FRONT-END */` but remains fully reachable: [7](#0-6) [8](#0-7) 

**Secondary unbounded fetch.** `UsersService.getUsers` also calls `this.repo.find()` with no limit on both the admin and non-admin branches, returning all organization users in a single response: [9](#0-8) 

## Impact Explanation

- **Memory exhaustion**: Every non-terminal transaction row — including its `transactionBytes` blob and `groupItem` relation — is loaded into the Node.js heap simultaneously. In an organization with thousands of pending transactions this can exhaust available memory.
- **CPU exhaustion**: Each row triggers two `SDKTransaction.fromBytes` calls (protobuf deserialization) and one `computeSignatureKey` call (mirror-node I/O + key-tree traversal). Concurrent requests multiply this cost linearly.
- **Service crash / severe degradation**: The NestJS API process can OOM-crash or become unresponsive, denying service to all users.

## Likelihood Explanation

- **Attacker precondition**: A valid JWT session — obtainable by any registered user via normal login.
- **Attack complexity**: A single HTTP GET to `/transactions/sign?page=1&size=1` is sufficient to trigger the full unbounded load regardless of the requested page size.
- **Amplification**: Concurrent requests from one or more accounts multiply the effect linearly.
- No rate limiting is present on this endpoint in the reviewed code.

## Recommendation

1. **Push pagination into the database.** Add `skip: offset, take: limit` to the `repo.find()` call in `getTransactionsToSign`, mirroring the pattern used in `getTransactions` and `getHistoryTransactions`.
2. **Scope the query to the requesting user.** Add a user-scoping predicate to `whereForUser` (e.g., filter by `signers.userId`, `creatorKey.userId`, or `observers.userId`) so the database returns only rows relevant to the caller, as `getTransactions` does.
3. **Remove or disable the endpoint.** Given the `/* NO LONGER USED BY FRONT-END */` annotation, the simplest remediation is to remove or disable `GET /transactions/sign` entirely.
4. **Apply a hard maximum page size.** Enforce a server-side cap (e.g., 100 rows) on the `limit` parameter across all paginated endpoints.
5. **Address `getUsers` unbounded fetch.** Add `take: limit` to both branches of `UsersService.getUsers` or restrict the endpoint to admin-only access.

## Proof of Concept

```
# Any authenticated user — no admin role required
curl -H "Authorization: Bearer <valid_jwt>" \
     "https://<api-host>/transactions/sign?page=1&size=1"
```

Regardless of `size=1`, the server fetches and deserializes every non-terminal transaction in the organization before returning a single row. Sending this request concurrently from multiple sessions amplifies memory and CPU pressure proportionally.

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L266-299)
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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L31-36)
```typescript
  const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

  // list of just public keys that have already signed the transaction
  const signerKeys = sdkTransaction._signerPublicKeys;

  const signature = await transactionSignatureService.computeSignatureKey(transaction, showAll);
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L42-43)
```typescript
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    const transactionModel = TransactionFactory.fromTransaction(sdkTransaction);
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L56-56)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L157-178)
```typescript
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

**File:** back-end/apps/api/src/users/users.service.ts (L86-96)
```typescript
  async getUsers(requestingUser: User): Promise<User[]> {
    // Only load clients relation when admin needs update info
    if (requestingUser.admin) {
      const users = await this.repo.find({ relations: ['clients'] });
      const latestSupported = this.configService.get<string>('LATEST_SUPPORTED_FRONTEND_VERSION');
      this.enrichUsersWithUpdateFlag(users, latestSupported);
      return users;
    }

    return this.repo.find();
  }
```
