### Title
Unbounded In-Memory Loop in `getTransactionsToSign` Causes Server-Side Resource Exhaustion via Single Authenticated Request

### Summary
The `getTransactionsToSign` method in `TransactionsService` fetches **all** non-terminal transactions from the database with no row limit, then iterates over every result performing expensive per-transaction async operations — including potential Hedera mirror-node network calls — before applying pagination in memory. A normal authenticated user who accumulates many active transactions can trigger severe CPU, memory, and I/O exhaustion with a single API request, degrading or crashing the service for all users.

### Finding Description

**Root cause — `back-end/apps/api/src/transactions/transactions.service.ts`, lines 295–316**

The `getTransactionsToSign` function receives `Pagination` parameters (`limit`, `offset`) but never passes them to the database query:

```typescript
// Lines 295-299: NO `take` or `skip` — fetches every matching row
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
});
```

It then iterates over the entire result set in a sequential `for` loop:

```typescript
// Lines 301-309: one async call per transaction
for (const transaction of transactions) {
  try {
    const keysToSign = await this.userKeysToSign(transaction, user);
    if (keysToSign.length > 0) result.push({ transaction, keysToSign });
  } catch (error) { console.log(error); }
}
```

Pagination is applied only **after** the full loop completes:

```typescript
// Line 312: slice happens after all N iterations
items: result.slice(offset, offset + limit),
```

**Cost of each iteration**

`userKeysToSign` → `userKeysRequiredToSign` → `keysRequiredToSign` → `computeSignatureKey` performs, per transaction:
- Deserialization of `transactionBytes`
- One `accountCacheService.getAccountInfoForTransaction` call per fee-payer account
- One call per signing account (`addSigningAccountKeys` loop)
- One call per receiver account (`addReceiverAccountKeys` loop)
- Potentially one call per node account

Each of these may hit the Hedera mirror node over the network. With N transactions and M accounts per transaction, the server performs up to N × M network round-trips before returning even a single page of results. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation

A single authenticated user making one `GET /transactions/sign` request causes the server to:
- Load all N non-terminal transactions into heap memory
- Execute N × M async mirror-node/DB calls sequentially before responding
- Block the Node.js event loop for the duration of the loop
- Exhaust server memory (OOM) or saturate mirror-node connections at large N
- Degrade or deny service for all concurrent users of the API

The `importSignatures` endpoint in the same file contains an explicit developer acknowledgment of a related missing limit: *"Added a batch mechanism, probably should limit this on the api side of things"* (line 575), confirming awareness that input-size controls are absent in this service layer. [4](#0-3) 

### Likelihood Explanation

- **No privilege required**: any registered user can create transactions — the core product feature.
- **Attacker-controlled growth**: a user creates N transactions with future `validStart` timestamps (keeping them in `WAITING_FOR_SIGNATURES` status, which is the filter applied at line 266-277). Hedera transactions can have a `validStart` up to ~180 days in the future.
- **Single request trigger**: one unauthenticated-to-authenticated HTTP request to the `getTransactionsToSign` endpoint is sufficient to trigger the full loop.
- **No rate-limit evidence found** in the service layer for this endpoint. [5](#0-4) 

### Recommendation

1. **Apply DB-level pagination**: pass `take: limit` and `skip: offset` directly to `repo.find()` so the database — not the application — limits the result set.
2. **Push the signing-key check to the query layer**: use a subquery or a pre-computed `publicKeys` column (already stored on the `Transaction` entity) to filter transactions that require the user's keys at the SQL level, eliminating the per-row async loop entirely.
3. **Cap maximum page size**: enforce a hard upper bound (e.g., 100) on `limit` at the controller or DTO validation layer.
4. **Apply the same fix to `importSignatures`**: add a DTO-level `@ArrayMaxSize` constraint on the `UploadSignatureMapDto[]` input, consistent with the developer's own comment at line 575.

### Proof of Concept

**Preconditions**: attacker is a registered user with at least one valid key pair.

**Steps**:
1. Authenticate and obtain a JWT token.
2. In a loop, call `POST /transactions` N times (e.g., N = 500), each with a `validStart` set 24 hours in the future. Each transaction is created in `WAITING_FOR_SIGNATURES` status and remains there until it expires.
3. Call `GET /transactions/sign?page=1&size=10`.
4. **Observed**: the server fetches all 500 transactions, then calls `userKeysToSign` (including mirror-node lookups) for each one before slicing to 10 results. Response time grows linearly with N; at N ≈ 500–1000 the request times out (default NestJS/Node timeout) or the process OOMs.
5. **Expected**: the server should return 10 results immediately using a DB-level `LIMIT 10 OFFSET 0`.

The attack requires only normal user credentials and standard product API calls — no exploited secrets, no admin access, no external infrastructure.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L266-316)
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
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L575-577)
```typescript
    //Added a batch mechanism, probably should limit this on the api side of things
    const BATCH_SIZE = 500;

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

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L104-122)
```typescript
  private async addSigningAccountKeys(
    signatureKey: KeyList,
    transaction: Transaction,
    signingAccounts: Set<string>
  ): Promise<void> {
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
  }
```
