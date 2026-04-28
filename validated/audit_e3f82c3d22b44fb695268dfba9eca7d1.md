The code is confirmed. Let me verify the `userKeysToSign` internals quickly.

All claims are verified against the actual code. The vulnerability is real and not excluded by SECURITY.md (which only excludes attacks that "only require DDoS" — this is a single-request server-side resource exhaustion caused by a code defect, not a volumetric DDoS).

---

Audit Report

## Title
Unbounded Full-Table Scan in `getTransactionsToSign` Causes Server-Side Resource Exhaustion

## Summary
`getTransactionsToSign` in `transactions.service.ts` fetches every non-terminal transaction in the entire database without any SQL-level `LIMIT`, then performs a sequential async cryptographic operation (including mirror-node account lookups) per row before applying pagination in memory. Any authenticated, verified user can trigger this endpoint, causing unbounded memory and CPU consumption proportional to the total number of active transactions in the system.

## Finding Description

**Missing `take`/`skip` in the DB query:**

The `repo.find()` call at lines 295–299 has no `take` or `skip` parameter:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no take / skip
});
``` [1](#0-0) 

The `whereForUser` predicate filters only on `status NOT IN (terminal statuses)` — it does **not** scope results to the requesting user's transactions. Every active transaction in the system is returned. [2](#0-1) 

**Per-row sequential async cryptographic work:**

For every returned row, `userKeysToSign` is awaited sequentially: [3](#0-2) 

`userKeysToSign` calls `userKeysRequiredToSign`, which calls `transactionSignatureService.computeSignatureKey`. That method deserializes the Hedera SDK transaction bytes and issues async mirror-node account lookups (`accountCacheService.getAccountInfoForTransaction`) for the fee payer, signing accounts, receiver accounts, and potentially node accounts — once per transaction row. [4](#0-3) 

**Pagination applied only after all rows are processed:**

```typescript
items: result.slice(offset, offset + limit),
``` [5](#0-4) 

**Contrast with every other paginated method in the same file**, which correctly passes `take: limit` to the DB query: [6](#0-5) [7](#0-6) 

**Controller endpoint — reachable by any authenticated, verified user:** [8](#0-7) 

The controller is guarded only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — no admin or elevated privilege is required. [9](#0-8) 

The `PaginationParams` decorator caps the response slice at `size ≤ 100`, but this cap is never applied to the underlying DB query inside `getTransactionsToSign`.

## Impact Explanation

A single HTTP request to `GET /transactions/sign?page=1&size=10` causes the server to:
1. Load **all** active transactions (potentially tens of thousands of rows, each containing `transactionBytes` blobs) into the Node.js heap.
2. Await one async cryptographic deserialization + one or more mirror-node HTTP lookups per row, sequentially.

This produces unbounded memory growth and CPU saturation proportional to the total number of active transactions in the system. At sufficient scale the API process times out or OOMs, making the signing endpoint — and potentially the entire API service — unavailable to all users.

## Likelihood Explanation

- Any registered, verified user can create transactions; there is no apparent per-user or global cap on active transaction count.
- A single accumulation of active transactions (by any means, including normal usage) triggers the condition on the next call to this endpoint.
- The attacker needs only a valid, verified session — no admin privileges or leaked credentials.
- Although the front-end comment notes `/* NO LONGER USED BY FRONT-END */`, the endpoint remains live and is directly accessible via the API.

## Recommendation

Apply SQL-level pagination before the per-row cryptographic work. The fix requires a two-phase approach since the user-relevance filter (`keysToSign.length > 0`) cannot be expressed in SQL:

1. **Paginate the DB query** using `take` and `skip` (or cursor-based pagination) to bound the number of rows loaded per request.
2. **Alternatively**, push the user-key filter into the DB query by joining on `transaction_signer` / `publicKeys` columns so that only transactions relevant to the requesting user are fetched, then apply `take`/`skip` as all other methods do.
3. Consider adding a **rate limit** on this endpoint to prevent rapid repeated calls.

## Proof of Concept

```
GET /transactions/sign?page=1&size=1
Authorization: Bearer <valid_user_jwt>
```

With N active transactions in the database, the server will:
- Execute `SELECT * FROM transaction WHERE status NOT IN (...)` — returning all N rows.
- Call `computeSignatureKey` (+ mirror-node lookups) N times sequentially.
- Return only 1 item in the response.

Increasing N (by creating transactions as any user) linearly increases server memory, CPU, and I/O consumption per request. At large N, the request times out or the Node.js process OOMs.

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L295-299)
```typescript
    const transactions = await this.repo.find({
      where: whereForUser,
      relations: ['groupItem'],
      order,
    });
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L301-308)
```typescript
    for (const transaction of transactions) {
      /* Check if the user should sign the transaction */
      try {
        const keysToSign = await this.userKeysToSign(transaction, user);
        if (keysToSign.length > 0) result.push({ transaction, keysToSign });
      } catch (error) {
        console.log(error);
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

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L54-57)
```typescript
@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L165-178)
```typescript
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
