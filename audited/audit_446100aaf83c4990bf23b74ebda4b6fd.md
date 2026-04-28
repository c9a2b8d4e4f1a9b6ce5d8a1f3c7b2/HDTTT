### Title
DoS: Attacker May Inflate `getTransactionsToSign()` Cost by Creating Unbounded Non-Terminal Transactions

### Summary
`getTransactionsToSign()` in `TransactionsService` fetches **all** non-terminal transactions from the database with no row limit, then iterates over every one calling `userKeysToSign()` → `computeSignatureKey()` (which deserializes transaction bytes and performs external account-cache lookups) before applying pagination in memory. Any authenticated user can create transactions with no per-user cap, so an attacker can flood the system with `WAITING_FOR_SIGNATURES` transactions, making every call to `GET /transactions/sign` perform an unbounded, expensive per-row computation that degrades or crashes the API service.

### Finding Description

**Root cause — unbounded full-table scan with per-row async work:**

In `back-end/apps/api/src/transactions/transactions.service.ts`, `getTransactionsToSign()` issues a `repo.find()` with **no `take` limit**: [1](#0-0) 

It then iterates over every returned row and awaits an expensive async call per transaction: [2](#0-1) 

Pagination is applied **in memory after the full scan**, so the `size ≤ 100` guard in `PaginationParams` only limits the response payload, not the work performed: [3](#0-2) [4](#0-3) 

**Cost of each iteration — `computeSignatureKey()`:**

`userKeysToSign()` delegates to `userKeysRequiredToSign()` → `keysRequiredToSign()` → `transactionSignatureService.computeSignatureKey()`. Each call deserializes the transaction bytes, resolves the fee-payer account, iterates signing accounts, and performs async account-cache lookups (potentially hitting the Hedera mirror node): [5](#0-4) [6](#0-5) 

**Attacker entry point — unrestricted transaction creation:**

Any verified user with at least one registered key can call `POST /transactions` with no per-user transaction count limit. Transactions are created in `WAITING_FOR_SIGNATURES` status, which is excluded from the terminal-status filter in `getTransactionsToSign()`, so they remain in the scanned set indefinitely until manually canceled or expired: [7](#0-6) [8](#0-7) 

### Impact Explanation

An attacker registers as a normal user, uploads one key, and submits thousands of valid (but never-to-be-signed) transactions. Every subsequent call to `GET /transactions/sign` by **any** user on the platform triggers:
- A full DB scan returning all N attacker transactions plus legitimate ones.
- N synchronous-in-sequence `computeSignatureKey()` calls, each deserializing bytes and awaiting async I/O.

At scale this causes: severe API response-time degradation (seconds to minutes per request), Node.js event-loop starvation blocking other requests, and potential OOM from loading all transaction rows into memory simultaneously. The endpoint becomes effectively unavailable — a full application-layer DoS.

### Likelihood Explanation

The attacker only needs a valid account (registration is open to any user who can pass email verification) and one uploaded key. Transaction creation has no rate limit or per-user quota visible in the codebase. The attack is cheap to mount (each transaction costs only an API call) and self-sustaining because `WAITING_FOR_SIGNATURES` transactions persist until explicitly canceled by their creator or expired by the Hedera network's `validStart` window — the attacker can continuously refresh them.

### Recommendation

1. **Apply DB-level pagination before the per-row loop.** Pre-filter candidates in SQL (e.g., join `transaction_signer` or `user_key` on the user's public keys) so only transactions plausibly requiring the user's signature are fetched, with a `take` limit.
2. **Add a per-user transaction creation quota** (e.g., max N active non-terminal transactions per user) enforced at `createTransaction()`.
3. **Rate-limit `POST /transactions`** per authenticated user using a NestJS throttle guard.
4. **Consider a background job** to expire stale `WAITING_FOR_SIGNATURES` transactions past their Hedera `validStart` window, shrinking the active set automatically.

### Proof of Concept

1. Register a user account and upload one ED25519 key via `POST /user/:id/keys`.
2. In a loop, call `POST /transactions` with a valid (non-expired) `AccountCreateTransaction` body signed by that key — repeat 10,000 times. Each transaction lands in `WAITING_FOR_SIGNATURES`.
3. As any other user, call `GET /transactions/sign?page=1&size=10`.
4. Observe: the server fetches all 10,000+ rows, calls `computeSignatureKey()` for each sequentially, and either times out or returns after an extreme delay — while blocking the Node.js thread pool for all concurrent requests.

**Relevant code path:**
`GET /transactions/sign` → `TransactionsController` → `getTransactionsToSign()` (line 295: unbounded `repo.find()`) → `for` loop (line 301) → `userKeysToSign()` → `computeSignatureKey()` (mirror-node I/O per row) → in-memory `slice()` (line 313). [9](#0-8)

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L295-316)
```typescript
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L400-401)
```typescript
  async createTransactions(dtos: CreateTransactionDto[], user: User): Promise<Transaction[]> {
    if (dtos.length === 0) return [];
```

**File:** back-end/libs/common/src/decorators/pagination-params.decorator.ts (L22-24)
```typescript
  if (size > 100) {
    throw new BadRequestException(ErrorCodes.IPP);
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
