### Title
Unbounded Full-Table Scan with Per-Row Async Computation in `getTransactionsToSign` Causes Server Resource Exhaustion

### Summary
`getTransactionsToSign` in `TransactionsService` fetches every non-terminal transaction from the database with no row limit, then performs an expensive async operation (`userKeysToSign` → `computeSignatureKey` → SDK deserialization + mirror-node account lookups) for each row before applying pagination. As the transaction table grows, a single authenticated API request consumes CPU, memory, and I/O proportional to the total number of active transactions in the system, enabling any verified user to cause sustained service degradation.

### Finding Description

**Root cause — no `take` limit on the database query:**

```ts
// back-end/apps/api/src/transactions/transactions.service.ts  lines 295-299
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no `take` / `skip` — fetches the entire non-terminal transaction table
});
``` [1](#0-0) 

**Unbounded per-row async work:**

```ts
// lines 301-309
for (const transaction of transactions) {
  try {
    const keysToSign = await this.userKeysToSign(transaction, user);
    if (keysToSign.length > 0) result.push({ transaction, keysToSign });
  } catch (error) { console.log(error); }
}
``` [2](#0-1) 

Each `userKeysToSign` call delegates to `userKeysRequiredToSign`, which calls `keysRequiredToSign`, which in turn calls `computeSignatureKey`. That function deserializes the raw transaction bytes via the Hedera SDK and makes one or more async mirror-node account-info lookups per signing account referenced in the transaction. [3](#0-2) [4](#0-3) 

**Pagination is applied only after all rows are processed:**

```ts
// line 313
items: result.slice(offset, offset + limit),
``` [5](#0-4) 

The function signature accepts `Pagination` parameters but ignores them during the database fetch and the computation loop; they are used only to slice the already-computed in-memory array.

**Exploit path:**

1. Attacker registers as a normal user and gets verified (standard product flow).
2. Attacker (or colluding users) creates a large number of transactions via `POST /transactions` — each transaction is valid and accepted by the system.
3. Attacker repeatedly calls `GET /transactions/sign` (the endpoint backed by `getTransactionsToSign`). Each call causes the server to fetch all non-terminal transactions and run `computeSignatureKey` for every one of them.
4. Because `computeSignatureKey` is `await`-ed sequentially inside the loop, the Node.js event loop is blocked for the duration of all mirror-node round-trips multiplied by the number of transactions.
5. Concurrent legitimate requests queue up behind these long-running handlers, causing timeouts and service unavailability for all users.

### Impact Explanation

- **Availability**: A single authenticated user can trigger O(N) mirror-node HTTP calls and O(N) SDK deserialization operations per API request, where N is the total number of active transactions. With a large enough N, each request takes tens of seconds, starving the NestJS worker of event-loop capacity and causing HTTP timeouts for all concurrent users.
- **Severity**: High — complete service degradation is achievable by any verified user without any privileged access, and the cost to the attacker is low (creating transactions is a normal product flow).

### Likelihood Explanation

- Any verified user can reach the endpoint; no admin or special role is required.
- Transaction creation is a core product feature, so the table naturally grows over time even without adversarial intent.
- A single user creating a few hundred transactions is sufficient to make each `GET /transactions/sign` call take several seconds, given the sequential mirror-node lookups per transaction.

### Recommendation

Apply the database `take`/`skip` limit **before** the computation loop, and push the key-eligibility filter into the database query rather than doing it in application code:

1. Add `take: limit, skip: offset` to the `repo.find(...)` call so the database returns only the page of rows needed.
2. Pre-filter transactions by the user's public keys at the SQL level (similar to how `getTransactions` uses a `Brackets` subquery) so that `userKeysToSign` is only called for transactions that are already known to require the user's keys.
3. If per-row `computeSignatureKey` calls are unavoidable, run them concurrently with `Promise.all` and add a concurrency cap (e.g., `p-limit`) to bound resource usage.

### Proof of Concept

1. Register and verify a user account.
2. Create 500 transactions via `POST /transactions` (all in `WAITING_FOR_SIGNATURES` status).
3. Issue `GET /transactions/sign?page=1&size=10` and measure response time.
4. **Expected**: The server fetches all 500 transactions, calls `computeSignatureKey` 500 times (each involving at least one mirror-node HTTP call), and only then returns 10 results. Response time scales linearly with the number of transactions, not with the requested page size.
5. Repeat with 1 000, 5 000 transactions to demonstrate linear degradation and eventual HTTP gateway timeout.

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
