The code at the cited lines is confirmed. Here is the evaluation:

**Confirmed code facts:**

- `this.repo.find(...)` at lines 295–299 has no `take`/`skip` — unbounded fetch confirmed. [1](#0-0) 
- The `for` loop at lines 301–309 `await`s `userKeysToSign` per transaction — sequential per-row async DB work confirmed. [2](#0-1) 
- Pagination via `.slice(offset, offset + limit)` at line 313 is applied only after the full loop — post-hoc pagination confirmed. [3](#0-2) 
- Compare with `getTransactions`, which correctly applies `skip`/`take` at the DB level (lines 179–181). [4](#0-3) 

**SECURITY.md scope check:**

The exclusion "Impacts that only require DDoS" refers to volumetric/network-layer flooding. This finding is an **application-level algorithmic complexity vulnerability** — a single authenticated HTTP GET triggers O(N) sequential database queries due to a code design flaw, not a flood of requests. It does not fall under that exclusion. [5](#0-4) 

---

# Audit Report

## Title
Unbounded Iteration in `getTransactionsToSign` Causes O(N) Per-Request Database Query Amplification Leading to Server Resource Exhaustion

## Summary
`TransactionsService.getTransactionsToSign()` fetches every non-terminal transaction from the database with no row limit, then issues at least one sequential async database query per transaction to compute signing keys. Pagination is applied only after the full iteration completes. A single authenticated `GET /transactions/sign` request triggers O(N) database queries where N is the number of active transactions, exhausting connection pool slots, CPU, and memory.

## Finding Description

**No `take` limit on the initial fetch:**

In `back-end/apps/api/src/transactions/transactions.service.ts`, `getTransactionsToSign` calls `this.repo.find(...)` with no `take` or `skip`:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no take / skip
});
``` [1](#0-0) 

**Unbounded per-item sequential async work:**

For every row returned, the code sequentially `await`s `userKeysToSign`, which calls `transactionSignatureService.computeSignatureKey` and `entityManager.find(UserKey, ...)` — at least one additional DB query per transaction:

```typescript
for (const transaction of transactions) {
  try {
    const keysToSign = await this.userKeysToSign(transaction, user);
    if (keysToSign.length > 0) result.push({ transaction, keysToSign });
  } catch (error) { ... }
}
``` [2](#0-1) 

**Pagination applied post-hoc:**

The `limit`/`offset` from the caller's `Pagination` object only slices the already-computed in-memory array — it never constrains the DB fetch or the loop:

```typescript
return {
  totalItems: result.length,
  items: result.slice(offset, offset + limit),
  page,
  size,
};
``` [3](#0-2) 

**Contrast with correct pattern:**

`getTransactions` correctly applies `skip`/`take` at the DB level, preventing unbounded fetches: [4](#0-3) 

**`userKeysToSign` delegates to `userKeysRequiredToSign`:** [6](#0-5) 

which is defined in `back-end/libs/common/src/utils/transaction/index.ts` and issues `entityManager.find(UserKey, ...)` per transaction. [7](#0-6) 

## Impact Explanation

For a deployment with N active (non-terminal) transactions:

- **Database connection exhaustion:** N sequential `await entityManager.find(...)` calls hold DB connections for the full duration of the request. Concurrent requests from multiple users multiply this linearly.
- **Memory pressure:** All N transaction rows (including `transactionBytes` blobs and `groupItem` relations) are loaded into the Node.js heap simultaneously.
- **CPU exhaustion:** `SDKTransaction.fromBytes(transaction.transactionBytes)` and `computeSignatureKey` are called N times per request.
- **Cascading denial of service:** A single user repeatedly calling `GET /transactions/sign` can saturate the DB connection pool, causing all other API requests to queue or fail.

The endpoint comment `/* NO LONGER USED BY FRONT-END */` confirms it is dead code that was never removed, yet remains fully active and reachable.

## Likelihood Explanation

- **Attacker precondition:** Only a valid JWT (any registered, verified user). No admin role required.
- **Trigger:** A single HTTP GET to `/transactions/sign`. No special payload needed.
- **Natural growth:** Even without a malicious actor, a long-running deployment accumulates thousands of transactions. Legitimate users hitting this endpoint will experience degraded performance that worsens monotonically over time.
- **Amplification:** Concurrent requests multiply the effect.

## Recommendation

1. **Remove the endpoint entirely** — it is already marked as no longer used by the front-end. Deleting the controller handler and service method eliminates the attack surface completely.
2. **If the endpoint must be retained**, apply a hard server-side `take` cap on the initial `repo.find(...)` call (e.g., `take: Math.min(limit, MAX_PAGE_SIZE)`) and pass `skip: offset` to the query, mirroring the pattern used in `getTransactions` and `getHistoryTransactions`.
3. **Refactor the signing-key computation** to use a single batched query across all fetched transaction IDs rather than one query per transaction.

## Proof of Concept

```
# Precondition: valid JWT for any registered user; N non-terminal transactions exist in DB

GET /transactions/sign?page=1&limit=10
Authorization: Bearer <valid_jwt>

# Server executes:
#   1. SELECT * FROM transaction WHERE status NOT IN (...) -- returns N rows, no LIMIT
#   2. For each of N rows:
#      SELECT * FROM user_key WHERE public_key IN (...) -- 1+ queries per row
#
# Total DB queries: O(N)
# Repeating this request concurrently exhausts the DB connection pool.
```

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L875-877)
```typescript
  async userKeysToSign(transaction: Transaction, user: User, showAll: boolean = false) {
    return userKeysRequiredToSign(transaction, user, this.transactionSignatureService, this.entityManager, showAll);
  }
```

**File:** SECURITY.md (L44-44)
```markdown
- Impacts that only require DDoS.
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L1-3)
```typescript
import { Transaction as SDKTransaction } from '@hiero-ledger/sdk';

import { EntityManager, In, Repository } from 'typeorm';
```
