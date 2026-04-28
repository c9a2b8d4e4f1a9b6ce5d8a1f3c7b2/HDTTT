Based on my direct code inspection, the core claim is confirmed. Here is my assessment:

---

Audit Report

## Title
`createTransactions()` Uses Only the First DTO's `mirrorNetwork` to Build the Client for All Batch Transactions

## Summary
`TransactionsService.createTransactions()` accepts an array of `CreateTransactionDto` objects, each carrying its own `mirrorNetwork` field. A single Hedera `Client` is constructed exclusively from `dtos[0].mirrorNetwork` and then reused to validate every DTO in the batch. Any DTO after index 0 that specifies a different network is frozen and node-validated against the wrong network's client.

## Finding Description

In `back-end/apps/api/src/transactions/transactions.service.ts`, the batch creation path is:

```typescript
// line 405 — client built from FIRST dto only
const client = await getClientFromNetwork(dtos[0].mirrorNetwork);

// lines 409-411 — ALL dtos validated with that single client
const validatedData = await Promise.all(
  dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)),
);
``` [1](#0-0) 

The service imports both `getNodeAccountIdsFromClientNetwork` and `isTransactionValidForNodes`, confirming they are used inside `validateAndPrepareTransaction` with the shared `client`: [2](#0-1) 

The caller `createTransactionGroup` passes all group-item transactions in a single `createTransactions` call:

```typescript
const transactionDtos = dto.groupItems.map(item => item.transaction);
const transactions = await this.transactionsService.createTransactions(
  transactionDtos,
  user,
);
``` [3](#0-2) 

**Root cause:** The failed assumption is that all DTOs in a batch share the same `mirrorNetwork`. The code never validates this assumption and never builds a per-DTO client.

**Exploit path:**
1. User creates a transaction group via `POST /transaction-groups` with two items: item 0 has `mirrorNetwork: "testnet"`, item 1 has `mirrorNetwork: "mainnet"`.
2. `createTransactions` builds a testnet `Client` from `dtos[0].mirrorNetwork`.
3. Item 1 (mainnet transaction) is passed to `validateAndPrepareTransaction` with the testnet client.
4. If item 1 is not yet frozen, it is frozen with the testnet client — embedding testnet node/ledger metadata into the transaction bytes.
5. Node validation runs `getNodeAccountIdsFromClientNetwork(client)` (testnet nodes) against item 1's mainnet node IDs → throws `TNVN`, rejecting the entire batch. Alternatively, if node IDs happen to overlap, the transaction passes validation but is stored with incorrect bytes.

## Impact Explanation

- **Incorrect rejection (functional DoS):** Any transaction group containing transactions for more than one network will fail with `TNVN` for all non-first-network transactions, making multi-network transaction groups permanently unusable.
- **Silent mis-freeze / data integrity violation:** If a non-first DTO's transaction is not yet frozen, it is frozen with the wrong network's client, embedding incorrect node/ledger metadata. The stored `transactionBytes` will contain node IDs from the wrong network, creating a persistent inconsistency between the stored `mirrorNetwork` field and the actual transaction bytes. When the transaction is later submitted, it will fail or behave unexpectedly on the intended network.

## Likelihood Explanation

The vulnerability is reachable by any authenticated user with no special privileges. The `createTransactionGroup` endpoint is a standard user-facing API. A user who legitimately wants to group a mainnet and a testnet transaction will trigger this bug. The code path is exercised every time a transaction group is created with heterogeneous networks. No exploitation or special knowledge is required — it is triggered by normal usage.

## Recommendation

Build a per-DTO client inside `validateAndPrepareTransaction` (or before calling it) using each DTO's own `mirrorNetwork`, rather than sharing a single client constructed from `dtos[0]`. For example:

```typescript
const validatedData = await Promise.all(
  dtos.map(async dto => {
    const dtoClient = await getClientFromNetwork(dto.mirrorNetwork);
    return this.validateAndPrepareTransaction(dto, user, dtoClient);
  }),
);
```

If batching with a shared client is intentional for performance, add an upfront guard that rejects the batch if any DTO specifies a `mirrorNetwork` different from `dtos[0].mirrorNetwork`, making the constraint explicit and the error message clear.

## Proof of Concept

1. Authenticate as any valid user.
2. `POST /transaction-groups` with a body containing two `groupItems`:
   - Item 0: a valid testnet transaction with `mirrorNetwork: "testnet"`
   - Item 1: a valid mainnet transaction with `mirrorNetwork: "mainnet"`
3. Observe that the entire batch is rejected with `TNVN` (transaction not valid for nodes), even though item 1 is a perfectly valid mainnet transaction.
4. Alternatively, submit item 0 as mainnet and item 1 as testnet with an unfrozen testnet transaction. Observe that item 1 is frozen using the mainnet client and stored with mainnet node IDs despite having `mirrorNetwork: "testnet"`. [4](#0-3)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L66-68)
```typescript
  getNodeAccountIdsFromClientNetwork,
  isTransactionValidForNodes,
} from '@app/common';
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L400-411)
```typescript
  async createTransactions(dtos: CreateTransactionDto[], user: User): Promise<Transaction[]> {
    if (dtos.length === 0) return [];

    await attachKeys(user, this.entityManager);

    const client = await getClientFromNetwork(dtos[0].mirrorNetwork);

    try {
      // Validate all DTOs upfront
      const validatedData = await Promise.all(
        dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)),
      );
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L47-53)
```typescript
    const transactionDtos = dto.groupItems.map(item => item.transaction);

    // Batch create all transactions
    const transactions = await this.transactionsService.createTransactions(
      transactionDtos,
      user,
    );
```
