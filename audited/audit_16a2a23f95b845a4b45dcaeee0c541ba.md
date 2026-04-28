### Title
Attacker Can Grief a Victim by Creating Many Transactions Requiring the Victim's Signature, Causing Unbounded Server-Side Resource Exhaustion in `getTransactionsToSign`

### Summary
The `getTransactionsToSign` function in the API backend loads **all** non-terminal transactions from the database with no row limit, then performs an async `userKeysToSign` call for every single row in a sequential loop. Because any authenticated user can create transactions that list an arbitrary public key as a required signer, an attacker can pre-populate the database with thousands of such transactions targeting a victim's public key. When the victim subsequently calls the "transactions to sign" endpoint, the server must iterate over every one of those rows with per-row async DB work, causing extreme latency, connection exhaustion, or a hard timeout that permanently degrades the victim's ability to use the platform.

### Finding Description

**Root cause — unbounded full-table scan with per-row async work**

`back-end/apps/api/src/transactions/transactions.service.ts`, `getTransactionsToSign` (lines 295–309):

```typescript
const transactions = await this.repo.find({
  where: whereForUser,   // filters only by STATUS, not by user
  relations: ['groupItem'],
  order,
});                      // NO `take` / limit — loads every non-terminal row

for (const transaction of transactions) {
  try {
    const keysToSign = await this.userKeysToSign(transaction, user); // async DB call per row
    if (keysToSign.length > 0) result.push({ transaction, keysToSign });
  } catch (error) { console.log(error); }
}

return {
  totalItems: result.length,
  items: result.slice(offset, offset + limit), // pagination applied AFTER full scan
  ...
};
``` [1](#0-0) 

The `whereForUser` predicate filters only on `status` (excluding terminal states), not on any user-specific column. This means the query returns every non-terminal transaction in the entire system. Pagination is applied in-memory **after** the full scan and the per-row async loop, so requesting page 1 still forces the server to process every row.

**Attack vector — attacker-controlled transaction creation**

Any authenticated user can call `POST /transactions` and supply arbitrary `publicKeys` (the set of keys required to sign). Because Hedera public keys are public information, an attacker can craft thousands of valid transaction payloads that each list the victim's public key as a required signer. The backend stores these in PostgreSQL without any per-user creation cap or rate limit visible in the transaction creation path. [2](#0-1) 

**Exploit flow**

1. Attacker registers a normal user account (no privilege required).
2. Attacker obtains the victim's public key (public on Hedera).
3. Attacker sends N `POST /transactions` requests, each with a valid transaction body listing the victim's public key as a required signer. These are stored in the backend DB; no on-chain submission is needed.
4. Victim calls `GET /transactions/sign` (maps to `getTransactionsToSign`).
5. The server executes `repo.find(...)` with no limit — returns all N attacker-created rows plus any legitimate rows.
6. The server then calls `userKeysToSign(transaction, user)` **N times sequentially**, each making additional DB queries.
7. The request either times out at the HTTP layer, exhausts the DB connection pool, or returns after an extreme delay — permanently degrading the victim's ability to view and sign transactions.

### Impact Explanation

- **Victim's signing workflow is blocked**: The victim cannot reliably retrieve the list of transactions they need to sign, which is a core platform function.
- **Server-side resource exhaustion**: Each victim request triggers O(N) async DB queries. With enough attacker-created transactions, this saturates the DB connection pool and degrades service for all users on the same server instance.
- **Persistent state**: The attacker's transactions remain in the DB until they expire or are manually cleaned up. The attack is durable and does not require the attacker to remain active.
- **No recovery path for the victim**: The victim cannot filter out attacker-created transactions from the query because the filter is applied server-side after the full scan.

### Likelihood Explanation

- **Attacker preconditions**: Only a valid (non-privileged) user account is required. Registration is open to any user.
- **Cost to attacker**: Creating transactions is a free API operation (no on-chain fees required for backend storage). An attacker can script thousands of requests with minimal effort.
- **Victim's public key**: Hedera public keys are publicly visible on-chain and in the mirror node API, making target selection trivial.
- **No existing mitigations**: There is no `take` limit on the `repo.find` call, no per-user transaction creation rate limit visible in the codebase, and no cap on how many transactions can reference a given public key.

### Recommendation

1. **Apply a database-level limit to `getTransactionsToSign`**: Add a `take` parameter to the `repo.find` call so the query never loads more rows than the requested page size. Pre-filter at the DB level using a join on `publicKeys` to only return transactions that actually contain the user's keys.
2. **Move the user-key filter into the SQL query**: Instead of loading all non-terminal transactions and filtering in memory, add a `WHERE` clause (or a join) that restricts results to transactions containing at least one of the requesting user's public keys.
3. **Enforce a per-user transaction creation rate limit**: Add a throttler (the `back-end/apps/api/src/throttlers/` directory already exists) on `POST /transactions` to limit how many transactions a single user can create per time window.
4. **Cap the number of active transactions per creator**: Reject transaction creation if the creator already has more than a configurable maximum of non-terminal transactions.

### Proof of Concept

**Setup**: Two accounts — `attacker` and `victim`. Victim has public key `victimPubKey`.

**Step 1** — Attacker authenticates and obtains a JWT.

**Step 2** — Attacker runs a loop (e.g., 5 000 iterations):
```
POST /transactions
Authorization: Bearer <attacker_jwt>
{
  "name": "grief-tx-<i>",
  "transactionBytes": "<valid_hedera_tx_bytes_with_victimPubKey_as_signer>",
  "creatorKeyId": <attacker_key_id>,
  "signature": "<attacker_signature>",
  "mirrorNetwork": "testnet",
  "publicKeys": ["<victimPubKey>"]
}
```
Each request succeeds (201) and persists a row in the `transaction` table.

**Step 3** — Victim authenticates and calls:
```
GET /transactions/sign
Authorization: Bearer <victim_jwt>
```

**Expected (vulnerable) outcome**: The server executes `SELECT * FROM transaction WHERE status NOT IN (...)` returning all 5 000 rows, then calls `userKeysToSign` 5 000 times sequentially. The request times out (HTTP 504) or takes tens of seconds, blocking the victim's signing workflow. Repeating the attack with more rows causes permanent degradation.

**Expected (fixed) outcome**: The query is pre-filtered to only rows containing the victim's public key and is limited to the requested page size, returning in constant time regardless of total transaction count.

### Citations

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L400-462)
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

      // Batch check for existing transactions
      const transactionIds = validatedData.map(v => v.transactionId);
      const existing = await this.repo.find({
        where: {
          transactionId: In(transactionIds),
          status: Not(
            In([
              TransactionStatus.CANCELED,
              TransactionStatus.REJECTED,
              TransactionStatus.ARCHIVED,
            ]),
          ),
        },
        select: ['transactionId'],
      });

      if (existing.length > 0) {
        throw new BadRequestException(
          `Transactions already exist: ${existing.map(t => t.transactionId).join(', ')}`,
        );
      }

      // Wrap database operations in transaction
      const savedTransactions = await this.entityManager.transaction(async (entityManager) => {
        const transactions = validatedData.map(data =>
          this.repo.create({
            name: data.name,
            type: data.type,
            description: data.description,
            transactionId: data.transactionId,
            transactionHash: data.transactionHash,
            transactionBytes: data.transactionBytes,
            unsignedTransactionBytes: data.unsignedTransactionBytes,
            status: TransactionStatus.WAITING_FOR_SIGNATURES,
            creatorKey: { id: data.creatorKeyId },
            signature: data.signature,
            mirrorNetwork: data.mirrorNetwork,
            validStart: data.validStart,
            isManual: data.isManual,
            cutoffAt: data.cutoffAt,
            publicKeys: data.publicKeys,
          }),
        );

        try {
          return await entityManager.save(Transaction, transactions);
        } catch (error) {
          throw new BadRequestException(ErrorCodes.FST);
        }
      });
```
