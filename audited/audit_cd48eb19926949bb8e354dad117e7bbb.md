### Title
Unbounded In-Memory Loop in `getTransactionsToSign` Enables Authenticated Resource Exhaustion DoS

### Summary
`getTransactionsToSign()` in the API service fetches **all** active transactions from the database without any row limit, then iterates over every record performing expensive per-transaction async I/O (mirror-node account lookups via `computeSignatureKey`). Any authenticated, verified user can trigger this endpoint with a single HTTP request. As the number of active transactions grows, the request consumes unbounded memory and exhausts the HTTP connection pool, degrading or crashing the shared NestJS process for all users.

### Finding Description

**Root cause — no `take` limit on the DB query:** [1](#0-0) 

```ts
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
  // ← no `take` / `skip`; returns every active transaction
});
```

Compare with `getHistoryTransactions` and `getTransactionsToApprove`, which both pass `skip: offset, take: limit` to the ORM and perform pagination at the database level. [2](#0-1) 

**Root cause — unbounded per-transaction async loop:** [3](#0-2) 

For every transaction returned, `userKeysToSign` → `userKeysRequiredToSign` → `keysRequiredToSign` → `computeSignatureKey` is called. `computeSignatureKey` deserializes the transaction bytes and makes multiple outbound mirror-node HTTP calls (fee payer, signing accounts, receiver accounts, node account): [4](#0-3) 

Pagination is applied only **after** the full in-memory loop completes: [5](#0-4) 

**Exposed endpoint — reachable by any verified user:** [6](#0-5) 

The controller comment `/* NO LONGER USED BY FRONT-END */` does not remove the route; it remains live and guarded only by standard JWT + verified-user guards, accessible to any registered user.

**Pagination decorator enforces `size ≤ 100` at the HTTP layer**, but this limit is never propagated to the DB query — it only slices the already-computed in-memory result: [7](#0-6) 

### Impact Explanation

With N active transactions and M accounts per transaction, a single request causes:

1. **Memory spike** — all N transaction rows (including `transactionBytes` blobs) loaded into the Node.js heap simultaneously.
2. **Connection pool exhaustion** — up to N × M outbound HTTP calls to the mirror node, saturating the connection pool and starving other concurrent requests.
3. **Event-loop starvation** — the sequential `await` loop inside `for (const transaction of transactions)` blocks the async queue for the duration of all mirror-node calls.
4. **Cascading service degradation** — because NestJS runs in a single process, all other users' requests queue behind this one, causing timeouts across the entire API.

Impact worsens monotonically as the organization accumulates active transactions; there is no self-correcting mechanism.

### Likelihood Explanation

- **Attacker precondition**: valid JWT token for any verified user — the lowest privilege level in the system.
- **Trigger**: one `GET /transactions/sign?page=1&size=1` request.
- **No rate limiting** is visible on this endpoint in the reviewed code.
- The endpoint is still live despite the "NO LONGER USED BY FRONT-END" comment, meaning it is an overlooked but fully functional attack surface.
- A malicious insider or a compromised low-privilege account is a realistic threat model for an enterprise multi-sig tool.

### Recommendation

1. **Push pagination into the database query** — add `take: limit` and `skip: offset` to the `repo.find()` call, mirroring the pattern used in `getHistoryTransactions`.
2. **Move the signing-key filter to SQL** — join against `transaction_signer` / `user_key` tables so only transactions actually requiring the requesting user's keys are returned, eliminating the need for the in-memory loop entirely.
3. **If the endpoint is truly unused**, remove the route or return `410 Gone` to eliminate the attack surface.
4. **Add a hard server-side cap** on the number of transactions processed per request, independent of the pagination decorator.

### Proof of Concept

**Setup**: An organization with 10,000+ active transactions in `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION` status (achievable by any user with the `createTransaction` permission over time, or by a malicious creator submitting many transactions).

**Trigger** (single HTTP request from any verified user):
```
GET /transactions/sign?page=1&size=1
Authorization: Bearer <any_valid_jwt>
```

**Execution path**:
1. `getTransactionsToSign` is called.
2. `repo.find({ where: whereForUser })` returns all 10,000+ rows with no limit.
3. The `for` loop calls `userKeysToSign` → `computeSignatureKey` for each row, issuing multiple mirror-node HTTP calls per transaction.
4. Node.js heap grows proportionally to the number of transactions × transaction byte size.
5. The HTTP connection pool is saturated; concurrent requests from other users begin timing out.
6. The server process may OOM-crash or become unresponsive for the duration of the request.

**Expected outcome**: API unavailability for all users for the duration of the request; repeated triggering causes sustained denial of service.

### Citations

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

**File:** back-end/libs/common/src/decorators/pagination-params.decorator.ts (L22-24)
```typescript
  if (size > 100) {
    throw new BadRequestException(ErrorCodes.IPP);
  }
```
