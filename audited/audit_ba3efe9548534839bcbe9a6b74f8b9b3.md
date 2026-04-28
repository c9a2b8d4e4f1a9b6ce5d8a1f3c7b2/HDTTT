### Title
Unauthenticated Cross-User Transaction History Disclosure via Missing User Filter in `getHistoryTransactions`

### Summary
The `GET /transactions/history` endpoint returns all completed transactions from every user in the organization to any authenticated, verified user. Unlike every other transaction-listing endpoint, `getHistoryTransactions` accepts no user context and applies no per-user WHERE clause, exposing the full transaction history — including `transactionBytes`, account IDs, amounts, and memo fields — of all other users without their knowledge or consent.

### Finding Description
**Root cause:** `getHistoryTransactions` in the controller takes no `@GetUser()` parameter and passes no user identity to the service. The service method applies only a status filter (terminal statuses), with zero ownership or participation check.

Controller — no user parameter at all: [1](#0-0) 

Service — no user-scoped WHERE clause: [2](#0-1) 

Contrast this with `getTransactions`, which correctly scopes results to the requesting user via `signers.userId`, `observers.userId`, `creatorKey.userId`, and an approver sub-query: [3](#0-2) 

The project's own e2e test confirms the behavior — a regular `userAuthToken` call returns `addedTransactions.total`, which is the combined count of **both** user and admin transactions: [4](#0-3) 

**Exploit path:**
1. Attacker registers/is invited as a normal verified user.
2. Attacker calls `GET /transactions/history?page=1&size=9999` with their JWT.
3. Response contains every completed transaction from every other user: full `transactionBytes`, transaction IDs, types, descriptions, account IDs, and amounts.

### Impact Explanation
Every completed transaction (status: EXECUTED, FAILED, EXPIRED, CANCELED, ARCHIVED) from every organization member is readable by any peer user. The `transactionBytes` field contains the full serialized Hedera SDK transaction, which encodes payer account, node account, transfer amounts, memo, and all signatures. This constitutes a complete financial history leak across all organization members.

### Likelihood Explanation
The attacker only needs a valid, verified JWT — the normal credential any organization member holds. The endpoint is reachable over standard HTTPS with no additional privilege. The front-end already calls this endpoint for its own History view, so the API path is well-known and documented.

### Recommendation
Add `@GetUser() user: User` to `getHistoryTransactions` in the controller and pass it to the service. In the service, add the same user-scoped OR conditions used by `getTransactions` (creator, signer, observer, approver) combined with the existing status filter. This mirrors the pattern already established for all other transaction-listing endpoints.

### Proof of Concept
```bash
# Step 1: Login as any verified user and obtain JWT
TOKEN=$(curl -s -X POST https://<server>/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@org.com","password":"..."}' | jq -r .accessToken)

# Step 2: Retrieve ALL completed transactions from ALL users
curl -s "https://<server>/transactions/history?page=1&size=9999" \
  -H "Authorization: Bearer $TOKEN" | jq '.totalItems, .items[].transactionId'

# Expected: totalItems equals the sum of every user's completed transactions,
# not just the requesting user's own history.
```

The e2e test at `back-end/apps/api/test/spec/transaction.e2e-spec.ts` line 493 already asserts `body.totalItems === addedTransactions.total` (all users combined), confirming this is the current, unguarded behavior. [1](#0-0) [2](#0-1)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L142-154)
```typescript
  @Get('/history')
  @Serialize(withPaginatedResponse(TransactionDto))
  getHistoryTransactions(
    @PaginationParams() paginationParams: Pagination,
    @SortingParams(transactionProperties) sort?: Sorting[],
    @FilteringParams({
      validProperties: transactionProperties,
      dateProperties: transactionDateProperties,
    })
    filter?: Filtering[],
  ): Promise<PaginatedResourceDto<Transaction>> {
    return this.transactionsService.getHistoryTransactions(paginationParams, filter, sort);
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L159-173)
```typescript
    const whereForUser = [
      { ...where, signers: { userId: user.id } },
      {
        ...where,
        observers: {
          userId: user.id,
        },
      },
      {
        ...where,
        creatorKey: {
          userId: user.id,
        },
      },
    ];
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L220-249)
```typescript
  async getHistoryTransactions(
    { page, limit, size, offset }: Pagination,
    filter: Filtering[] = [],
    sort: Sorting[] = [],
  ): Promise<PaginatedResourceDto<Transaction>> {
    const order = getOrder(sort);

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

    const [transactions, total] = await this.repo
      .createQueryBuilder()
      .setFindOptions(findOptions)
      .getManyAndCount();

    return {
      totalItems: total,
      items: transactions,
      page,
      size,
    };
  }
```

**File:** back-end/apps/api/test/spec/transaction.e2e-spec.ts (L489-494)
```typescript
    it('(GET) should get all transactions that are visible to everyone', async () => {
      const { status, body } = await endpoint.get(null, userAuthToken, 'page=1&size=99');

      expect(status).toEqual(200);
      expect(body.totalItems).toEqual(addedTransactions.total);
    });
```
