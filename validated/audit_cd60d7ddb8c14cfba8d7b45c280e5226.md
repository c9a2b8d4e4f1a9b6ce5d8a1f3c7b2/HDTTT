### Title
Missing User-Scoped Access Control on `GET /transactions/history` Exposes All Historical Transactions to Any Authenticated User

### Summary
The `getHistoryTransactions` endpoint in `TransactionsController` does not apply any user-based access filtering. Any authenticated user can retrieve all historical transactions (executed, failed, expired, canceled, archived) belonging to every other user in the organization, including their raw `transactionBytes`, `transactionHash`, `transactionId`, and network metadata.

### Finding Description
In `transactions.controller.ts`, the `getHistoryTransactions` handler does not extract or forward the requesting user's identity to the service layer: [1](#0-0) 

The handler signature accepts no `@GetUser()` parameter and calls `this.transactionsService.getHistoryTransactions(paginationParams, filter, sort)` with no user argument.

In `transactions.service.ts`, `getHistoryTransactions` takes no `user` parameter and issues an unscoped database query returning every transaction whose status is in the terminal set: [2](#0-1) 

Contrast this with `getTransactions`, which correctly scopes results to the requesting user via `signers`, `observers`, `creatorKey`, and approver sub-queries: [3](#0-2) 

A second, lower-severity instance exists in `transaction-groups.controller.ts`. The endpoint annotated `/* TESTING ONLY */` calls `getTransactionGroups()` with no user filter, returning every group in the database to any authenticated caller: [4](#0-3) [5](#0-4) 

### Impact Explanation
Any verified organization member can enumerate the complete history of every other user's transactions. The `TransactionDto` serialization exposes `transactionBytes` (the full serialized Hedera SDK transaction), `transactionHash`, `transactionId`, `mirrorNetwork`, `validStart`, `creatorKey`, and status. This leaks:
- The full transaction payload of every peer, including account IDs, amounts, memo fields, and key structures embedded in `transactionBytes`.
- Organizational activity patterns (who transacted, when, on which network, with what outcome).

### Likelihood Explanation
The endpoint is reachable by any user who has completed registration and login (guarded only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`). No elevated role is required. The route `GET /transactions/history` is a standard REST path that any user or automated client would naturally discover and call. [6](#0-5) 

### Recommendation
1. Add `@GetUser() user: User` to `getHistoryTransactions` in `TransactionsController` and thread it through to `TransactionsService.getHistoryTransactions`.
2. In `getHistoryTransactions`, apply the same user-scoping WHERE clause used in `getTransactions` (filter by `creatorKey.userId`, `signers.userId`, `observers.userId`, and approver sub-query).
3. Remove or gate the `GET /transaction-groups` (testing-only) endpoint behind `AdminGuard` or delete it from the production build entirely.

### Proof of Concept
```
# Step 1: Authenticate as any verified user
POST /auth/login
{ "email": "alice@org.com", "password": "..." }
→ { "accessToken": "<alice_token>" }

# Step 2: Retrieve ALL historical transactions for every user in the org
GET /transactions/history
Authorization: Bearer <alice_token>

# Response: paginated list of ALL executed/failed/expired/canceled/archived
# transactions from every user, including full transactionBytes, hashes, etc.
```

Alice receives Bob's, Carol's, and every other user's completed transaction records without restriction.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L54-57)
```typescript
@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
```

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L150-217)
```typescript
  async getTransactions(
    user: User,
    { page, limit, size, offset }: Pagination,
    sort?: Sorting[],
    filter?: Filtering[],
  ): Promise<PaginatedResourceDto<Transaction>> {
    const where = getWhere<Transaction>(filter);
    const order = getOrder(sort);

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

    const findOptions: FindManyOptions<Transaction> = {
      where: whereForUser,
      order,
      relations: ['creatorKey', 'groupItem', 'groupItem.group'],
      skip: offset,
      take: limit,
    };

    const whereBrackets = new Brackets(qb =>
      qb.where(where).andWhere(
        `
        (
          with recursive "approverList" as
            (
              select * from "transaction_approver"
              where "transaction_approver"."transactionId" = "Transaction"."id"
                union all
                  select "approver".* from "transaction_approver" as "approver"
                  join "approverList" on "approverList"."id" = "approver"."listId"
            )
          select count(*) from "approverList"
          where "approverList"."deletedAt" is null and "approverList"."userId" = :userId
        ) > 0
        `,
        {
          userId: user.id,
        },
      ),
    );

    const [transactions, total] = await this.repo
      .createQueryBuilder()
      .setFindOptions(findOptions)
      .orWhere(whereBrackets)
      .getManyAndCount();

    return {
      totalItems: total,
      items: transactions,
      page,
      size,
    };
  }
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

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L52-57)
```typescript
  /* TESTING ONLY: Get all transactions groups */
  @Get()
  @Serialize(TransactionGroupDto)
  getTransactionGroups(): Promise<TransactionGroup[]> {
    return this.transactionGroupsService.getTransactionGroups();
  }
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L36-38)
```typescript
  getTransactionGroups(): Promise<TransactionGroup[]> {
    return this.dataSource.manager.find(TransactionGroup);
  }
```
