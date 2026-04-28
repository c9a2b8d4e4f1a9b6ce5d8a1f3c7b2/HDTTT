### Title
Missing User-Scoping in `getHistoryTransactions` Exposes All Users' Transaction History to Any Authenticated User

### Summary
The `GET /transactions/history` endpoint in `TransactionsController` returns **all** history transactions (executed, failed, expired, canceled, archived) without filtering by the requesting user. Any authenticated user can retrieve the complete transaction history of every other user in the organization. This is the same vulnerability class as the external report — missing access control on a shared-state query — manifesting here as cross-tenant data exposure rather than quota DoS.

### Finding Description

**Root cause:** `getHistoryTransactions` in `transactions.service.ts` applies no user-based predicate to its database query.

In `transactions.controller.ts`, the endpoint does not pass the authenticated user to the service:

```typescript
@Get('/history')
@Serialize(withPaginatedResponse(TransactionDto))
getHistoryTransactions(
  @PaginationParams() paginationParams: Pagination,
  @SortingParams(transactionProperties) sort?: Sorting[],
  @FilteringParams({...}) filter?: Filtering[],
): Promise<PaginatedResourceDto<Transaction>> {
  return this.transactionsService.getHistoryTransactions(paginationParams, filter, sort);
}
``` [1](#0-0) 

In `transactions.service.ts`, the query contains only a status filter — no `creatorKey.userId`, `signers.userId`, `observers.userId`, or `approvers.userId` constraint:

```typescript
async getHistoryTransactions(
  { page, limit, size, offset }: Pagination,
  filter: Filtering[] = [],
  sort: Sorting[] = [],
): Promise<PaginatedResourceDto<Transaction>> {
  const findOptions: FindManyOptions<Transaction> = {
    where: {
      ...getWhere<Transaction>(filter),
      status: this.getHistoryStatusWhere(filter),   // ← only status filter
    },
    ...
  };
  const [transactions, total] = await this.repo
    .createQueryBuilder()
    .setFindOptions(findOptions)
    .getManyAndCount();
``` [2](#0-1) 

**Contrast with `getTransactions`**, which correctly scopes results to the requesting user:

```typescript
const whereForUser = [
  { ...where, signers: { userId: user.id } },
  { ...where, observers: { userId: user.id } },
  { ...where, creatorKey: { userId: user.id } },
];
``` [3](#0-2) 

The controller-level guard stack (`JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard`) authenticates the caller but does **not** scope the query to that caller's data. [4](#0-3) 

### Impact Explanation

Any authenticated user can enumerate the complete transaction history of every other user in the organization. Exposed data includes:

- Transaction type (HBAR transfers, account creation, file updates, node operations)
- Transaction IDs, hashes, valid start timestamps, and mirror network
- Transaction status and creator key associations (linking transactions to specific users)
- Group membership metadata

This breaks the multi-tenant isolation model of Organization Mode, where users should only see transactions they are party to (as creator, signer, observer, or approver).

### Likelihood Explanation

- **Attacker precondition:** A valid JWT token — i.e., any registered, verified user in the organization.
- **No privileged access required.** A newly registered user with no transactions of their own can immediately call this endpoint.
- **Trivially exploitable:** A single `GET /transactions/history` request with a valid `Authorization` header returns all other users' history.
- The endpoint is exposed via Swagger documentation, making discovery straightforward.

### Recommendation

Pass the authenticated user into `getHistoryTransactions` and apply the same user-scoping predicate used in `getTransactions` — filtering by `creatorKey.userId`, `signers.userId`, `observers.userId`, and approver membership. The controller method signature should accept `@GetUser() user: User` and forward it to the service.

### Proof of Concept

1. Register two users (User A and User B) in the organization.
2. As User A, create and execute a transaction. It moves to `EXECUTED` status and appears in history.
3. As User B (who has no relationship to User A's transaction), call:
   ```
   GET /transactions/history
   Authorization: Bearer <User B's JWT>
   ```
4. **Observed:** User A's executed transaction is returned in the response body.
5. **Expected:** Only transactions where User B is creator, signer, observer, or approver should be returned.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L54-57)
```typescript
@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L143-154)
```typescript
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
