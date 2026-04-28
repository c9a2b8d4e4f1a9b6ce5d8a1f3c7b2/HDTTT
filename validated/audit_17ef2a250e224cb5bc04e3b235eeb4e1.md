After reviewing all controllers and services, I found a concrete access control analog.

---

### Title
Any Authenticated User Can Read All Organization Historical Transactions via Missing User Scope in `getHistoryTransactions`

### Summary
The `GET /transactions/history` endpoint in `TransactionsController` omits the authenticated user when calling the service layer, unlike every other transaction-listing endpoint. This causes the endpoint to return all executed, failed, and expired transactions across the entire organization to any authenticated user, regardless of whether they created, signed, or observed those transactions.

### Finding Description

In `transactions.controller.ts`, the `getHistoryTransactions` handler does not extract or forward the requesting user to the service:

```typescript
// back-end/apps/api/src/transactions/transactions.controller.ts  lines 142-154
@Get('/history')
@Serialize(withPaginatedResponse(TransactionDto))
getHistoryTransactions(
  @PaginationParams() paginationParams: Pagination,
  @SortingParams(transactionProperties) sort?: Sorting[],
  @FilteringParams({...}) filter?: Filtering[],
): Promise<PaginatedResourceDto<Transaction>> {
  return this.transactionsService.getHistoryTransactions(paginationParams, filter, sort);
  //                                                     ^^^ user is never passed
}
``` [1](#0-0) 

Compare this to every other listing endpoint, which correctly scopes results to the requesting user:

```typescript
// lines 119-132 — getTransactions passes user
getTransactions(
  @GetUser() user: User,
  ...
): Promise<PaginatedResourceDto<Transaction>> {
  return this.transactionsService.getTransactions(user, paginationParams, sort, filter);
}
``` [2](#0-1) 

The same pattern holds for `getTransactionsToSign` and `getTransactionsToApprove`, both of which pass `user` to their respective service calls. [3](#0-2) 

Because `user` is never forwarded, the service has no basis to scope results. The endpoint returns the full organization-wide history of terminal-state transactions (EXECUTED, FAILED, EXPIRED) to any caller who holds a valid JWT.

The controller-level guard chain (`JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard`) only confirms the caller is a verified member — it does not restrict which transactions they can read. [4](#0-3) 

### Impact Explanation

Any verified organization member can enumerate the complete historical transaction record of every other member: transaction types, amounts, recipient Hedera accounts, timestamps, and execution status. This is a cross-user data exposure that breaks the confidentiality boundary between organization members and violates the principle of least privilege. In an organization handling sensitive financial operations on Hedera, this leaks the full operational history to any insider.

### Likelihood Explanation

The attacker precondition is minimal: hold a valid, non-blacklisted JWT for any verified account in the organization. No admin role, no special key, no internal network access is required. The exploit is a single unauthenticated-to-authenticated HTTP GET request. The inconsistency with all sibling endpoints (which all pass `user`) makes this an unambiguous omission rather than an intentional design choice.

### Recommendation

**Short term:** Extract the authenticated user in `getHistoryTransactions` and pass it to the service:

```typescript
getHistoryTransactions(
  @GetUser() user: User,   // add this
  @PaginationParams() paginationParams: Pagination,
  ...
) {
  return this.transactionsService.getHistoryTransactions(user, paginationParams, filter, sort);
}
```

Update `TransactionsService.getHistoryTransactions` to apply the same user-scoping logic used by `getTransactions` (filter to transactions where the user is creator, signer, approver, or observer).

**Long term:** Add an E2E test asserting that `GET /transactions/history` with User A's token does not return transactions created exclusively by User B.

### Proof of Concept

1. Register two users (User A, User B) in the organization; both become verified members.
2. As User B (or admin), create and execute several transactions.
3. As User A, send:
   ```
   GET /transactions/history?page=1&size=99
   Authorization: Bearer <User A JWT>
   ```
4. Observe that User B's EXECUTED/FAILED/EXPIRED transactions appear in the response body — transactions User A has no legitimate relationship to.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L54-57)
```typescript
@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L119-132)
```typescript
  @Get()
  @Serialize(withPaginatedResponse(TransactionDto))
  getTransactions(
    @GetUser() user: User,
    @PaginationParams() paginationParams: Pagination,
    @SortingParams(transactionProperties) sort?: Sorting[],
    @FilteringParams({
      validProperties: transactionProperties,
      dateProperties: transactionDateProperties,
    })
    filter?: Filtering[],
  ): Promise<PaginatedResourceDto<Transaction>> {
    return this.transactionsService.getTransactions(user, paginationParams, sort, filter);
  }
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
