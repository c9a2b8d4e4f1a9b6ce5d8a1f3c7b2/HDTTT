### Title
Any Authenticated User Can Read All Historical Transactions Belonging to Other Users

### Summary
The `GET /transactions/history` endpoint returns all terminal-status transactions (EXECUTED, FAILED, EXPIRED, CANCELED, ARCHIVED) from the entire organization without any per-user access filtering. Additionally, `verifyAccess` unconditionally grants access to any terminal-status transaction for any caller. Any authenticated user — regardless of whether they are a creator, signer, observer, or approver of a transaction — can enumerate and read every historical transaction in the system.

### Finding Description

**Root cause — missing user filter in `getHistoryTransactions`:**

`transactions.controller.ts` exposes the history endpoint without passing the requesting user to the service: [1](#0-0) 

The controller signature accepts no `@GetUser()` parameter and forwards no identity to the service. The service method itself has no `user` parameter at all: [2](#0-1) 

The `findOptions` object contains only status and pagination filters — no `creatorKey.userId`, `signers.userId`, `observers.userId`, or approver constraint. Every terminal-status transaction in the database is returned to whoever calls the endpoint.

**Root cause — `verifyAccess` unconditionally returns `true` for terminal-status transactions:**

The single-transaction `GET /transactions/:id` endpoint calls `getTransactionWithVerifiedAccess`, which calls `verifyAccess`. Inside `verifyAccess`, the very first branch short-circuits all identity checks for any terminal status: [3](#0-2) 

Lines 789–798 return `true` immediately for EXECUTED, EXPIRED, FAILED, CANCELED, and ARCHIVED transactions, before any check of `creatorKey.userId`, `observers`, `signers`, or `approvers`. A user with no relationship to the transaction whatsoever is granted full read access.

**Exploit path:**

1. Attacker registers or is invited as a normal user (no admin, no keys required).
2. Attacker calls `GET /transactions/history` (paginated) — receives all historical transactions in the organization.
3. Attacker calls `GET /transactions/<id>` for any terminal-status transaction ID — receives full transaction detail including `transactionBytes`, `transactionHash`, `transactionId`, `mirrorNetwork`, and group membership.

No elevated privilege is required beyond a valid JWT.

### Impact Explanation

- **Cross-tenant data exposure**: Every historical Hedera transaction — including account IDs, transaction bytes, hashes, and network identifiers — is readable by any authenticated user, including users who were never involved in those transactions.
- **Confidentiality breach**: Organizations use this tool for sensitive multi-sig workflows (account updates, node governance, file operations). Leaking transaction bytes and IDs to unauthorized users violates the confidentiality model the system is designed to enforce.
- **Enumeration**: The paginated history endpoint allows a low-privilege attacker to systematically dump the entire transaction history of the organization.

### Likelihood Explanation

- **Precondition**: A valid JWT — obtainable by any user who has been invited to the organization (or by a malicious insider).
- **No special tooling**: A standard HTTP client (`curl`, Postman) is sufficient.
- **No rate-limit barrier**: The endpoint is protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — all of which a legitimate user already satisfies.
- **Realistic scenario**: A disgruntled or curious employee, or a compromised low-privilege account, can silently exfiltrate the full transaction history.

### Recommendation

1. **`getHistoryTransactions`**: Add a `user` parameter and apply the same per-user `WHERE` clause used in `getTransactions` (creator, signer, observer, approver membership) so only transactions the caller is authorized to see are returned.

2. **`verifyAccess`**: Remove the blanket `return true` for terminal statuses. Terminal-status transactions should still require the caller to be a creator, signer, observer, or approver. The early-return was likely intended as a performance shortcut but eliminates all authorization for the most common query pattern (history). [4](#0-3) 

### Proof of Concept

```
# Step 1 – Obtain a JWT as any verified user
POST /auth/login
{ "email": "attacker@org.com", "password": "..." }
→ { "accessToken": "<JWT>" }

# Step 2 – Dump all historical transactions (no user filter applied)
GET /transactions/history?page=1&limit=100
Authorization: Bearer <JWT>
→ 200 OK — returns ALL terminal-status transactions from ALL users

# Step 3 – Read full detail of any returned transaction
GET /transactions/42          # 42 is a transaction the attacker never touched
Authorization: Bearer <JWT>
→ 200 OK — full TransactionFullDto including transactionBytes, transactionHash,
            transactionId, mirrorNetwork, groupItem, etc.
```

Expected (correct) behavior: both calls should return 401/403 or an empty result set for transactions the attacker has no relationship to. Actual behavior: full data is returned.

### Citations

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L786-808)
```typescript
  async verifyAccess(transaction: Transaction, user: User): Promise<boolean> {
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (
      [
        TransactionStatus.EXECUTED,
        TransactionStatus.EXPIRED,
        TransactionStatus.FAILED,
        TransactionStatus.CANCELED,
        TransactionStatus.ARCHIVED,
      ].includes(transaction.status)
    )
      return true;

    const userKeysToSign = await this.userKeysToSign(transaction, user, true);

    return (
      userKeysToSign.length !== 0 ||
      transaction.creatorKey?.userId === user.id ||
      !!transaction.observers?.some(o => o.userId === user.id) ||
      !!transaction.signers?.some(s => s.userKey?.userId === user.id) ||
      !!transaction.approvers?.some(a => a.userId === user.id)
    );
```
