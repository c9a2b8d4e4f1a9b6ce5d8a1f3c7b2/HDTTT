All referenced code has been verified against the actual repository. Every specific claim checks out:

- Unbounded `repo.find()` with no `take` at lines 295–299 [1](#0-0) 
- Sequential `await` loop over all N transactions at lines 301–309 [2](#0-1) 
- In-memory slice at lines 311–316 [3](#0-2) 
- `PaginationParams` enforces `size ≤ 100` but only for the final slice [4](#0-3) 
- `keysRequiredToSign` performs `SDKTransaction.fromBytes` + `computeSignatureKey` per transaction [5](#0-4) 
- Controller guarded only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard` [6](#0-5) 
- `UserThrottlerModule` exists but is not imported in `api.module.ts` [7](#0-6) 
- `GLOBAL_MINUTE_LIMIT` defaults to 10 000/min — no hardcoded floor [8](#0-7) 

---

# Audit Report

## Title
Unbounded Full-Table Scan in `getTransactionsToSign` Enables Authenticated DoS

## Summary
`GET /transactions/sign` loads every non-terminal transaction from the database in a single unbounded query, then performs CPU-bound protobuf deserialization and async signature-key computation for each transaction sequentially, before slicing the result in memory. Any verified organization member can trigger this with a single request, causing memory exhaustion, event-loop saturation, and database connection starvation proportional to the total number of active transactions.

## Finding Description

**Unbounded database query — no `take` / `LIMIT`:**

`getTransactionsToSign` in `back-end/apps/api/src/transactions/transactions.service.ts` issues:

```typescript
const transactions = await this.repo.find({
  where: whereForUser,
  relations: ['groupItem'],
  order,
});
``` [1](#0-0) 

No `take` (SQL `LIMIT`) is passed. The `whereForUser` filter only excludes five terminal statuses (`EXECUTED`, `FAILED`, `EXPIRED`, `CANCELED`, `ARCHIVED`), so every `WAITING_FOR_SIGNATURES`, `WAITING_FOR_EXECUTION`, `NEW`, and `SIGN_ONLY` transaction in the entire organization is loaded into the Node.js heap. [9](#0-8) 

By contrast, every other listing method in the same file — `getTransactions`, `getHistoryTransactions`, and `getTransactionsToApprove` — passes `skip: offset, take: limit` to the database. [10](#0-9) 

**O(N) sequential async work per transaction:**

After loading all N transactions, the code iterates over every one sequentially:

```typescript
for (const transaction of transactions) {
  const keysToSign = await this.userKeysToSign(transaction, user);
  ...
}
``` [2](#0-1) 

`userKeysToSign` → `userKeysRequiredToSign` → `keysRequiredToSign` performs, for each transaction:
1. `SDKTransaction.fromBytes(transaction.transactionBytes)` — CPU-bound protobuf deserialization
2. `transactionSignatureService.computeSignatureKey(transaction, showAll)` — async external lookup [5](#0-4) 

**Pagination applied only in-memory after all work is done:**

```typescript
return {
  totalItems: result.length,
  items: result.slice(offset, offset + limit),
  ...
};
``` [3](#0-2) 

The `PaginationParams` decorator enforces `size ≤ 100`, but this only controls the final in-memory slice — it does not limit the database fetch or the per-transaction processing loop. [11](#0-10) 

**Insufficient rate-limiting:**

The global `IpThrottlerGuard` is applied as an `APP_GUARD` and reads limits from environment variables (`GLOBAL_MINUTE_LIMIT`, `GLOBAL_SECOND_LIMIT`). [12](#0-11) 

The reference/default values are 10 000 requests/minute and 1 000 requests/second — far too high to prevent a single-request DoS. [8](#0-7) 

`UserThrottlerModule` and `UserThrottlerGuard` exist but are not imported in `api.module.ts` and are not applied to the transactions controller. [7](#0-6) 

The endpoint is explicitly commented `/* NO LONGER USED BY FRONT-END */` yet remains fully registered and reachable. [13](#0-12) 

## Impact Explanation

A single authenticated request to `GET /transactions/sign?page=1&size=1` causes the server to:
- Execute a full table scan of all active transactions (unbounded PostgreSQL result set loaded into Node.js heap)
- Perform O(N) protobuf deserializations and O(N) async `computeSignatureKey` calls sequentially, blocking the event loop

With thousands of active transactions — realistic in an enterprise multi-sig deployment — this exhausts Node.js heap memory, saturates the event loop, and starves the PostgreSQL connection pool, making the API unavailable to all users. The `size=1` parameter does not reduce server-side work at all; it only controls the final slice of the already-computed result.

## Likelihood Explanation

The endpoint is reachable by any verified organization member with no special privileges. The `/* NO LONGER USED BY FRONT-END */` comment confirms the endpoint is still live. The IP-based rate limiter defaults to 10 000 requests/minute, which does not prevent a single-request DoS. A malicious insider or a compromised member account can trigger this with one HTTP request. The cost to the attacker is negligible; the cost to the server scales linearly with the organization's active transaction count.

## Recommendation

1. **Add database-level pagination to `getTransactionsToSign`**: Pass `skip: offset, take: limit` to `this.repo.find()`, consistent with all other listing methods in the same file.
2. **Remove or disable the endpoint**: The `/* NO LONGER USED BY FRONT-END */` comment indicates this endpoint is dead code. If it is not needed, remove the route entirely.
3. **Apply `UserThrottlerGuard` to the transactions controller** to rate-limit per authenticated user identity, not just per IP.
4. **Set a hardcoded floor on throttler limits** rather than relying solely on operator-configured environment variables.

## Proof of Concept

```
GET /transactions/sign?page=1&size=1
Authorization: Bearer <valid_jwt_for_any_verified_user>
```

With N active (non-terminal) transactions in the database:
- PostgreSQL returns all N rows (no LIMIT applied)
- Node.js deserializes all N transactions via `SDKTransaction.fromBytes`
- Node.js calls `computeSignatureKey` N times sequentially
- Only after all N iterations complete does the server return 1 item

Repeating this request (or issuing it once with a large N) exhausts server resources proportional to N, causing denial of service for all concurrent users.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L266-277)
```typescript
    const whereForUser: FindOptionsWhere<Transaction> = {
      ...where,
      status: Not(
        In([
          TransactionStatus.EXECUTED,
          TransactionStatus.FAILED,
          TransactionStatus.EXPIRED,
          TransactionStatus.CANCELED,
          TransactionStatus.ARCHIVED,
        ]),
      ),
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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L342-350)
```typescript
    const findOptions: FindManyOptions<Transaction> = {
      order,
      relations: {
        creatorKey: true,
        groupItem: true,
      },
      skip: offset,
      take: limit,
    };
```

**File:** back-end/libs/common/src/decorators/pagination-params.decorator.ts (L13-29)
```typescript
export const PaginationParams = createParamDecorator((data, ctx: ExecutionContext): Pagination => {
  const req: Request = ctx.switchToHttp().getRequest();
  const page = parseInt(req.query.page as string);
  const size = parseInt(req.query.size as string);

  if (isNaN(page) || page <= 0 || isNaN(size) || size < 0) {
    throw new BadRequestException(ErrorCodes.IPP);
  }

  if (size > 100) {
    throw new BadRequestException(ErrorCodes.IPP);
  }

  // calculate pagination parameters
  const limit = size;
  const offset = (page - 1) * limit;
  return { page, limit, size, offset };
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L31-36)
```typescript
  const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

  // list of just public keys that have already signed the transaction
  const signerKeys = sdkTransaction._signerPublicKeys;

  const signature = await transactionSignatureService.computeSignatureKey(transaction, showAll);
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L56-56)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L156-157)
```typescript
  /* Get all transactions to be signed by the user */
  /* NO LONGER USED BY FRONT-END */
```

**File:** back-end/apps/api/src/api.module.ts (L68-69)
```typescript
    IpThrottlerModule,
    EmailThrottlerModule,
```

**File:** back-end/apps/api/src/api.module.ts (L73-77)
```typescript
  providers: [
    {
      provide: APP_GUARD,
      useClass: IpThrottlerGuard,
    },
```

**File:** back-end/apps/api/example.env (L28-29)
```text
GLOBAL_MINUTE_LIMIT=10000
GLOBAL_SECOND_LIMIT=1000
```
