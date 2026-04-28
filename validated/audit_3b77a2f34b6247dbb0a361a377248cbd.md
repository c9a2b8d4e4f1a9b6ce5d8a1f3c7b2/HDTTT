### Title
`shouldSignTransaction` Returns Empty Array for Non-Existent Transactions Instead of Throwing an Error

### Summary
The `GET /transactions/sign/:transactionId` endpoint in `TransactionsController` calls `getTransactionById()`, which returns `null` for non-existent transaction IDs, and then passes that `null` directly to `userKeysToSign()` without any null guard. Every other caller of `getTransactionById()` in the same service explicitly checks for `null` and throws `BadRequestException(ErrorCodes.TNF)`. This endpoint silently returns `[]` (empty array) for any non-existent transaction ID, making it impossible for callers to distinguish "transaction does not exist" from "no keys are required to sign this transaction."

### Finding Description

**Root cause — missing null check in controller:**

In `back-end/apps/api/src/transactions/transactions.controller.ts` lines 189–196:

```typescript
@Get('/sign/:transactionId')
async shouldSignTransaction(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
): Promise<number[]> {
  const transaction = await this.transactionsService.getTransactionById(transactionId);
  return this.transactionsService.userKeysToSign(transaction, user);  // null passed here
}
```

`getTransactionById()` explicitly returns `null` for non-existent IDs:

```typescript
// transactions.service.ts line 111
if (!id) return null;
// ...
// line 126
if (!transactions.length) return null;
```

`userKeysToSign()` receives the `null` transaction and delegates to `userKeysRequiredToSign()` with no null guard:

```typescript
// transactions.service.ts lines 875–877
async userKeysToSign(transaction: Transaction, user: User, showAll: boolean = false) {
  return userKeysRequiredToSign(transaction, user, this.transactionSignatureService, this.entityManager, showAll);
}
```

**Contrast with every other caller of `getTransactionById()`**, all of which guard against null:

- `getTransactionForCreator()` (line 882): `if (!transaction) throw new BadRequestException(ErrorCodes.TNF);`
- `attachTransactionSigners()` (line 766): `if (!transaction) throw new BadRequestException(ErrorCodes.TNF);`
- `attachTransactionApprovers()` (line 780): `if (!transaction) throw new BadRequestException(ErrorCodes.TNF);`
- `verifyAccess()` (line 787): `if (!transaction) throw new BadRequestException(ErrorCodes.TNF);`
- `shouldApproveTransaction()` (line 853): `if (!transaction) throw new BadRequestException(ErrorCodes.TNF);`

The `shouldSignTransaction` endpoint is the only path that skips this guard.

### Impact Explanation

Any authenticated user can call `GET /transactions/sign/<arbitrary_id>` with a non-existent transaction ID and receive `[]` instead of a `400 Bad Request`. The caller cannot distinguish between:
- "This transaction does not exist"
- "This transaction exists but you have no keys required to sign it"

This breaks the API contract that is consistently enforced everywhere else in the service. Downstream clients relying on this endpoint to determine signing obligations will silently receive incorrect data for phantom transaction IDs, potentially causing them to skip signing workflows or make incorrect state decisions. If `userKeysRequiredToSign` throws an unhandled exception on a null input, the endpoint instead returns a `500 Internal Server Error`, leaking stack trace information.

### Likelihood Explanation

Any authenticated user (no elevated privileges required) can trigger this by sending a `GET` request to `/transactions/sign/<non-existent-id>`. The controller is protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — all of which are standard user-level authentication. No special role or ownership is required.

### Recommendation

Add the same null guard used by every other caller of `getTransactionById()`:

```typescript
@Get('/sign/:transactionId')
async shouldSignTransaction(
  @GetUser() user: User,
  @Param('transactionId', ParseIntPipe) transactionId: number,
): Promise<number[]> {
  const transaction = await this.transactionsService.getTransactionById(transactionId);
  if (!transaction) {
    throw new BadRequestException(ErrorCodes.TNF);
  }
  return this.transactionsService.userKeysToSign(transaction, user);
}
```

### Proof of Concept

1. Authenticate as any verified user and obtain a valid JWT.
2. Send: `GET /transactions/sign/9999999` (a transaction ID that does not exist).
3. **Expected**: `400 Bad Request` with `ErrorCodes.TNF` (Transaction Not Found), consistent with all other endpoints.
4. **Actual**: `200 OK` with body `[]`, indistinguishable from a valid transaction where no signing keys are required. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L189-196)
```typescript
  @Get('/sign/:transactionId')
  async shouldSignTransaction(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
  ): Promise<number[]> {
    const transaction = await this.transactionsService.getTransactionById(transactionId);
    return this.transactionsService.userKeysToSign(transaction, user);
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L110-127)
```typescript
  async getTransactionById(id: number | TransactionId): Promise<Transaction> {
    if (!id) return null;

    const transactions = await this.repo.find({
      where: typeof id == 'number' ? { id } : { transactionId: id.toString() },
      relations: [
        'creatorKey',
        'creatorKey.user',
        'observers',
        'comments',
        'groupItem',
        'groupItem.group',
      ],
      order: { id: 'DESC' },
    });

    if (!transactions.length) return null;

```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L765-767)
```typescript
  async attachTransactionSigners(transaction: Transaction) {
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L875-877)
```typescript
  async userKeysToSign(transaction: Transaction, user: User, showAll: boolean = false) {
    return userKeysRequiredToSign(transaction, user, this.transactionSignatureService, this.entityManager, showAll);
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L879-891)
```typescript
  async getTransactionForCreator(id: number, user: User) {
    const transaction = await this.getTransactionById(id);

    if (!transaction) {
      throw new BadRequestException(ErrorCodes.TNF);
    }

    if (transaction.creatorKey?.userId !== user?.id) {
      throw new UnauthorizedException('Only the creator has access to this transaction');
    }

    return transaction;
  }
```
