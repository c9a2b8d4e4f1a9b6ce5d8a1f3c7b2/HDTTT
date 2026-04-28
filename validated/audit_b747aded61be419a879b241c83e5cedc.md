All code references check out. The vulnerability is real and verifiable. Here is the audit report:

---

Audit Report

## Title
`getSignaturesByTransactionId` Endpoint Exposes Signer Data Without Authorization

## Summary
The `GET /transactions/:transactionId/signers` endpoint in `SignersController` authenticates the caller but performs no authorization check to verify the caller has any relationship to the queried transaction. Any verified user can retrieve all `TransactionSigner` records — including soft-deleted ones — with eagerly loaded `userKey` data (public keys, key IDs) for every transaction in the system.

## Finding Description

**Root cause:**

The `getSignaturesByTransactionId` handler in `signers.controller.ts` accepts no `User` context and passes the caller-supplied `transactionId` directly to the service with no ownership or membership check: [1](#0-0) 

The service method performs no access check — it queries all signers for the given transaction ID, eagerly loads the `userKey` relation, and returns soft-deleted records via `withDeleted`: [2](#0-1) 

The controller applies only authentication guards (`JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard`), not any authorization guard: [3](#0-2) 

**Contrast with correct patterns in the same codebase:**

`getVerifiedApproversByTransactionId` in `approvers.service.ts` explicitly checks creator, observer, signer, and approver membership before returning approver data, throwing `UnauthorizedException` if the user has no relationship to the transaction: [4](#0-3) 

`verifyAccess` in `transactions.service.ts` enforces the same membership check for other sensitive endpoints: [5](#0-4) 

`importSignatures` in `transactions.service.ts` calls `verifyAccess` before processing any signature data: [6](#0-5) 

The `getSignaturesByTransactionId` endpoint is the only sensitive transaction data endpoint that skips this check entirely.

## Impact Explanation

A malicious authenticated user can enumerate the full signing history of every transaction in the organization — including transactions they have no legitimate access to. The response includes `userKey` data (public keys and key IDs) tied to specific users and transactions. The `withDeleted: true` flag means even soft-deleted signer records are returned, exposing historical signing activity. This breaks the cross-tenant isolation model: a regular employee can learn which users signed which transactions, reconstruct signing timelines, and correlate public keys to user identities across the entire transaction history.

## Likelihood Explanation

The attack requires only a valid, verified account — the lowest privilege level in the system. Transaction IDs are sequential integers, making enumeration trivial. No special tooling, timing, or cryptographic capability is needed. The endpoint is a standard REST GET request.

## Recommendation

Add authorization to `getSignaturesByTransactionId` consistent with the pattern used by `getVerifiedApproversByTransactionId`. Specifically:

1. Inject `@GetUser() user: User` into the `getSignaturesByTransactionId` handler.
2. Before returning results, verify the requesting user is a creator, observer, signer, or approver of the transaction (reusing `verifyAccess` or an equivalent check).
3. For terminal-status transactions (`EXECUTED`, `EXPIRED`, `FAILED`, `CANCELED`, `ARCHIVED`), the existing codebase pattern allows open access — decide whether that policy should apply here as well and document it explicitly.

## Proof of Concept

```
# 1. Register and verify a standard (non-admin) account.
# 2. Obtain a JWT via login.
# 3. Enumerate signers for arbitrary transactions:

for i in $(seq 1 100); do
  curl -s -H "Authorization: Bearer <JWT>" \
    https://<host>/transactions/$i/signers
done

# Each response returns TransactionSigner records with userKey (publicKey, id)
# for transactions the attacker has no legitimate relationship to.
# withDeleted: true means soft-deleted historical signer records are also returned.
```

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L37-41)
```typescript
@ApiTags('Transaction Signers')
@Controller('transactions/:transactionId?/signers')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class SignersController {
  constructor(private signaturesService: SignersService) {}
```

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L52-58)
```typescript
  @Get()
  @HttpCode(200)
  getSignaturesByTransactionId(
    @Param('transactionId', ParseIntPipe) transactionId: number,
  ): Promise<TransactionSigner[]> {
    return this.signaturesService.getSignaturesByTransactionId(transactionId, true);
  }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L78-96)
```typescript
  getSignaturesByTransactionId(
    transactionId: number,
    withDeleted: boolean = false,
  ): Promise<TransactionSigner[]> {
    if (!transactionId) {
      return null;
    }
    return this.repo.find({
      where: {
        transaction: {
          id: transactionId,
        },
      },
      relations: {
        userKey: true,
      },
      withDeleted,
    });
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L111-152)
```typescript
  async getVerifiedApproversByTransactionId(
    transactionId: number,
    user: User,
  ): Promise<TransactionApprover[]> {
    const transaction = await this.dataSource.manager.findOne(Transaction, {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user', 'observers', 'signers', 'signers.userKey'],
    });

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    const approvers = await this.getApproversByTransactionId(transactionId);

    const userKeysToSign = await userKeysRequiredToSign(
      transaction,
      user,
      this.transactionSignatureService,
      this.dataSource.manager,
    );

    if (
      [
        TransactionStatus.EXECUTED,
        TransactionStatus.EXPIRED,
        TransactionStatus.FAILED,
        TransactionStatus.CANCELED,
        TransactionStatus.ARCHIVED,
      ].includes(transaction.status)
    )
      return approvers;

    if (
      userKeysToSign.length === 0 &&
      transaction.creatorKey?.userId !== user.id &&
      !transaction.observers.some(o => o.userId === user.id) &&
      !transaction.signers.some(s => s.userKey?.userId === user.id) &&
      !approvers.some(a => a.userId === user.id)
    )
      throw new UnauthorizedException("You don't have permission to view this transaction");

    return approvers;
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L529-532)
```typescript
        /* Verify that the transaction exists and access is verified */
        if (!(await this.verifyAccess(transaction, user))) {
          throw new BadRequestException(ErrorCodes.TNF);
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
