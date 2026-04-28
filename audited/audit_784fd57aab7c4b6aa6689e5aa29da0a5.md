### Title
Any Authenticated User Can Access Any Terminal-Status Transaction Due to Unconditional `verifyAccess` Bypass

### Summary
The `verifyAccess` function in `transactions.service.ts` unconditionally returns `true` for **any** authenticated user when a transaction is in a terminal status (`EXECUTED`, `EXPIRED`, `FAILED`, `CANCELED`, `ARCHIVED`). This breaks the intended access-control model — where only creators, signers, observers, and approvers may view a transaction — for the entire history of completed transactions. Any registered user with no relationship to a transaction can retrieve its full details, including transaction bytes, public keys, and signature data.

### Finding Description
**Root cause — `verifyAccess`, lines 786–809:**

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
    return true;          // ← no user-relationship check whatsoever

  const userKeysToSign = await this.userKeysToSign(transaction, user, true);

  return (
    userKeysToSign.length !== 0 ||
    transaction.creatorKey?.userId === user.id ||
    !!transaction.observers?.some(o => o.userId === user.id) ||
    !!transaction.signers?.some(s => s.userKey?.userId === user.id) ||
    !!transaction.approvers?.some(a => a.userId === user.id)
  );
}
``` [1](#0-0) 

For **active** transactions the function correctly enforces that the caller must be the creator, a signer, an observer, or an approver. For **terminal** transactions the entire check is skipped and `true` is returned unconditionally.

**Exploit path — `getTransactionWithVerifiedAccess`, lines 754–763:**

```typescript
async getTransactionWithVerifiedAccess(transactionId: number | TransactionId, user: User) {
  const transaction = await this.getTransactionById(transactionId);
  await this.attachTransactionApprovers(transaction);

  if (!(await this.verifyAccess(transaction, user))) {
    throw new UnauthorizedException('You don\'t have permission to view this transaction');
  }
  return transaction;
}
``` [2](#0-1) 

This is the single gated entry point used by the controller to serve individual transaction details. Because `verifyAccess` returns `true` for any terminal-status transaction, the `UnauthorizedException` branch is never reached for completed transactions, and the full `Transaction` object — including `transactionBytes`, `publicKeys`, `signature`, and all relational data — is returned to the caller.

**Contrast with `getTransactions` (active transactions), lines 159–173:**

```typescript
const whereForUser = [
  { ...where, signers: { userId: user.id } },
  { ...where, observers: { userId: user.id } },
  { ...where, creatorKey: { userId: user.id } },
];
``` [3](#0-2) 

Active transactions are correctly scoped to the requesting user. The same scoping is absent for terminal transactions.

### Impact Explanation
An attacker who is a legitimate (but unprivileged) organization member can enumerate integer transaction IDs and retrieve the full details of every completed transaction in the system — including raw transaction bytes, extracted public keys (`publicKeys` column), creator key metadata, and all signer/observer relationships. In an enterprise multi-signature workflow this constitutes a cross-tenant data breach: one department's completed treasury or node-update transactions become readable by any other department's staff member.

### Likelihood Explanation
Preconditions: the attacker needs only a valid, verified organization account — the lowest privilege level in the system. No admin rights, no leaked credentials, no cryptographic break. Transaction IDs are sequential integers, making enumeration trivial. The endpoint is a standard REST `GET /transactions/:id` call.

### Recommendation
Remove the early-return shortcut for terminal statuses in `verifyAccess`. Apply the same user-relationship checks regardless of transaction status:

```typescript
async verifyAccess(transaction: Transaction, user: User): Promise<boolean> {
  if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

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

If a deliberate design decision exists to make completed transactions broadly visible, it must be explicitly documented and scoped (e.g., admin-only), not silently granted to every authenticated user.

### Proof of Concept
1. Register two accounts: `alice` (creator of a transaction) and `bob` (no relationship to any transaction).
2. As `alice`, create and execute a transaction; note its integer ID (e.g., `42`).
3. As `bob`, send `GET /transactions/42` with a valid JWT.
4. Observe that the response returns the full `Transaction` object — `transactionBytes`, `publicKeys`, `signature`, signer list, observer list — with HTTP 200, bypassing the `UnauthorizedException` that would fire for an active transaction.
5. Repeat for IDs 1–N to enumerate the entire transaction history of the organization. [4](#0-3)

### Citations

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
