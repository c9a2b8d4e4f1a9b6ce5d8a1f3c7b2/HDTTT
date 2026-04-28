### Title
`TransactionSigner` Allows Duplicate Signer Records and Cannot Be Removed After Creation

### Summary
The `TransactionSigner` entity lacks a unique database constraint on `(transactionId, userKeyId)`, meaning the same user key can be recorded as a signer for the same transaction multiple times. Unlike `TransactionObserver` (which enforces uniqueness) and `TransactionApprover` (which supports soft-delete), `TransactionSigner` has neither protection — directly mirroring the external report's vulnerability class of non-flexible, duplicate-permitting data objects.

### Finding Description

**Root cause — no unique constraint on `TransactionSigner`:**

The `TransactionSigner` entity declares only a plain performance index on `(transactionId, userKeyId)`: [1](#0-0) 

```ts
@Entity()
@Index(['transactionId', 'userKeyId'])   // ← NOT unique
export class TransactionSigner {
```

Compare this with `TransactionObserver`, where the developer explicitly added `{ unique: true }`: [2](#0-1) 

```ts
@Entity()
@Index(['userId', 'transactionId'], { unique: true })  // ← unique
```

The inconsistency proves the developer was aware of the need for uniqueness in some places but omitted it for `TransactionSigner`.

**Root cause — no deletion path for `TransactionSigner`:**

`TransactionApprover` carries a `@DeleteDateColumn()` enabling soft-delete: [3](#0-2) 

`TransactionSigner` has no such column and no `deletedAt` field: [4](#0-3) 

Once a `TransactionSigner` row is inserted it is permanent and cannot be soft-deleted or corrected.

**Exploit path:**

A normal authenticated user who holds signing rights for a transaction can call the signing endpoint repeatedly with the same `userKeyId`. Because there is no `UNIQUE` constraint at the database level and no soft-delete guard, each call inserts a new `TransactionSigner` row for the same `(transactionId, userKeyId)` pair. If the chain service or any downstream logic counts `signers.length` (rather than `DISTINCT userKeyId`) to determine whether a threshold is met, the attacker can artificially inflate the signer count and satisfy multi-signature thresholds with a single key.

### Impact Explanation

- **Threshold bypass**: If signature-count logic counts rows rather than distinct keys, a single compromised or malicious signer can satisfy any N-of-M threshold by submitting N duplicate signing requests.
- **Irremovable corrupt state**: Because there is no delete path, any erroneously or maliciously inserted duplicate signer record is permanent, corrupting the audit trail and potentially the execution eligibility of the transaction.
- **Severity**: High — directly affects the integrity of the multi-signature coordination model, which is the core security primitive of the system.

### Likelihood Explanation

Any authenticated user with signing rights for a transaction can reach the signing endpoint. No privileged access is required. The attacker only needs to replay the same valid signing HTTP request multiple times — a trivial operation with any HTTP client. The missing database constraint means no server-side guard can reliably prevent this without an explicit application-level check (which the entity design does not enforce).

### Recommendation

1. **Add a unique constraint** to `TransactionSigner` at the database level:

```ts
@Entity()
@Index(['transactionId', 'userKeyId'], { unique: true })
export class TransactionSigner {
```

2. **Add soft-delete support** (`@DeleteDateColumn() deletedAt: Date`) to `TransactionSigner`, consistent with `TransactionApprover`, so erroneous or revoked signer records can be corrected.

3. **Audit downstream counting logic** in the chain service to ensure it uses `COUNT(DISTINCT userKeyId)` or equivalent rather than a raw row count.

### Proof of Concept

1. Authenticate as a user who has signing rights for transaction ID `T`.
2. Send `POST /transactions/T/signers` (or equivalent signing endpoint) with the same `userKeyId` twice in succession.
3. Query the `transaction_signer` table: two rows with identical `(transactionId, userKeyId)` will exist.
4. If the threshold check counts `signers.length`, the transaction now appears to have two signatures from one key, potentially satisfying a 2-of-N threshold with a single key. [5](#0-4) [2](#0-1) [3](#0-2)

### Citations

**File:** back-end/libs/common/src/database/entities/transaction-signer.entity.ts (L14-43)
```typescript
@Entity()
@Index(['transactionId', 'userKeyId'])
export class TransactionSigner {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => Transaction, transaction => transaction.signers)
  @JoinColumn({ name: 'transactionId' })
  transaction: Transaction;

  @Column()
  transactionId: number;

  @ManyToOne(() => UserKey, userKey => userKey.signedTransactions)
  @JoinColumn({ name: 'userKeyId' })
  userKey: UserKey;

  @Column()
  userKeyId: number;

  @ManyToOne(() => User, user => user.signerForTransactions)
  @JoinColumn({ name: 'userId' })
  user: User;

  @Column()
  userId: number;

  @CreateDateColumn()
  createdAt: Date;
}
```

**File:** back-end/libs/common/src/database/entities/transaction-observer.entity.ts (L19-22)
```typescript
@Entity()
@Index(['userId', 'transactionId'], { unique: true })
@Index(['transactionId'])
@Index(['userId'])
```

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L75-77)
```typescript
  @DeleteDateColumn()
  deletedAt: Date;
}
```
