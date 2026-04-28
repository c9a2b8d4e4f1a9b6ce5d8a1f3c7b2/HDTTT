### Title
`hasValidSignatureKey` Returns `true` for Empty `KeyList`, Bypassing Signature Validation When `computeSignatureKey` Yields No Keys

### Summary
The `hasValidSignatureKey` function in `back-end/libs/common/src/utils/sdk/key.ts` unconditionally returns `true` when passed an empty `KeyList` (no keys, no threshold). `computeSignatureKey` in `TransactionSignatureService` silently swallows all errors from the account cache and skips adding keys when the cache returns `null`. When both conditions coincide, the signature validation gate in `getValidatedSDKTransaction` passes without checking any actual signatures, allowing an unsigned or under-signed transaction to proceed to Hedera network submission.

### Finding Description

**Root cause — `hasValidSignatureKey` with empty `KeyList`:**

In `back-end/libs/common/src/utils/sdk/key.ts` lines 31–46:

```typescript
export const hasValidSignatureKey = (publicKeys: string[], key: Key) => {
  if (key instanceof KeyList) {
    const keys = key.toArray();          // [] when KeyList is empty
    let currentThreshold = 0;

    keys.forEach(key => {               // loop body never executes
      if (hasValidSignatureKey(publicKeys, key)) {
        currentThreshold++;
      }
    });

    return currentThreshold >= (key.threshold || keys.length);
    //     0                 >= (undefined    || 0          )
    //     0                 >= 0   →  true  ← validation bypassed
  }
  ...
};
``` [1](#0-0) 

When `key` is an empty `KeyList` with no threshold set, `key.threshold` is `undefined`, `keys.length` is `0`, so the expression `key.threshold || keys.length` evaluates to `0`. The check `0 >= 0` is always `true`, meaning the function reports valid signatures without examining a single key.

**Trigger — `computeSignatureKey` silently drops keys on cache failure:**

In `back-end/libs/common/src/transaction-signature/transaction-signature.service.ts`, `addFeePayerKey` (lines 82–99) catches all errors and returns without adding any key to the `signatureKey` list:

```typescript
private async addFeePayerKey(...): Promise<void> {
  try {
    const accountInfo = await this.accountCacheService.getAccountInfoForTransaction(...);
    if (accountInfo?.key) {
      signatureKey.push(accountInfo.key);   // skipped if accountInfo is null
    }
  } catch (error) {
    this.logger.error(`Failed to get fee payer key: ${error.message}`);
    return null;   // silently returns; key never added
  }
}
``` [2](#0-1) 

`addSigningAccountKeys` (lines 104–122) has the same silent-catch pattern for every signing account. [3](#0-2) 

The test suite explicitly documents this behavior — when `getAccountInfoForTransaction` returns `null`, `computeSignatureKey` returns a `KeyList` with zero items:

```typescript
it('handles null accountInfo for fee payer without crashing', async () => {
  accountCacheMock.getAccountInfoForTransaction.mockResolvedValue(null);
  const result = await service.computeSignatureKey(makeTransaction());
  expect((result as unknown as AsMockKeyList).getItems()).toHaveLength(0);
});
``` [4](#0-3) 

**Validation gate — `getValidatedSDKTransaction` passes on empty `KeyList`:**

In `back-end/libs/common/src/execute/execute.service.ts` lines 204–223:

```typescript
const signatureKey = await this.transactionSignatureService.computeSignatureKey(transaction);
if (!hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey))
    throw new Error('Transaction has invalid signature.');
return sdkTransaction;   // reached even with zero signatures
``` [5](#0-4) 

The same `hasValidSignatureKey` call appears in `processTransactionStatus` (`back-end/libs/common/src/utils/transaction/index.ts` lines 134–137), which controls the status transition to `WAITING_FOR_EXECUTION`: [6](#0-5) 

**End-to-end exploit path:**

1. Attacker submits a transaction whose fee-payer account is absent from or not yet indexed by the Mirror Node cache (e.g., a freshly created account, or during a transient Mirror Node outage).
2. `processTransactionStatus` calls `computeSignatureKey` → cache returns `null` → empty `KeyList` returned.
3. `hasValidSignatureKey([], emptyKeyList)` → `true` → transaction is promoted to `WAITING_FOR_EXECUTION` without any signature check.
4. The scheduler picks it up and calls `getValidatedSDKTransaction` → same empty `KeyList` → same bypass → transaction is submitted to Hedera.
5. Hedera rejects it (its own signature validation is independent), but the system has already recorded an incorrect state transition and consumed scheduler resources.

### Impact Explanation
- Transactions are incorrectly promoted to `WAITING_FOR_EXECUTION` and submitted to the Hedera network without the required signatures.
- The system's internal transaction state becomes inconsistent (a transaction that should remain in `WAITING_FOR_SIGNATURES` is marked as submitted/failed).
- Hedera network fees may be incurred for the rejected submission.
- The Hedera network's own signature validation acts as a safety net, preventing actual unauthorized on-chain execution, which limits the severity.

### Likelihood Explanation
- The trigger condition (cache returning `null` or throwing) is reachable without privileged access: a newly created Hedera account may not yet be indexed by the Mirror Node, and any user can create a transaction with such an account as the fee payer.
- The `addFeePayerKey` and `addSigningAccountKeys` methods silently swallow all errors, making the empty-`KeyList` outcome reachable under transient infrastructure conditions (Mirror Node lag, network partition).
- The `hasValidSignatureKey` empty-`KeyList` bypass is deterministic once the empty list is produced — no probabilistic element.

### Recommendation
1. **Fail closed in `hasValidSignatureKey`**: Treat an empty `KeyList` as a validation failure, not a pass. Add an explicit guard:
   ```typescript
   if (key instanceof KeyList) {
     const keys = key.toArray();
     if (keys.length === 0) return false;  // empty key list cannot be satisfied
     ...
   }
   ```
2. **Fail closed in `computeSignatureKey`**: If the fee payer key cannot be resolved (cache miss or error), throw rather than silently omitting the key. The caller (`getValidatedSDKTransaction`) should propagate this as a hard error, preventing the transaction from advancing.
3. **Consistent guard in `processTransactionStatus`**: Apply the same fix so that status promotion to `WAITING_FOR_EXECUTION` is also blocked when the required key set cannot be determined.

### Proof of Concept

**Deterministic reproduction (unit-test level):**

```typescript
import { KeyList } from '@hiero-ledger/sdk';
import { hasValidSignatureKey } from 'back-end/libs/common/src/utils/sdk/key';

const emptyKeyList = new KeyList();   // no keys, no threshold
const result = hasValidSignatureKey([], emptyKeyList);
console.log(result);  // true — validation bypassed
```

**System-level path:**
1. Register a user and create a Hedera transaction whose `transactionId` uses a fee-payer account ID that is not yet present in the Mirror Node cache.
2. Submit the transaction to the API (`POST /transactions`). The creation-time checks do not verify cache presence.
3. Observe that `processTransactionStatus` promotes the transaction to `WAITING_FOR_EXECUTION` (no signatures required because `hasValidSignatureKey` returns `true` on the empty `KeyList`).
4. The scheduler submits the transaction to Hedera; Hedera returns `INVALID_SIGNATURE`; the system marks it `FAILED` — confirming the bypass occurred and the transaction was submitted without valid signatures. [1](#0-0) [7](#0-6) [8](#0-7)

### Citations

**File:** back-end/libs/common/src/utils/sdk/key.ts (L31-46)
```typescript
export const hasValidSignatureKey = (publicKeys: string[], key: Key) => {
  if (key instanceof KeyList) {
    const keys = key.toArray();
    let currentThreshold = 0;

    keys.forEach(key => {
      if (hasValidSignatureKey(publicKeys, key)) {
        currentThreshold++;
      }
    });

    return currentThreshold >= (key.threshold || keys.length);
  } else if (key instanceof PublicKey) {
    return publicKeys.includes(key.toStringRaw());
  } else throw new Error(`Invalid key type`);
};
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L38-62)
```typescript
  async computeSignatureKey(
    transaction: Transaction,
    showAll: boolean = false,
  ): Promise<KeyList> {
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    const transactionModel = TransactionFactory.fromTransaction(sdkTransaction);

    // Extract signature requirements from the transaction model
    const requirements = this.extractSignatureRequirements(transactionModel);

    // Build the key list
    const signatureKey = new KeyList();

    await this.addFeePayerKey(signatureKey, transaction, requirements.feePayerAccount);
    await this.addSigningAccountKeys(signatureKey, transaction, requirements.signingAccounts);
    await this.addReceiverAccountKeys(signatureKey, transaction, requirements.receiverAccounts, showAll);

    if (requirements.nodeId) {
      await this.addNodeKeys(signatureKey, transaction, requirements.nodeId);
    }

    signatureKey.push(...requirements.newKeys);

    return signatureKey;
  }
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L82-99)
```typescript
  private async addFeePayerKey(
    signatureKey: KeyList,
    transaction: Transaction,
    feePayerAccount: string
  ): Promise<void> {
    try {
      const accountInfo = await this.accountCacheService.getAccountInfoForTransaction(
        transaction,
        feePayerAccount,
      );
      if (accountInfo?.key) {
        signatureKey.push(accountInfo.key);
      }
    } catch (error) {
      this.logger.error(`Failed to get fee payer key: ${error.message}`);
      return null;
    }
  }
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L104-122)
```typescript
  private async addSigningAccountKeys(
    signatureKey: KeyList,
    transaction: Transaction,
    signingAccounts: Set<string>
  ): Promise<void> {
    for (const account of signingAccounts) {
      try {
        const accountInfo = await this.accountCacheService.getAccountInfoForTransaction(
          transaction,
          account,
        );
        if (accountInfo?.key) {
          signatureKey.push(accountInfo.key);
        }
      } catch (error) {
        this.logger.error(`Failed to get key for account ${account}: ${error.message}`);
      }
    }
  }
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.spec.ts (L359-370)
```typescript
    it('handles null accountInfo for fee payer without crashing', async () => {
      (SDKTransaction.fromBytes as jest.Mock).mockReturnValue({});
      (TransactionFactory.fromTransaction as jest.Mock).mockReturnValue(makeTransactionModel());
      accountCacheMock.getAccountInfoForTransaction.mockResolvedValue(
        null as unknown as AccountInfoParsed,
      );

      const result = await service.computeSignatureKey(makeTransaction());

      expect(result).toBeDefined();
      expect((result as unknown as AsMockKeyList).getItems()).toHaveLength(0);
    });
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L62-81)
```typescript
  @MurLock(15000, 'transactionGroup.id + "_group"')
  async executeTransactionGroup(transactionGroup: TransactionGroup) {
    this.logger.log('executing transactions');
    transactionGroup.groupItems = transactionGroup.groupItems.filter(
      tx => tx.transaction.status === TransactionStatus.WAITING_FOR_EXECUTION
    );
    const transactions: { sdkTransaction: SDKTransaction; transaction: Transaction }[] =
      [];
    // first we need to validate all the transactions, as they all need to be valid before we can execute any of them
    for (const groupItem of transactionGroup.groupItems) {
      const transaction = groupItem.transaction;
      try {
        const sdkTransaction = await this.getValidatedSDKTransaction(transaction);
        transactions.push({ sdkTransaction, transaction });
      } catch (error) {
        throw new Error(
          `Transaction Group cannot be submitted. Error validating transaction ${transaction.id}: ${error.message}`,
        );
      }
    }
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L216-222)
```typescript
    const signatureKey = await this.transactionSignatureService.computeSignatureKey(transaction);

    /* Checks if the transaction has valid signatureKey */
    if (!hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey))
      throw new Error('Transaction has invalid signature.');

    return sdkTransaction;
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L132-146)
```typescript
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    const signatureKey = await transactionSignatureService.computeSignatureKey(transaction);
    const isAbleToSign = hasValidSignatureKey(
      [...sdkTransaction._signerPublicKeys],
      signatureKey
    );

    let newStatus = TransactionStatus.WAITING_FOR_SIGNATURES;

    if (isAbleToSign) {
      const collatedTx = await smartCollate(transaction, signatureKey);
      if (collatedTx !== null) {
        newStatus = TransactionStatus.WAITING_FOR_EXECUTION;
      }
    }
```
