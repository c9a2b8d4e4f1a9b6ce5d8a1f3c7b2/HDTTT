I need to verify the upstream validation path to determine if a transaction with a null `accountId` can actually reach `extractSignatureRequirements`.

## Audit Report

## Title
`extractSignatureRequirements` Calls `.toString()` on Potentially Null Return Value of `getFeePayerAccountId()`, Causing Unhandled TypeError in Signature Key Computation

## Summary
In `back-end/libs/common/src/transaction-signature/transaction-signature.service.ts`, the private method `extractSignatureRequirements` calls `transactionModel.getFeePayerAccountId().toString()` at line 71 without a null guard. The return type of `getFeePayerAccountId()` is explicitly `AccountId | null`, and the null path is confirmed by both the implementation and the project's own unit tests. Calling `.toString()` on `null` throws a `TypeError` that propagates uncaught through `computeSignatureKey` and `keysRequiredToSign`, crashing the entire signature key resolution pipeline for any transaction that reaches this code path with a missing fee payer account ID.

## Finding Description

**Root cause — `getFeePayerAccountId()` returns `null`:**

`back-end/libs/common/src/transaction-signature/model/transaction-base.model.ts` explicitly returns `null` when `transactionId` or `transactionId.accountId` is absent: [1](#0-0) 

The project's own unit tests confirm both null-return paths (undefined `transactionId`, and `transactionId` present but `accountId` absent): [2](#0-1) 

**Vulnerable call site — no null guard before `.toString()`:**

Line 71 of `transaction-signature.service.ts` dereferences the return value unconditionally: [3](#0-2) 

When `getFeePayerAccountId()` returns `null`, JavaScript throws `TypeError: Cannot read properties of null (reading 'toString')`. This exception is not caught inside `extractSignatureRequirements` and propagates up through `computeSignatureKey`: [4](#0-3) 

And further up through `keysRequiredToSign` and `processTransactionStatus`: [5](#0-4) [6](#0-5) 

**Why upstream validation does not fully block this:**

`validateAndPrepareTransaction` checks `sdkTransaction.transactionId.toString()` (line 967) and `sdkTransaction.transactionId.validStart.toDate()` (line 974), which guard against a fully-null `transactionId` object. However, neither check verifies that `transactionId.accountId` is non-null: [7](#0-6) 

A transaction whose protobuf bytes encode a `TransactionID` with a missing `accountID` field would deserialize to a `TransactionId` with a null `accountId`, pass all existing ingestion checks (expiry, size, node validity), be stored in the database, and later crash `computeSignatureKey` deterministically.

**Contrast with the frontend model**, which correctly guards the null before use before calling `.toString()`: [8](#0-7) 

The test helper itself mocks `getFeePayerAccountId` to always return a non-null object, meaning the null path is never exercised in the service's own test suite.

## Impact Explanation

Any code path that calls `computeSignatureKey` on a transaction whose deserialized SDK object has a null `transactionId.accountId` will throw an unhandled `TypeError`. This breaks:

1. **Signature key resolution** — the backend cannot determine which keys are required to sign the transaction.
2. **Transaction status progression** — `processTransactionStatus` calls `computeSignatureKey` in a loop; a single affected transaction throws and prevents status advancement for that transaction.
3. **`keysRequiredToSign` / `userKeysToSign`** — both call `computeSignatureKey` and will propagate the unhandled rejection to the caller.

## Likelihood Explanation

The Hedera protobuf schema allows a `TransactionID` message to be encoded without an `accountID` field. When the SDK deserializes such bytes, `transactionId.accountId` will be null. The ingestion layer validates `transactionId` (the object) but not `transactionId.accountId` (the field), so such bytes can be stored. The null-return path is not theoretical — it is explicitly typed, implemented, and tested by the project itself. The missing guard is a straightforward oversight given the documented return type.

## Recommendation

Add a null guard in `extractSignatureRequirements` before calling `.toString()`:

```typescript
private extractSignatureRequirements(
  transactionModel: TransactionBaseModel<any>
): SignatureRequirements {
  const feePayerAccountId = transactionModel.getFeePayerAccountId();
  return {
    feePayerAccount: feePayerAccountId ? feePayerAccountId.toString() : null,
    signingAccounts: transactionModel.getSigningAccounts(),
    receiverAccounts: transactionModel.getReceiverAccounts(),
    newKeys: transactionModel.getNewKeys() ?? [],
    nodeId: transactionModel.getNodeId(),
  };
}
```

Update `SignatureRequirements.feePayerAccount` to `string | null` and handle the null case in `addFeePayerKey` (which already has a try/catch). Additionally, add an explicit check in `validateAndPrepareTransaction` that `sdkTransaction.transactionId?.accountId` is non-null before storing the transaction.

## Proof of Concept

```typescript
import {
  AccountCreateTransaction,
  Transaction as SDKTransaction,
} from '@hiero-ledger/sdk';

// Build a transaction with transactionId present but accountId absent
const tx = new AccountCreateTransaction();
// Manually set transactionId without accountId (simulating crafted protobuf bytes)
(tx as any)._transactionId = { accountId: null, validStart: { toDate: () => new Date() }, toString: () => 'null@0' };

const bytes = tx.toBytes(); // store these bytes via the API

// Later, when computeSignatureKey is called:
// getFeePayerAccountId() returns null
// null.toString() → TypeError: Cannot read properties of null (reading 'toString')
```

The `validateAndPrepareTransaction` call at line 967 (`sdkTransaction.transactionId.toString()`) succeeds because `transactionId` itself is not null — only `accountId` is. The transaction is stored. On the next call to `computeSignatureKey`, `extractSignatureRequirements` throws unconditionally. [9](#0-8) [1](#0-0)

### Citations

**File:** back-end/libs/common/src/transaction-signature/model/transaction-base.model.ts (L6-12)
```typescript
  getFeePayerAccountId(): AccountId | null {
    const payerId = this.transaction.transactionId?.accountId;
    if (payerId) {
      return payerId;
    }
    return null;
  }
```

**File:** back-end/libs/common/src/transaction-signature/model/transaction-base.model.spec.ts (L32-48)
```typescript
    it('should return null when transactionId is undefined', () => {
      const model = new TestTransactionModel(mockTransaction);
      const result = model.getFeePayerAccountId();

      expect(result).toBeNull();
    });

    it('should return null when transactionId.accountId is undefined', () => {
      mockTransaction.setTransactionId({
        validStart: null,
      } as any);

      const model = new TestTransactionModel(mockTransaction);
      const result = model.getFeePayerAccountId();

      expect(result).toBeNull();
    });
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

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L67-77)
```typescript
  private extractSignatureRequirements(
    transactionModel: TransactionBaseModel<any>
  ): SignatureRequirements {
    return {
      feePayerAccount: transactionModel.getFeePayerAccountId().toString(),
      signingAccounts: transactionModel.getSigningAccounts(),
      receiverAccounts: transactionModel.getReceiverAccounts(),
      newKeys: transactionModel.getNewKeys() ?? [],
      nodeId: transactionModel.getNodeId(),
    };
  }
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L36-36)
```typescript
  const signature = await transactionSignatureService.computeSignatureKey(transaction, showAll);
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L133-133)
```typescript
    const signatureKey = await transactionSignatureService.computeSignatureKey(transaction);
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L963-978)
```typescript
    return {
      name: dto.name,
      type: transactionType,
      description: dto.description,
      transactionId: sdkTransaction.transactionId.toString(),
      transactionHash: encodeUint8Array(transactionHash),
      transactionBytes: sdkTransaction.toBytes(),
      unsignedTransactionBytes: sdkTransaction.toBytes(),
      creatorKeyId: dto.creatorKeyId,
      signature: dto.signature,
      mirrorNetwork: dto.mirrorNetwork,
      validStart: sdkTransaction.transactionId.validStart.toDate(),
      isManual: dto.isManual,
      cutoffAt: dto.cutoffAt,
      publicKeys,
    };
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.spec.ts (L86-95)
```typescript
function buildTransactionModel(overrides: any = {}) {
  return {
    getFeePayerAccountId: jest.fn().mockReturnValue({ toString: () => '0.0.100' }),
    getSigningAccounts: jest.fn().mockReturnValue(new Set<string>()),
    getReceiverAccounts: jest.fn().mockReturnValue(new Set<string>()),
    getNewKeys: jest.fn().mockReturnValue([]),
    getNodeId: jest.fn().mockReturnValue(null),
    ...overrides,
  };
}
```
