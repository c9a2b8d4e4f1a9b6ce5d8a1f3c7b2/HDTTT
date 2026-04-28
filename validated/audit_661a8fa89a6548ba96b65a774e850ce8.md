Audit Report

## Title
`computeSignatureKey` Skips Node Admin Key for Node ID 0 Due to Falsy Check

## Summary

In `back-end/libs/common/src/transaction-signature/transaction-signature.service.ts`, the guard `if (requirements.nodeId)` at line 55 uses a JavaScript falsy check on a `number | null` field. When a `NodeUpdateTransaction` or `NodeDeleteTransaction` targets consensus node ID `0`, the expression evaluates to `false`, causing `addNodeKeys` to be silently skipped. The admin key for node 0 is never added to the required signature list.

## Finding Description

The root cause is the falsy guard at line 55:

```typescript
if (requirements.nodeId) {
  await this.addNodeKeys(signatureKey, transaction, requirements.nodeId);
}
```

`requirements.nodeId` is typed `number | null` and is populated by `transactionModel.getNodeId()`. [1](#0-0) 

For `NodeUpdateTransactionModel`, `getNodeId()` checks `if (this.transaction.nodeId)` where `this.transaction.nodeId` is a `Long` object. Since JavaScript objects are always truthy (even when their numeric value is `0`), `Long(0)` passes this check and `.toNumber()` correctly returns the number `0`. [2](#0-1) 

For `NodeDeleteTransactionModel`, the same applies — `this.transaction.nodeId` is a `Long` object, so `Long(0)` is truthy and `.toNumber()` returns `0` for non-council payers. [3](#0-2) 

Once `getNodeId()` returns the number `0`, the service-level check `if (requirements.nodeId)` becomes `if (0)`, which is `false` in JavaScript. `addNodeKeys` is never invoked, and the admin key for node 0 is never pushed onto `signatureKey`. [4](#0-3) 

The front-end models correctly handle this case using `if (nodeId == null || Number.isNaN(nodeId))`, which is safe for `0`: [5](#0-4) [6](#0-5) 

The back-end service never adopted this null-safe pattern.

## Impact Explanation

For any `NodeUpdateTransaction` or `NodeDeleteTransaction` targeting node ID `0`:

1. `computeSignatureKey` returns a `KeyList` that omits the node admin key entirely.
2. `keysRequiredToSign` (which calls `computeSignatureKey`) never identifies the admin key as required.
3. The transaction is marked as fully signed and ready to execute without the admin key signature.
4. When submitted to the Hedera network, the transaction is rejected because the mandatory admin key signature is absent.
5. The transaction is recorded as failed/expired despite appearing valid inside the tool, and any associated fees are wasted.
6. Signers and approvers holding the node-0 admin key are never notified, breaking the multi-signature workflow for that node. [7](#0-6) 

## Likelihood Explanation

Hedera consensus node IDs are zero-indexed integers. Node `0` is the first node on every Hedera network (mainnet, testnet, previewnet). Any authenticated user of the tool can draft a `NodeUpdateTransaction` or `NodeDeleteTransaction` and set `nodeId = 0`. No privileged access is required beyond having a valid account. The trigger is deterministic and reproducible — it fires every time node ID `0` is targeted.

## Recommendation

Replace the falsy guard with an explicit null check:

```typescript
// Before (buggy):
if (requirements.nodeId) {

// After (correct):
if (requirements.nodeId !== null) {
```

This mirrors the null-safe pattern already used in the front-end models and correctly handles `0` as a valid node ID. [4](#0-3) 

## Proof of Concept

1. Create a `NodeUpdateTransaction` (or `NodeDeleteTransaction`) with `nodeId = 0` and a non-council fee payer.
2. Serialize it and pass it to `computeSignatureKey`.
3. `NodeUpdateTransactionModel.getNodeId()` returns `0` (correct — `Long(0)` is a truthy object).
4. `requirements.nodeId` is `0`.
5. `if (requirements.nodeId)` → `if (0)` → `false` — `addNodeKeys` is skipped.
6. The returned `KeyList` contains only the fee payer key; the node admin key is absent.
7. The transaction passes internal signature validation but is rejected by the Hedera network upon submission. [8](#0-7)

### Citations

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L17-23)
```typescript
export interface SignatureRequirements {
  feePayerAccount: string;
  signingAccounts: Set<string>;
  receiverAccounts: Set<string>;
  newKeys: Key[];
  nodeId: number | null;
}
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

**File:** back-end/libs/common/src/transaction-signature/model/node-update-transaction.model.ts (L18-23)
```typescript
  getNodeId(): number | null {
    if (this.transaction.nodeId) {
      return this.transaction.nodeId.toNumber();
    }
    return null;
  }
```

**File:** back-end/libs/common/src/transaction-signature/model/node-delete-transaction.model.ts (L11-23)
```typescript
  getNodeId(): number | null {
    // if fee payer is council_accounts,
    // it will already be added to the required list
    // and the admin key is not required
    // otherwise, admin key is required
    const payerId = this.transaction.transactionId?.accountId;
    if (!payerId) return null;
    const isCouncilAccount = payerId.toString() in COUNCIL_ACCOUNTS;
    if (!isCouncilAccount && this.transaction.nodeId) {
      return this.transaction.nodeId.toNumber();
    }
    return null;
  }
```

**File:** front-end/src/renderer/utils/transactionSignatureModels/node-update-transaction.model.ts (L27-29)
```typescript
      if (nodeId == null || Number.isNaN(nodeId)) {
        return null;
      }
```

**File:** front-end/src/renderer/utils/transactionSignatureModels/node-delete-transaction.model.ts (L31-33)
```typescript
      if (nodeId == null || Number.isNaN(nodeId)) {
        return null;
      }
```
