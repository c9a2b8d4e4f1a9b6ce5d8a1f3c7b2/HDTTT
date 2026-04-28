### Title
`computeSignatureKey` Skips Node Admin Key for Node ID 0 Due to Falsy Check

### Summary
In `transaction-signature.service.ts`, the guard `if (requirements.nodeId)` uses a JavaScript truthiness check on a `number | null` value. When `nodeId` is `0` (a valid Hedera consensus node ID), the condition evaluates to `false`, causing `addNodeKeys` to be silently skipped. As a result, the node admin key is never added to the required signature set for any transaction targeting node 0.

### Finding Description
The `computeSignatureKey` method in `TransactionSignatureService` extracts a `nodeId: number | null` from the transaction model and then conditionally calls `addNodeKeys`:

```typescript
if (requirements.nodeId) {
  await this.addNodeKeys(signatureKey, transaction, requirements.nodeId);
}
``` [1](#0-0) 

The `SignatureRequirements` interface explicitly types `nodeId` as `number | null`:

```typescript
nodeId: number | null;
``` [2](#0-1) 

In JavaScript, `0` is falsy. When `getNodeId()` returns `0` (Hedera consensus node IDs are zero-indexed), the condition `if (requirements.nodeId)` evaluates to `false`, and `addNodeKeys` is never invoked. The correct guard is `if (requirements.nodeId !== null)`.

The `addNodeKeys` method handles both `NodeDeleteTransaction` and `NodeUpdateTransaction`, adding the node's admin key (and potentially a threshold key for account-ID-only changes) to the `signatureKey` list: [3](#0-2) 

When `nodeId === 0`, none of this logic executes, so the admin key for node 0 is absent from the computed `KeyList`.

### Impact Explanation
The computed `signatureKey` is consumed in two critical paths:

1. **Execution gate** — `ExecuteService.getValidatedSDKTransaction` calls `computeSignatureKey` and then checks `hasValidSignatureKey`. With the admin key missing, the check passes even when the node 0 admin key has not signed, allowing the transaction to be submitted to the network without the required authorization. [4](#0-3) 

2. **Signing workflow** — `userKeysRequiredToSign` uses the same service to determine which user keys must sign. Users holding the node 0 admin key are never prompted, so the transaction can reach `WAITING_FOR_EXECUTION` status without that key's signature.

The net effect is that a `NodeUpdateTransaction` or `NodeDeleteTransaction` targeting node 0 can be created, signed only by the fee payer, and executed — bypassing the node admin key requirement entirely.

### Likelihood Explanation
Hedera consensus node IDs are zero-indexed; node 0 exists on every network (mainnet, testnet, previewnet). Any operator who creates a `NodeUpdateTransaction` or `NodeDeleteTransaction` for node 0 through this tool will trigger the bug. No special attacker capability is required — a normal authenticated user with creator-key access can reach this path.

### Recommendation
Replace the falsy guard with an explicit `null` check:

```typescript
// Before (buggy)
if (requirements.nodeId) {

// After (correct)
if (requirements.nodeId !== null) {
``` [1](#0-0) 

Add a unit test that constructs a `NodeUpdateTransaction` or `NodeDeleteTransaction` with `nodeId = 0` and asserts that the resulting `KeyList` contains the node admin key.

### Proof of Concept

1. Authenticate as a user with a registered creator key.
2. Create a `NodeDeleteTransaction` (or `NodeUpdateTransaction`) targeting node ID `0`.
3. Sign only with the fee-payer key (do **not** provide the node 0 admin key signature).
4. Submit via the API. The backend calls `computeSignatureKey`, which returns a `KeyList` that omits the node 0 admin key because `if (0)` is `false`.
5. `hasValidSignatureKey` passes, and the transaction proceeds to execution without the required admin key — demonstrating that the authorization check for node 0 is silently bypassed.

### Citations

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L22-23)
```typescript
  nodeId: number | null;
}
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L55-57)
```typescript
    if (requirements.nodeId) {
      await this.addNodeKeys(signatureKey, transaction, requirements.nodeId);
    }
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L174-212)
```typescript
  private async addNodeKeys(
    signatureKey: KeyList,
    transaction: Transaction,
    nodeId: number,
  ): Promise<void> {
    try {
      const nodeInfo = await this.nodeCacheService.getNodeInfoForTransaction(transaction, nodeId);

      if (!nodeInfo) {
        this.logger.warn(`No node info found for node ${nodeId}`);
        return;
      }

      if (!nodeInfo.admin_key) {
        this.logger.warn(`No node admin key found for node ${nodeId}`);
        return;
      }

      const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

      if (sdkTransaction instanceof NodeDeleteTransaction) {
        // if fee payer is council_accounts,
        // it will already be added to the required list
        // and the admin key is not required (as the fee payer will already approve it)
        // otherwise, admin key is required
        const payerId = sdkTransaction.transactionId?.accountId;
        const isCouncilAccount = payerId && payerId.toString() in COUNCIL_ACCOUNTS;

        if (!isCouncilAccount) {
          signatureKey.push(nodeInfo.admin_key);
        }
        return;
      } else if (!(sdkTransaction instanceof NodeUpdateTransaction)) {
        // Non-update transactions only require the admin key
        signatureKey.push(nodeInfo.admin_key);
        return;
      }

      const nodeUpdateTx = sdkTransaction as NodeUpdateTransaction;
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L216-220)
```typescript
    const signatureKey = await this.transactionSignatureService.computeSignatureKey(transaction);

    /* Checks if the transaction has valid signatureKey */
    if (!hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey))
      throw new Error('Transaction has invalid signature.');
```
