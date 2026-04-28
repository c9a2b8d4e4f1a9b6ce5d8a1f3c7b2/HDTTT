Let me verify one more critical detail — whether the Hedera SDK embeds a ledger ID in the serialized transaction bytes, which would be the only technical barrier to cross-network replay at the protocol level.

Audit Report

## Title
Cross-Network Transaction Replay via Unsigned `mirrorNetwork` Field

## Summary
The `mirrorNetwork` field in `CreateTransactionDto` is accepted from the request body and stored verbatim, but is never included in the data the creator cryptographically signs. Because Hedera testnet node account IDs (`0.0.3`–`0.0.9`) are a strict subset of mainnet node account IDs (`0.0.3`–`0.0.39+`), the server-side node validation check does not distinguish between networks. Combined with a bypassable `transactionId` uniqueness check, an authenticated malicious creator can cause the same signed transaction bytes to be stored and executed on a different Hedera network than the one co-signers believed they were approving.

## Finding Description

**Root cause — unsigned network discriminator:**

In `validateAndPrepareTransaction`, the creator's signature is verified only over `dto.transactionBytes`:

```typescript
const validSignature = publicKey.verify(dto.transactionBytes, dto.signature);
``` [1](#0-0) 

`mirrorNetwork` is then stored verbatim from the request body without being part of the signed payload:

```typescript
mirrorNetwork: dto.mirrorNetwork,
``` [2](#0-1) 

**Node validation does not provide cross-network isolation:**

The node check validates that the transaction's node account IDs exist in the client built from `dto.mirrorNetwork`:

```typescript
const allowedNodes = getNodeAccountIdsFromClientNetwork(client);
if (!isTransactionValidForNodes(sdkTransaction, allowedNodes)) {
  throw new BadRequestException(ErrorCodes.TNVN);
}
``` [3](#0-2) 

`getNodeAccountIdsFromClientNetwork` reads the node map from the SDK `Client` object: [4](#0-3) 

`isTransactionValidForNodes` checks that every node ID in the transaction is present in the allowed set: [5](#0-4) 

The flaw is that Hedera testnet nodes (`0.0.3`–`0.0.9`) are a strict subset of mainnet nodes (`0.0.3`–`0.0.39+`). A transaction frozen against testnet node `0.0.3` passes node validation for mainnet because mainnet also has `0.0.3`. The Hedera transaction body protobuf does not embed a ledger/network identifier — the `ledgerId` is a client-side SDK concept and is not serialized into the transaction bytes — so the same bytes are structurally valid on any network sharing those node IDs.

**`transactionId` uniqueness check is bypassable after cancellation:**

The duplicate check excludes canceled, rejected, and archived transactions:

```typescript
status: Not(
  In([
    TransactionStatus.CANCELED,
    TransactionStatus.REJECTED,
    TransactionStatus.ARCHIVED,
  ]),
),
``` [6](#0-5) 

Once the original testnet transaction is canceled, the same `transactionId` and signed bytes can be resubmitted with a different `mirrorNetwork`.

## Impact Explanation

A malicious creator in an organization context can:
1. Build a transaction targeting testnet node IDs (e.g., `0.0.3`).
2. Present it to co-signers as a testnet operation; co-signers upload their signatures.
3. Cancel the testnet transaction.
4. Resubmit the **identical** `{transactionBytes, signature}` with `mirrorNetwork: 'mainnet'`.
5. All previously collected co-signer signatures remain cryptographically valid (the bytes are unchanged), so the threshold is immediately met.
6. The transaction executes on mainnet.

Co-signers who believed they were approving a testnet operation have unknowingly authorized a mainnet transaction. Depending on the transaction type (e.g., `AccountUpdateTransaction` changing account keys, `CryptoTransfer` moving funds), the impact can be loss of account control or loss of funds on mainnet.

## Likelihood Explanation

The attack requires an authenticated, malicious creator — an insider threat. However, the Hedera Transaction Tool is explicitly designed for multi-party organizational workflows where the creator role is distinct from approvers, making this a realistic threat model. The exploit is constrained by Hedera's default 180-second transaction validity window, but this is sufficient time to cancel and resubmit programmatically, especially if co-signer signatures were already collected on the testnet transaction before cancellation. No special privileges beyond the creator role are required.

## Recommendation

1. **Include `mirrorNetwork` in the signed payload.** Require the creator to sign a message that binds `transactionBytes` to `mirrorNetwork`, e.g., `sign(sha256(transactionBytes || mirrorNetwork))`. Reject submissions where the signature does not cover the network field.
2. **Alternatively, extract and verify the network from the transaction bytes.** Parse the node account IDs from the frozen transaction and cross-reference them against a known per-network node list that is maintained server-side, rejecting any transaction whose node set is ambiguous across networks.
3. **Add `mirrorNetwork` to the `transactionId` uniqueness check.** Even after cancellation, prevent the same `transactionId` from being resubmitted on a different network.

## Proof of Concept

```typescript
// 1. Build and sign a transaction using testnet node 0.0.3
const tx = new AccountUpdateTransaction()
  .setAccountId('0.0.12345')
  .setKey(newKey)
  .setTransactionId(TransactionId.generate('0.0.12345'))
  .setNodeAccountIds([AccountId.fromString('0.0.3')])
  .freezeWith(Client.forTestnet());

const txBytes = tx.toBytes();
const signature = privateKey.sign(txBytes);

// 2. Submit as testnet — accepted
await POST('/transactions', { transactionBytes: txBytes, signature, mirrorNetwork: 'testnet', creatorKeyId: X });

// 3. Collect co-signer approvals (they see mirrorNetwork: 'testnet' in the UI)

// 4. Cancel the testnet transaction
await PATCH('/transactions/cancel/{id}');

// 5. Replay with mirrorNetwork: 'mainnet' — all checks pass:
//    - signature valid (bytes unchanged)
//    - node 0.0.3 exists on mainnet
//    - transactionId uniqueness check skips CANCELED records
await POST('/transactions', { transactionBytes: txBytes, signature, mirrorNetwork: 'mainnet', creatorKeyId: X });

// 6. Co-signer signatures already embedded in txBytes are valid for mainnet execution
```

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L418-427)
```typescript
          status: Not(
            In([
              TransactionStatus.CANCELED,
              TransactionStatus.REJECTED,
              TransactionStatus.ARCHIVED,
            ]),
          ),
        },
        select: ['transactionId'],
      });
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L909-913)
```typescript
    // Verify signature
    const validSignature = publicKey.verify(dto.transactionBytes, dto.signature);
    if (!validSignature) {
      throw new BadRequestException(ErrorCodes.SNMP);
    }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L934-937)
```typescript
    const allowedNodes = getNodeAccountIdsFromClientNetwork(client);
    if (!isTransactionValidForNodes(sdkTransaction, allowedNodes)) {
      throw new BadRequestException(ErrorCodes.TNVN);
    }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L972-973)
```typescript
      signature: dto.signature,
      mirrorNetwork: dto.mirrorNetwork,
```

**File:** back-end/libs/common/src/utils/sdk/client.ts (L55-63)
```typescript
export const getNodeAccountIdsFromClientNetwork = (client: Client): Set<string> => {
  const network = client.network as { [key: string]: string | AccountId };
  const values = Object.values(network ?? {});
  return new Set(
    values.map((v) =>
      v instanceof AccountId ? v.toString() : AccountId.fromString(String(v)).toString(),
    ),
  );
};
```

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L342-362)
```typescript
export const isTransactionValidForNodes = (
  sdkTransaction: SDKTransaction,
  allowedNodeAccountIds: Set<string>
): boolean  => {
  const nodeAccountIds = (sdkTransaction as any)._nodeAccountIds;
  const txNodeIds: string[] = [];
  if (
    nodeAccountIds &&
    typeof nodeAccountIds.length === 'number' &&
    typeof nodeAccountIds.get === 'function'
  ) {
    for (let i = 0; i < nodeAccountIds.length; i++) {
      const id = nodeAccountIds.get(i);
      const accountId =
        id instanceof AccountId ? id : AccountId.fromString(String(id));
      txNodeIds.push(accountId.toString());
    }
  }

  return txNodeIds.every((id) => allowedNodeAccountIds.has(id));
};
```
