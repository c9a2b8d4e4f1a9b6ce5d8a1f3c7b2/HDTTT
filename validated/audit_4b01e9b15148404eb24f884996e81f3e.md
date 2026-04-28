**Audit Report**

## Title
`TransferTransactionModel.getSigningAccounts()` Only Inspects HBAR Transfers, Missing Token and NFT Transfer Senders

## Summary
Both the back-end and front-end `TransferTransactionModel` implementations compute required signers by iterating exclusively over `hbarTransfersList`. A Hedera `TransferTransaction` can also carry fungible-token transfers and NFT transfers, whose senders are never added to the signing-accounts set. The same omission applies to `getReceiverAccounts()`. The result is an incomplete `KeyList` fed into the organization multi-sig workflow.

## Finding Description

**Affected files and confirmed lines:**

Back-end — `back-end/libs/common/src/transaction-signature/model/transfer-transaction.model.ts`:

`getSigningAccounts()` iterates only `hbarTransfersList`: [1](#0-0) 

`getReceiverAccounts()` also iterates only `hbarTransfersList`: [2](#0-1) 

Front-end — `front-end/src/renderer/utils/transactionSignatureModels/transfer-transaction.model.ts`:

Same omission in both overrides: [3](#0-2) 

The output of `getSigningAccounts()` and `getReceiverAccounts()` is consumed directly by `TransactionSignatureService.computeSignatureKey()` to build the `KeyList` of required signatures: [4](#0-3) 

**Root cause:** The `TransferTransactionModel` was written assuming a `TransferTransaction` only carries HBAR transfers. The Hedera SDK `TransferTransaction` also exposes `tokenTransferList` (fungible HTS) and `nftTransfersList` (NFTs), neither of which is consulted.

**Important scope constraint confirmed by code search:** A `grep` across the entire repository for `tokenTransferList`, `nftTransfersList`, `addTokenTransfer`, and `addNftTransfer` returns **zero matches**. The application's own UI and transaction-creation utilities (`createTransferHbarTransaction`) only ever call `addHbarTransfer` / `addApprovedHbarTransfer`: [5](#0-4) 

The tool does not provide a UI path to create token/NFT transfers. However, the API endpoint accepts raw `transactionBytes` submitted externally, meaning a user can craft and submit a `TransferTransaction` containing token or NFT transfers using the Hedera SDK directly and POST it to the tool.

## Impact Explanation

**Primary impact — transaction failure:** When a `TransferTransaction` containing HTS fungible-token or NFT transfers is submitted via raw bytes, the tool builds an incomplete `KeyList` (missing token-sender keys). The `keysRequiredToSign` utility then derives an incomplete set of required user keys, so the workflow may mark the transaction ready for submission before all required signatures are collected. Hedera will reject it with `INVALID_SIGNATURE`. No funds are lost, but the transaction permanently fails and fees are wasted. [6](#0-5) 

**Secondary impact — approval-threshold bypass:** When the token sender is the same account as the fee payer, the tool collects that account's key once (as fee payer) and never adds it again as a "signing account." If the organization's threshold key structure requires the token sender to be an explicitly-counted approver, the threshold is silently under-counted, potentially allowing the transaction to be marked ready with fewer approvals than policy requires.

## Likelihood Explanation

The application's own UI only creates HBAR-only `TransferTransaction`s, so the vulnerable path is not reachable through normal UI workflows. However, the API explicitly accepts externally-crafted raw transaction bytes, and the Hedera ecosystem heavily uses HTS tokens. Any authenticated organization user who crafts a token-transfer transaction externally and submits it via the API triggers this path. No elevated privilege is required.

## Recommendation

In both `TransferTransactionModel` implementations, extend `getSigningAccounts()` to also iterate `tokenTransferList` (checking `amount < 0 && !isApproved` per entry) and `nftTransfersList` (checking `!isApproved` per entry, as NFT senders are always debit-side). Similarly extend `getReceiverAccounts()` to include token and NFT receivers. Add corresponding unit-test cases covering token and NFT transfer scenarios.

## Proof of Concept

```ts
import { TransferTransaction, TokenId, AccountId, TransactionId } from '@hiero-ledger/sdk';

// Craft a TransferTransaction with an HTS token transfer (not HBAR)
const tx = new TransferTransaction()
  .setTransactionId(TransactionId.withValidStart(AccountId.fromString('0.0.100'), new Date()))
  .addTokenTransfer(TokenId.fromString('0.0.999'), '0.0.200', -100)  // sender: 0.0.200
  .addTokenTransfer(TokenId.fromString('0.0.999'), '0.0.300', 100);  // receiver: 0.0.300

// POST tx.toBytes() (hex-encoded) to the tool's /transactions endpoint
// The tool calls TransferTransactionModel.getSigningAccounts()
// → iterates hbarTransfersList → empty (no HBAR transfers)
// → returns empty Set; account 0.0.200's key is never added to the KeyList
// → workflow proceeds without 0.0.200's signature
// → Hedera rejects with INVALID_SIGNATURE
```

### Citations

**File:** back-end/libs/common/src/transaction-signature/model/transfer-transaction.model.ts (L10-19)
```typescript
  getSigningAccounts(): Set<string> {
    const accounts = new Set<string>();

    // add all accounts that are senders
    for (const transfer of this.transaction.hbarTransfersList) {
      if (transfer.amount.isNegative() && !transfer.isApproved) {
        accounts.add(transfer.accountId.toString());
      }
    }
    return accounts;
```

**File:** back-end/libs/common/src/transaction-signature/model/transfer-transaction.model.ts (L22-31)
```typescript
  getReceiverAccounts(): Set<string> {
    const accounts = new Set<string>();

    for (const transfer of this.transaction.hbarTransfersList) {
      if (!transfer.amount.isNegative()) {
        accounts.add(transfer.accountId.toString());
      }
    }
    return accounts;
  }
```

**File:** front-end/src/renderer/utils/transactionSignatureModels/transfer-transaction.model.ts (L6-28)
```typescript
  override getSigningAccounts(): Set<string> {
    // Get the Fee Payer
    const accounts = super.getSigningAccounts();

    // add all accounts that are senders
    for (const transfer of this.transaction.hbarTransfersList) {
      if (transfer.amount.isNegative() && !transfer.isApproved) {
        accounts.add(transfer.accountId.toString());
      }
    }
    return accounts;
  }

  override getReceiverAccounts(): Set<string> {
    const accounts = new Set<string>();

    for (const transfer of this.transaction.hbarTransfersList) {
      if (!transfer.amount.isNegative()) {
        accounts.add(transfer.accountId.toString());
      }
    }
    return accounts;
  }
```

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L46-53)
```typescript
    const requirements = this.extractSignatureRequirements(transactionModel);

    // Build the key list
    const signatureKey = new KeyList();

    await this.addFeePayerKey(signatureKey, transaction, requirements.feePayerAccount);
    await this.addSigningAccountKeys(signatureKey, transaction, requirements.signingAccounts);
    await this.addReceiverAccountKeys(signatureKey, transaction, requirements.receiverAccounts, showAll);
```

**File:** front-end/src/renderer/utils/sdk/createTransactions.ts (L418-431)
```typescript
export const createTransferHbarTransaction = (
  data: TransactionCommonData & TransferHbarData,
): TransferTransaction => {
  const transaction = new TransferTransaction();
  setTransactionCommonData(transaction, data);

  data.transfers.forEach(transfer => {
    transfer.isApproved
      ? transaction.addApprovedHbarTransfer(transfer.accountId.toString(), transfer.amount)
      : transaction.addHbarTransfer(transfer.accountId.toString(), transfer.amount);
  });

  return transaction;
};
```

**File:** back-end/libs/common/src/utils/transaction/index.ts (L36-43)
```typescript
  const signature = await transactionSignatureService.computeSignatureKey(transaction, showAll);
  // flatten the key list to an array of public keys
  // and filter out any keys that have already signed the transaction
  const flatPublicKeys = flattenKeyList(signature)
    .map(pk => pk.toStringRaw())
    .filter(pk => !signerKeys.has(pk));

  if (flatPublicKeys.length === 0) return [];
```
