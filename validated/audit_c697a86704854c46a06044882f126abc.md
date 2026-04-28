### Title
`TransferTransactionModel.getSigningAccounts()` Ignores Token and NFT Transfer Senders, Causing Transactions to Permanently Fail

### Summary
Both the backend and frontend `TransferTransactionModel` implementations compute required signers by iterating only over `hbarTransfersList`. A Hedera `TransferTransaction` can also carry fungible-token transfers (`tokenTransfersList`) and NFT transfers (`nftTransfersList`), each of which requires the sender account's signature. Because those lists are never consulted, the system never collects the required keys from token-only senders, marks the transaction as ready for execution with an incomplete signature set, and the Hedera network rejects it with `INVALID_SIGNATURE`. The transaction is permanently stuck in `FAILED` state with no recovery path.

### Finding Description

**Root cause — backend model:**

`back-end/libs/common/src/transaction-signature/model/transfer-transaction.model.ts`

```
getSigningAccounts(): Set<string> {
  const accounts = new Set<string>();
  // add all accounts that are senders
  for (const transfer of this.transaction.hbarTransfersList) {   // ← only HBAR
    if (transfer.amount.isNegative() && !transfer.isApproved) {
      accounts.add(transfer.accountId.toString());
    }
  }
  return accounts;   // tokenTransfersList / nftTransfersList never visited
}
``` [1](#0-0) 

The identical omission exists in the frontend model: [2](#0-1) 

**Exploit path:**

1. A user (no special privileges) creates a `TransferTransaction` that moves fungible tokens or NFTs from account A to account B, with the fee paid by account C. Account A is not an HBAR sender.
2. The backend calls `TransactionSignatureService.computeSignatureKey()`, which calls `extractSignatureRequirements()` → `transactionModel.getSigningAccounts()`. [3](#0-2) 

3. `getSigningAccounts()` returns only HBAR senders. Account A is absent. The computed `KeyList` contains only the fee-payer key.
4. `processTransactionStatus()` calls `hasValidSignatureKey()` against the existing signatures. Because only the fee-payer key is required (per the incomplete model), the transaction is promoted to `WAITING_FOR_EXECUTION`. [4](#0-3) 

5. The chain service submits the transaction to the Hedera network. The network enforces its own signature rules: account A's key is required for the token debit. The network returns `INVALID_SIGNATURE`. The transaction is marked `FAILED`.

**Contrast with `AccountAllowanceApproveTransactionModel`**, which correctly handles all three approval types (HBAR, token, NFT): [5](#0-4) 

The same completeness is absent from `TransferTransactionModel`.

**`getReceiverAccounts()` has the same gap** — token/NFT receivers with `receiverSignatureRequired = true` are also never included, compounding the problem for inbound token transfers. [6](#0-5) 

### Impact Explanation
Any `TransferTransaction` that debits tokens or NFTs from an account that is not simultaneously an HBAR sender will be submitted to the Hedera network without the required sender signature. The network rejects it. The transaction is permanently marked `FAILED` and cannot be retried through the normal workflow. For organization users, this means token-transfer workflows are silently broken: the UI reports success at the signing stage, but the on-chain execution always fails. No funds are stolen, but the service is permanently unavailable for a broad, legitimate transaction class.

### Likelihood Explanation
Transferring tokens without a simultaneous HBAR transfer in the same transaction is a standard, everyday Hedera operation. Any authenticated organization user can trigger this by submitting a token-only `TransferTransaction`. No privileged access, no leaked credentials, and no special network position are required. The failure is deterministic and reproducible on every such transaction.

### Recommendation
Extend `getSigningAccounts()` in both `TransferTransactionModel` implementations to iterate `tokenTransfersList` and `nftTransfersList` in addition to `hbarTransfersList`, adding any account with a negative (debit) amount that is not approved:

```typescript
getSigningAccounts(): Set<string> {
  const accounts = super.getSigningAccounts(); // fee payer

  for (const transfer of this.transaction.hbarTransfersList) {
    if (transfer.amount.isNegative() && !transfer.isApproved)
      accounts.add(transfer.accountId.toString());
  }
  for (const transfer of this.transaction.tokenTransfersList) {
    if (transfer.amount < 0 && !transfer.isApproved)
      accounts.add(transfer.accountId.toString());
  }
  for (const transfer of this.transaction.nftTransfersList) {
    if (!transfer.isApproved)
      accounts.add(transfer.senderAccountId.toString());
  }
  return accounts;
}
```

Apply the same fix to `getReceiverAccounts()` so that token/NFT receivers with `receiverSignatureRequired` are also captured.

### Proof of Concept

1. In an organization with two registered users (User A controls account `0.0.100`, User B controls account `0.0.200`):
2. User A creates a `TransferTransaction`:
   - Fee payer: `0.0.200` (User B)
   - Token transfer: debit 10 units of token `0.0.500` from `0.0.100` (User A), credit to `0.0.200`
   - No HBAR transfers
3. User B signs (fee payer key collected correctly). User A is never prompted to sign because `getSigningAccounts()` returns an empty set (no HBAR senders).
4. Backend promotes the transaction to `WAITING_FOR_EXECUTION`.
5. Chain service submits to Hedera. Network returns `INVALID_SIGNATURE` (account `0.0.100` did not sign).
6. Transaction is permanently `FAILED`. No recovery path exists in the current workflow.

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

**File:** front-end/src/renderer/utils/transactionSignatureModels/transfer-transaction.model.ts (L6-16)
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

**File:** back-end/libs/common/src/utils/transaction/index.ts (L118-155)
```typescript
export async function processTransactionStatus(
  transactionRepo: Repository<Transaction>,
  transactionSignatureService: TransactionSignatureService,
  transactions: Transaction[],
): Promise<Map<number, TransactionStatus>> {
  const statusChanges = new Map<number, TransactionStatus>();

  // Group intended updates by [newStatus, oldStatus] so we can bulk update
  // only rows that still have the expected current status
  const updatesByStatus = new Map<string, { newStatus: TransactionStatus, oldStatus: TransactionStatus, ids: number[] }>();

  for (const transaction of transactions) {
    if (!transaction) continue;

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

    if (transaction.status !== newStatus) {
      const key = `${transaction.status}->${newStatus}`;
      if (!updatesByStatus.has(key)) {
        updatesByStatus.set(key, { newStatus, oldStatus: transaction.status, ids: [] });
      }
      updatesByStatus.get(key)!.ids.push(transaction.id);
    }
  }
```

**File:** back-end/libs/common/src/transaction-signature/model/account-allowance-approve-transaction.model.ts (L10-26)
```typescript
  getSigningAccounts(): Set<string> {
    const set = super.getSigningAccounts();

    this.transaction.hbarApprovals.forEach(value => {
      set.add(value.ownerAccountId?.toString() || '');
    });

    this.transaction.tokenApprovals.forEach(value => {
      set.add(value.ownerAccountId?.toString() || '');
    });

    this.transaction.tokenNftApprovals.forEach(value => {
      set.add(value.ownerAccountId?.toString() || '');
    });

    return set;
  }
```
