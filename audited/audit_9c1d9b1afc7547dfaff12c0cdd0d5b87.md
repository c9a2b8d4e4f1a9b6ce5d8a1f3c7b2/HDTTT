### Title
`TransferTransactionModel` silently omits token and NFT transfer participants from required-signer computation, breaking multi-signature coordination for all non-HBAR transfers

### Summary
Both the back-end and front-end `TransferTransactionModel` implementations only iterate `hbarTransfersList` when computing `getSigningAccounts()` and `getReceiverAccounts()`. A Hedera `TransferTransaction` can also carry fungible-token transfers (`tokenTransfersList`) and NFT transfers (`nftTransfersList`), but neither list is ever consulted. The result is that the entire signature-coordination pipeline silently produces an incomplete required-signer set for any token or NFT transfer, directly analogous to the external report's "missing receiver" pattern.

### Finding Description

**Root cause — back-end model**

`getSigningAccounts()` and `getReceiverAccounts()` both loop exclusively over `this.transaction.hbarTransfersList`: [1](#0-0) 

`tokenTransfersList` and `nftTransfersList` are never read. For a token-only `TransferTransaction`, both methods return empty sets.

**Root cause — front-end model**

The front-end copy has the identical gap: [2](#0-1) 

**Exploit path through the back-end pipeline**

`TransactionSignatureService.computeSignatureKey()` calls `TransactionFactory.fromTransaction()`, which instantiates `TransferTransactionModel`, then calls `extractSignatureRequirements()` to obtain `signingAccounts` and `receiverAccounts`: [3](#0-2) 

When the transaction contains only token transfers, both sets are empty. `addSigningAccountKeys()` and `addReceiverAccountKeys()` iterate over empty sets, so the returned `KeyList` contains only the fee-payer key — token senders and token receivers with `receiverSignatureRequired` are never included.

**Factory registration confirms the model is the sole handler**

`TransferTransaction` maps to exactly one model in both factories, with no fallback: [4](#0-3) [5](#0-4) 

### Impact Explanation

**Concrete impact — organization multi-sig workflow**

In organization mode the system uses `computeSignatureKey` to decide which users must sign before a transaction can be executed. For any `TransferTransaction` that moves fungible tokens or NFTs:

- Token-sender accounts are never added to `signingAccounts` → they are never routed the transaction for signing.
- Token-receiver accounts with `receiverSignatureRequired = true` are never added to `receiverAccounts` → their mandatory counter-signature is never collected.
- The transaction appears "fully signed" to the tool but is submitted to Hedera without required signatures → Hedera rejects it with `INVALID_SIGNATURE`.

**Concrete impact — front-end "to-sign" list**

The front-end uses the same model via its own `TransactionFactory` to compute which keys a local user must supply. Token-transfer participants are invisible to this computation, so users are never prompted to sign transactions where they are token senders. [6](#0-5) 

### Likelihood Explanation

`TransferTransaction` is the most common transaction type in the codebase (dedicated UI component, dedicated test suite, dedicated automation helpers). Token transfers are a primary Hedera use case. Any organization using this tool to coordinate token or NFT transfers will trigger this path on every such transaction. No privileged access is required — a normal user creating a token transfer is sufficient.

### Recommendation

In both `TransferTransactionModel` implementations, extend `getSigningAccounts()` to iterate `tokenTransfersList` (accounts with negative amounts and `isApproved === false`) and `nftTransfersList` (sender fields), and extend `getReceiverAccounts()` to include token/NFT recipient accounts. Apply the fix symmetrically to both:

- `back-end/libs/common/src/transaction-signature/model/transfer-transaction.model.ts`
- `front-end/src/renderer/utils/transactionSignatureModels/transfer-transaction.model.ts`

### Proof of Concept

1. In organization mode, create a `TransferTransaction` that transfers a fungible HTS token from account A to account B with no HBAR component. Account B has `receiverSignatureRequired = true`.
2. Submit the transaction draft via `POST /transactions`.
3. Call `GET /transactions?toSign=true` as the user controlling account A — the transaction does **not** appear (A is not in `signingAccounts`).
4. Call `GET /transactions?toSign=true` as the user controlling account B — the transaction does **not** appear (B is not in `receiverAccounts`).
5. The system marks the transaction as ready and executes it with only the fee-payer signature.
6. Hedera returns `INVALID_SIGNATURE` because A's and B's signatures are absent.
7. Repeat with an NFT transfer — identical outcome. [7](#0-6) [8](#0-7)

### Citations

**File:** back-end/libs/common/src/transaction-signature/model/transfer-transaction.model.ts (L10-31)
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
  }

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

**File:** back-end/libs/common/src/transaction-signature/transaction-signature.service.ts (L127-147)
```typescript
  private async addReceiverAccountKeys(
    signatureKey: KeyList,
    transaction: Transaction,
    receiverAccounts: Set<string>,
    showAll: boolean,
  ): Promise<void> {
    for (const account of receiverAccounts) {
      try {
        const accountInfo = await this.accountCacheService.getAccountInfoForTransaction(
          transaction,
          account,
          true,
        );
        if (accountInfo?.key && (showAll || accountInfo.receiverSignatureRequired)) {
          signatureKey.push(accountInfo.key);
        }
      } catch (error) {
        this.logger.error(`Failed to get receiver key for account ${account}: ${error.message}`);
      }
    }
  }
```

**File:** back-end/libs/common/src/transaction-signature/model/transaction-factory.ts (L21-36)
```typescript
const TRANSACTION_MODEL_MAP = new Map<string, TxModelCtor>([
  ['AccountAllowanceApproveTransaction', AccountAllowanceApproveTransactionModel],
  ['AccountCreateTransaction', AccountCreateTransactionModel],
  ['AccountDeleteTransaction', AccountDeleteTransactionModel],
  ['AccountUpdateTransaction', AccountUpdateTransactionModel],
  ['FileAppendTransaction', FileAppendTransactionModel],
  ['FileCreateTransaction', FileCreateTransactionModel],
  ['FileUpdateTransaction', FileUpdateTransactionModel],
  ['FreezeTransaction', FreezeTransactionModel],
  ['NodeCreateTransaction', NodeCreateTransactionModel],
  ['NodeDeleteTransaction', NodeDeleteTransactionModel],
  ['NodeUpdateTransaction', NodeUpdateTransactionModel],
  ['SystemDeleteTransaction', SystemDeleteTransactionModel],
  ['SystemUndeleteTransaction', SystemUndeleteTransactionModel],
  ['TransferTransaction', TransferTransactionModel],
]);
```

**File:** front-end/src/renderer/utils/transactionSignatureModels/transaction-factory.ts (L26-41)
```typescript
    const transactionModelMap = {
      TransferTransaction: TransferTransactionModel,
      AccountCreateTransaction: AccountCreateTransactionModel,
      AccountUpdateTransaction: AccountUpdateTransactionModel,
      SystemDeleteTransaction: SystemDeleteTransactionModel,
      SystemUndeleteTransaction: SystemUndeleteTransactionModel,
      FreezeTransaction: FreezeTransactionModel,
      FileUpdateTransaction: FileUpdateTransactionModel,
      FileAppendTransaction: FileAppendTransactionModel,
      AccountDeleteTransaction: AccountDeleteTransactionModel,
      AccountAllowanceApproveTransaction: AccountAllowanceApproveTransactionModel,
      FileCreateTransaction: FileCreateTransactionModel,
      NodeCreateTransaction: NodeCreateTransactionModel,
      NodeUpdateTransaction: NodeUpdateTransactionModel,
      NodeDeleteTransaction: NodeDeleteTransactionModel,
    };
```
