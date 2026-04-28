The code evidence is conclusive. All referenced files and line numbers check out exactly as described.

---

Audit Report

## Title
`TransferTransactionModel` silently omits token and NFT transfer participants from required-signer computation, breaking multi-signature coordination for all non-HBAR transfers

## Summary
Both the back-end and front-end `TransferTransactionModel` implementations compute `getSigningAccounts()` and `getReceiverAccounts()` by iterating only `hbarTransfersList`. A Hedera `TransferTransaction` also carries fungible-token transfers (`tokenTransfersList`) and NFT transfers (`nftTransfersList`), but neither list is consulted. The entire signature-coordination pipeline therefore silently produces an incomplete required-signer set for any token or NFT transfer.

## Finding Description

**Back-end root cause**

`getSigningAccounts()` and `getReceiverAccounts()` in the back-end model loop exclusively over `this.transaction.hbarTransfersList`: [1](#0-0) 

`tokenTransfersList` and `nftTransfersList` are never read. For a token-only `TransferTransaction`, both methods return empty sets.

**Front-end root cause**

The front-end copy has the identical gap: [2](#0-1) 

**Exploit path through the back-end pipeline**

`TransactionSignatureService.computeSignatureKey()` calls `TransactionFactory.fromTransaction()`, which instantiates `TransferTransactionModel`, then calls `extractSignatureRequirements()` to obtain `signingAccounts` and `receiverAccounts`: [3](#0-2) 

When the transaction contains only token transfers, both sets are empty. `addSigningAccountKeys()` and `addReceiverAccountKeys()` iterate over empty sets, so the returned `KeyList` contains only the fee-payer key — token senders and token receivers with `receiverSignatureRequired` are never included.

**Factory registration confirms the model is the sole handler**

`TransferTransaction` maps to exactly one model in both factories, with no fallback: [4](#0-3) [5](#0-4) 

## Impact Explanation

**Organization multi-sig workflow**

In organization mode the system uses `computeSignatureKey` to decide which users must sign before a transaction can be executed. For any `TransferTransaction` that moves fungible tokens or NFTs:

- Token-sender accounts are never added to `signingAccounts` → they are never routed the transaction for signing.
- Token-receiver accounts with `receiverSignatureRequired = true` are never added to `receiverAccounts` → their mandatory counter-signature is never collected.
- The transaction appears "fully signed" to the tool but is submitted to Hedera without required signatures → Hedera rejects it with `INVALID_SIGNATURE`.

**Front-end "to-sign" list**

The front-end uses the same model via its own `TransactionFactory` to compute which keys a local user must supply. Token-transfer participants are invisible to this computation, so users are never prompted to sign transactions where they are token senders or token receivers with `receiverSignatureRequired`. [6](#0-5) 

## Likelihood Explanation

`TransferTransaction` is the most common transaction type in the codebase (dedicated UI component, dedicated test suite, dedicated automation helpers). Token transfers are a primary Hedera use case. Any organization using this tool to coordinate token or NFT transfers will trigger this path on every such transaction. No privileged access is required — a normal user creating a token transfer is sufficient. The existing test suite for `TransferTransactionModel` only exercises `hbarTransfersList` scenarios, confirming the gap has not been caught by automated testing. [7](#0-6) 

## Recommendation

Extend both `TransferTransactionModel` implementations to also iterate `tokenTransfersList` and `nftTransfersList`:

- **`getSigningAccounts()`**: For each entry in `tokenTransfersList`, add the `accountId` of any transfer with a negative amount and `isApproved === false`. For each entry in `nftTransfersList`, add the `senderAccountId`.
- **`getReceiverAccounts()`**: For each entry in `tokenTransfersList`, add the `accountId` of any transfer with a non-negative amount. For each entry in `nftTransfersList`, add the `receiverAccountId`.

Apply the same fix symmetrically to both:
- `back-end/libs/common/src/transaction-signature/model/transfer-transaction.model.ts`
- `front-end/src/renderer/utils/transactionSignatureModels/transfer-transaction.model.ts`

Add unit tests covering token-only and NFT-only `TransferTransaction` scenarios to prevent regression.

## Proof of Concept

```typescript
import {
  TransferTransaction,
  TokenId,
  AccountId,
  NftId,
} from '@hiero-ledger/sdk';
import { TransferTransactionModel } from
  './back-end/libs/common/src/transaction-signature/model/transfer-transaction.model';

// Construct a TransferTransaction with ONLY a fungible-token transfer
const tokenId = TokenId.fromString('0.0.1000');
const sender  = AccountId.fromString('0.0.200');
const receiver = AccountId.fromString('0.0.300');

const tx = new TransferTransaction()
  .addTokenTransfer(tokenId, sender,   -50)
  .addTokenTransfer(tokenId, receiver,  50);

const model = new TransferTransactionModel(tx);

console.log(model.getSigningAccounts());  // Set {} — sender 0.0.200 is MISSING
console.log(model.getReceiverAccounts()); // Set {} — receiver 0.0.300 is MISSING

// Result: computeSignatureKey() will build a KeyList containing only the
// fee-payer key. The transaction is submitted without the sender's signature
// and without the receiver's counter-signature (if receiverSignatureRequired),
// causing Hedera to reject it with INVALID_SIGNATURE.
```

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

**File:** front-end/src/renderer/utils/transactionSignatureModels/transaction-factory.ts (L25-55)
```typescript
  static fromTransaction(transaction: Transaction): TransactionBaseModel<Transaction> {
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

    const transactionType = getTransactionType(
      transaction,
      true,
    ) as keyof typeof transactionModelMap;

    if (transactionModelMap[transactionType]) {
      const Model = transactionModelMap[transactionType];
      //@ts-expect-error typescript
      return new Model(transaction);
    } else {
      throw new Error('Transaction type unknown');
    }
  }
```

**File:** front-end/src/renderer/utils/transactionSignatureModels/transaction.model.ts (L64-125)
```typescript
  async computeSignatureKey(
    mirrorNodeLink: string,
    accountInfoCache: AccountByIdCache,
    nodeInfoCache: NodeByIdCache,
    publicKeyOwnerCache: PublicKeyOwnerCache,
    organization: ConnectedOrganization | null,
  ): Promise<SignatureAudit> {
    const feePayerAccountId = this.getFeePayerAccountId();
    const accounts = this.getSigningAccounts();
    const receiverAccounts = this.getReceiverAccounts();
    const newKeys = this.getNewKeys() ?? [];
    const nodeKeys = await this.getNodeKeys(mirrorNodeLink, accountInfoCache, nodeInfoCache);
    const newNodeKeys = await this.getNewNodeAccountKeys(mirrorNodeLink, accountInfoCache);

    /* Create result objects */
    const signatureKeys: Key[] = [];
    const accountsKeys: Record<string, Key> = {};
    const payerKey: Record<string, Key> = {};
    const receiverAccountsKeys: Record<string, Key> = {};
    const nodeAdminKeys: Record<number, Key> = {};
    const newNodeAccountKeys: Record<string, Key> = {};
    const externalKeys = new Set<PublicKey>();

    const currentKeyList: Key[] = [];
    const hasKey = (key: Key) => currentKeyList.some(existingKey => compareKeys(existingKey, key));

    if (feePayerAccountId) {
      try {
        const accountInfo = await accountInfoCache.lookup(
          feePayerAccountId.toString(),
          mirrorNodeLink,
        );
        if (accountInfo?.key) {
          signatureKeys.push(accountInfo.key);
          payerKey[feePayerAccountId.toString()] = accountInfo.key;
          currentKeyList.push(accountInfo.key);
        }
      } catch (error) {
        logger.warn('Failed to resolve fee payer key', {
          error,
        });
        throw error;
      }
    }

    /* Get the keys of the account ids to the signature key list */
    for (const accountId of accounts) {
      try {
        const accountInfo = await accountInfoCache.lookup(accountId, mirrorNodeLink);
        if (accountInfo?.key && !hasKey(accountInfo.key)) {
          signatureKeys.push(accountInfo.key);
          accountsKeys[accountId] = accountInfo.key;
          currentKeyList.push(accountInfo.key);
        }
      } catch (error) {
        logger.warn('Failed to resolve account signing key', {
          accountId,
          error,
        });
        throw error;
      }
    }
```

**File:** back-end/libs/common/src/transaction-signature/model/transfer-transaction.model.spec.ts (L1-67)
```typescript
import { TransferTransaction } from '@hiero-ledger/sdk';
import { TransferTransactionModel } from './transfer-transaction.model';

describe('TransferTransactionModel', () => {
  it('should have TRANSACTION_TYPE defined', () => {
    expect(TransferTransactionModel.TRANSACTION_TYPE).toBe('TransferTransaction');
  });

  describe('getSigningAccounts', () => {
    it('should return accounts with negative amount and not approved', () => {
      const tx = {
        hbarTransfersList: [
          { accountId: { toString: () => '1' }, amount: { isNegative: () => true }, isApproved: false },
          { accountId: { toString: () => '2' }, amount: { isNegative: () => true }, isApproved: true },
          { accountId: { toString: () => '3' }, amount: { isNegative: () => false }, isApproved: false },
        ],
      } as unknown as TransferTransaction;

      const model = new TransferTransactionModel(tx);
      const accounts = model.getSigningAccounts();

      expect(accounts).toEqual(new Set(['1']));
    });

    it('should return empty set if no transfers meet criteria', () => {
      const tx = {
        hbarTransfersList: [
          { accountId: { toString: () => '1' }, amount: { isNegative: () => false }, isApproved: false },
        ],
      } as unknown as TransferTransaction;

      const model = new TransferTransactionModel(tx);
      const accounts = model.getSigningAccounts();

      expect(accounts.size).toBe(0);
    });
  });

  describe('getReceiverAccounts', () => {
    it('should return accounts with non-negative amounts', () => {
      const tx = {
        hbarTransfersList: [
          { accountId: { toString: () => '1' }, amount: { isNegative: () => false }, isApproved: false },
          { accountId: { toString: () => '2' }, amount: { isNegative: () => true }, isApproved: false },
        ],
      } as unknown as TransferTransaction;

      const model = new TransferTransactionModel(tx);
      const accounts = model.getReceiverAccounts();

      expect(accounts).toEqual(new Set(['1']));
    });

    it('should return empty set if no transfers meet criteria', () => {
      const tx = {
        hbarTransfersList: [
          { accountId: { toString: () => '2' }, amount: { isNegative: () => true }, isApproved: false },
        ],
      } as unknown as TransferTransaction;

      const model = new TransferTransactionModel(tx);
      const accounts = model.getReceiverAccounts();

      expect(accounts.size).toBe(0);
    });
  });
});
```
