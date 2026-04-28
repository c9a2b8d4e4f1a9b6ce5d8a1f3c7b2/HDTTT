All code references check out. Let me verify the exact lines before writing the report.

Audit Report

## Title
`TransferTransactionModel.getSigningAccounts()` Ignores Token and NFT Transfer Senders, Causing Transactions to Permanently Fail

## Summary
Both the backend and frontend `TransferTransactionModel` implementations compute required signers by iterating only over `hbarTransfersList`. A Hedera `TransferTransaction` can also carry fungible-token transfers (`tokenTransfersList`) and NFT transfers (`nftTransfersList`), each of which requires the sender account's signature. Because those lists are never consulted, the system never collects the required keys from token-only senders, marks the transaction as ready for execution with an incomplete signature set, and the Hedera network rejects it with `INVALID_SIGNATURE`. The transaction is permanently stuck in `FAILED` state with no recovery path.

## Finding Description

**Root cause — backend model:**

`getSigningAccounts()` in the backend `TransferTransactionModel` iterates exclusively over `hbarTransfersList`: [1](#0-0) 

`tokenTransfersList` and `nftTransfersList` are never visited. The identical omission exists in the frontend model: [2](#0-1) 

`getReceiverAccounts()` has the same gap in both models — token/NFT receivers with `receiverSignatureRequired = true` are also never included: [3](#0-2) 

**Contrast with `AccountAllowanceApproveTransactionModel`**, which correctly handles all three approval types (HBAR, token, NFT): [4](#0-3) 

**Signature pipeline:**

`TransactionSignatureService.computeSignatureKey()` calls `extractSignatureRequirements()`, which calls `transactionModel.getSigningAccounts()`: [5](#0-4) 

`processTransactionStatus()` then calls `computeSignatureKey()` and `hasValidSignatureKey()`. Because the computed `KeyList` contains only the fee-payer key (no token sender keys), and the fee-payer has already signed, `hasValidSignatureKey` returns `true` and the transaction is promoted to `WAITING_FOR_EXECUTION`: [6](#0-5) 

The same incomplete `computeSignatureKey()` is used again at execution time in `getValidatedSDKTransaction()`: [7](#0-6) 

## Impact Explanation
Any `TransferTransaction` that debits tokens or NFTs from an account that is not simultaneously an HBAR sender will be submitted to the Hedera network without the required sender signature. The network rejects it with `INVALID_SIGNATURE`. The transaction is permanently marked `FAILED` and cannot be retried through the normal workflow. No funds are stolen, but token-transfer workflows are silently broken: the UI reports success at the signing stage, but on-chain execution always fails.

## Likelihood Explanation
Transferring tokens without a simultaneous HBAR transfer in the same transaction is a standard, everyday Hedera operation. Any authenticated organization user can trigger this by submitting a token-only `TransferTransaction`. No privileged access, no leaked credentials, and no special network position are required. The failure is deterministic and reproducible on every such transaction.

## Recommendation
Extend `getSigningAccounts()` in both the backend and frontend `TransferTransactionModel` to also iterate over `tokenTransfersList` and `nftTransfersList`, adding the sender account for each non-approved debit entry — mirroring the pattern already used in `AccountAllowanceApproveTransactionModel`. Similarly extend `getReceiverAccounts()` to include token/NFT receiver accounts so that `receiverSignatureRequired` checks are applied correctly.

## Proof of Concept
1. Create a `TransferTransaction` that moves fungible tokens from account A to account B, with the fee paid by account C. Account A has no HBAR debit in the transaction.
2. Sign the transaction with only account C's key (the fee-payer).
3. Upload the signature map to the backend.
4. `processTransactionStatus()` calls `computeSignatureKey()` → `getSigningAccounts()` → returns only `{C}`. `hasValidSignatureKey` returns `true`. Transaction is promoted to `WAITING_FOR_EXECUTION`.
5. The chain service calls `getValidatedSDKTransaction()`, which again computes the same incomplete key list and passes the check.
6. The transaction is submitted to the Hedera network. The network requires account A's signature for the token debit. The network returns `INVALID_SIGNATURE`.
7. `_executeTransaction()` catches the error and sets `transactionStatus = TransactionStatus.FAILED`. [8](#0-7)

### Citations

**File:** back-end/libs/common/src/transaction-signature/model/transfer-transaction.model.ts (L10-20)
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

**File:** front-end/src/renderer/utils/transactionSignatureModels/transfer-transaction.model.ts (L6-17)
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

**File:** back-end/libs/common/src/execute/execute.service.ts (L151-175)
```typescript
    } catch (error) {
      let message = 'Unknown error';
      let statusCode = null;

      if (error instanceof Error) {
        message = error.message;

        const status = (error as any).status;
        if (status?._code) {
          statusCode = status._code;
        } else {
          statusCode = getStatusCodeFromMessage(message);
        }
      }

      // Another pod already submitted this — don't touch the row, let the
      // successful pod win the update and emit the change
      if (statusCode === Status.DuplicateTransaction._code) {
        isDuplicate = true;
        this.logger.debug(
          `Duplicate transaction ${transaction.id} (txId=${sdkTransaction.transactionId}, statusCode=${statusCode}) detected; assuming it was successfully executed by another pod and skipping updates.`,
        );
      } else {
        transactionStatus = TransactionStatus.FAILED;
        transactionStatusCode = statusCode;
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L215-220)
```typescript
    /* Gets the signature key */
    const signatureKey = await this.transactionSignatureService.computeSignatureKey(transaction);

    /* Checks if the transaction has valid signatureKey */
    if (!hasValidSignatureKey([...sdkTransaction._signerPublicKeys], signatureKey))
      throw new Error('Transaction has invalid signature.');
```
