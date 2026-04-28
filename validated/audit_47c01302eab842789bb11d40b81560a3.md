I have verified the claim against the actual codebase. Let me confirm the key facts before rendering a verdict.

**Verified facts:**

1. `ConfirmTransactionHandler.vue` template (lines 102–163) renders only: Type, Transaction ID, Valid Start, Max Transaction Fee, and a staking-range warning — no transfer amounts or recipients. [1](#0-0) 

2. The `transaction` computed property deserializes bytes into a generic `Transaction` — never cast to `TransferTransaction` to read `hbarTransfersList`. [2](#0-1) 

3. `TransferTransactionModel` iterates `hbarTransfersList` to determine signing accounts, proving the data is accessible from deserialized bytes. [3](#0-2) 

4. `TransferDetails.vue` correctly renders sender accounts, receiver accounts, and amounts per leg — but it is only used in `TransactionDetails` page and `TransactionBrowserPage`, not in `ConfirmTransactionHandler.vue`. [4](#0-3) 

5. `createAccountCreateTransaction` sets `initialBalance` on the transaction bytes. [5](#0-4) 

6. The `isTransferOutOfStaking` guard only warns about staking-range accounts (0.0.400–0.0.439); it does not surface amounts or recipients for ordinary transfers. [6](#0-5) 

7. SECURITY.md excludes "UI/UX best practice recommendations" and "UX and UI impacts that do not materially disrupt use of the platform" — but this omission affects the irreversible cryptographic signing step, which is a material security checkpoint, not a cosmetic preference. [7](#0-6) 

---

Audit Report

## Title
Missing HBAR Transfer Amount and Recipients in Transaction Signing Confirmation Dialog

## Summary
`ConfirmTransactionHandler.vue` — the modal shown immediately before a user enters their password and cryptographically signs a transaction — omits the financial substance of `TransferTransaction` (sender accounts, receiver accounts, per-leg amounts) and the `initialBalance` of `AccountCreateTransaction`. A signer sees only the transaction type label and the max fee, making it impossible to verify what they are authorizing at the last checkpoint before an irreversible signature.

## Finding Description
The `transaction` computed property in `ConfirmTransactionHandler.vue` (lines 36–40) deserializes raw bytes into a generic `Transaction` object via `Transaction.fromBytes()` but never casts it to `TransferTransaction` to access `hbarTransfersList`. [2](#0-1) 

The template branch for `TransactionRequest` (lines 102–133) renders four fields unconditionally — Type, Transaction ID, Valid Start, Max Transaction Fee — and nothing else for transfer-specific data. [1](#0-0) 

The only additional guard is `isTransferOutOfStaking` (lines 135–142), which only fires for transfers debiting staking accounts 0.0.400–0.0.439 and does not surface amounts or recipients for ordinary transfers. [8](#0-7) 

`TransferTransactionModel.getSigningAccounts()` already iterates `hbarTransfersList` from the same deserialized bytes, proving the data is accessible. [3](#0-2) 

`TransferDetails.vue` correctly renders all legs of a transfer (sender, receiver, amount) and is mapped to `TransferTransaction` in `txTypeComponentMapping`, but this mapping is only consumed by `TransactionDetails.vue` and `TransactionBrowserPage.vue` — never by `ConfirmTransactionHandler.vue`. [4](#0-3) 

For `AccountCreateTransaction`, `initialBalance` is embedded in the transaction bytes at creation time but is never read back or displayed in the confirmation modal. [5](#0-4) 

## Impact Explanation
In the organization multi-signer workflow, a transaction is created by one party and signed by another. The signer's last checkpoint before entering their password and producing an irreversible cryptographic signature is the `ConfirmTransactionHandler` modal. Because the modal shows only `"Transfer Transaction"` and a max fee, a malicious or compromised transaction creator can embed an arbitrarily large HBAR transfer — including one that drains the payer account — and the signer's confirmation screen is visually identical to a routine 1-HBAR transfer. The signature, once submitted to the Hedera network, cannot be reversed.

## Likelihood Explanation
The organization multi-signer workflow is the primary use-case of the tool. `TransferTransaction` and `AccountCreateTransaction` with non-zero `initialBalance` are among the most common transaction types. No special attacker capability is required beyond being a legitimate transaction creator in the organization. The omission is present for every such transaction, not an edge case.

## Recommendation
In `ConfirmTransactionHandler.vue`, after deserializing the transaction bytes, check `instanceof TransferTransaction` and render each leg of `hbarTransfersList` (account ID and amount) in the confirmation modal — reusing or adapting the existing `TransferDetails.vue` component. Similarly, check `instanceof AccountCreateTransaction` and render `initialBalance`. The `txTypeComponentMapping` and `TransferDetails.vue` already contain the correct rendering logic and can be composed into the confirmation modal with minimal additional code. [9](#0-8) 

## Proof of Concept
1. In an organization, Party A creates a `TransferTransaction` that sends 50,000 HBAR from the organization's treasury account to an attacker-controlled account, with a max fee of 2 HBAR.
2. Party A submits the transaction to the organization server.
3. Party B (a legitimate signer) receives a signing notification and opens the transaction.
4. Party B clicks "Sign." The `ConfirmTransactionHandler` modal appears showing:
   - Type of Transaction: `Transfer Transaction`
   - Transaction ID: `0.0.1234@1234567890.000000000`
   - Valid Start: `Mon Jan 01 2024`
   - Max Transaction Fee: `2 ℏ`
5. No transfer amounts or recipient accounts are shown. The `isTransferOutOfStaking` guard does not fire because neither account is in the 0.0.400–0.0.439 range.
6. Party B enters their password and clicks Confirm.
7. The 50,000 HBAR transfer is signed and submitted to the Hedera network irreversibly.

The root cause is the absence of a `instanceof TransferTransaction` branch in the `ConfirmTransactionHandler.vue` template that reads and renders `transaction.hbarTransfersList`. [1](#0-0)

### Citations

**File:** front-end/src/renderer/components/Transaction/TransactionProcessor/components/ConfirmTransactionHandler.vue (L36-40)
```vue
const transaction = computed(() =>
  request.value instanceof TransactionRequest
    ? Transaction.fromBytes(request.value.transactionBytes)
    : null,
);
```

**File:** front-end/src/renderer/components/Transaction/TransactionProcessor/components/ConfirmTransactionHandler.vue (L102-133)
```vue
      <form v-if="transaction" @submit.prevent="handleConfirmTransaction">
        <h3 class="text-center text-title text-bold mt-5">Confirm Transaction</h3>
        <div class="container-main-bg text-small p-4 mt-5">
          <div class="d-flex justify-content-between p-3">
            <p>Type of Transaction</p>
            <p data-testid="p-type-transaction">{{ getTransactionType(transaction) }}</p>
          </div>
          <div class="d-flex justify-content-between p-3 mt-3">
            <p>Transaction ID</p>
            <p class="text-secondary" data-testid="p-transaction-id">
              {{ transaction?.transactionId }}
            </p>
          </div>
          <div class="d-flex justify-content-between p-3 mt-3">
            <p>Valid Start</p>
            <p class="">
              {{ transaction?.transactionId?.validStart?.toDate().toDateString() }}
            </p>
          </div>
          <div
            v-if="transaction?.maxTransactionFee"
            class="d-flex justify-content-between p-3 mt-3"
          >
            <p>Max Transaction Fee</p>
            <p class="" data-testid="p-max-tx-fee">
              {{ stringifyHbar(transaction.maxTransactionFee) }}
              <span v-if="network.currentRate" class="text-pink">
                ({{ getDollarAmount(network.currentRate, transaction.maxTransactionFee.toBigNumber()) }})
              </span>
            </p>
          </div>
        </div>
```

**File:** front-end/src/renderer/components/Transaction/TransactionProcessor/components/ConfirmTransactionHandler.vue (L135-142)
```vue
        <div
          v-if="isTransferOutOfStaking"
          class="container-main-bg text-small text-center text-warning border-warning p-4 mt-5"
        >
          <p class="text-title">Transfer out of staking accounts</p>
          <p class="mt-3">This transaction is moving funds out of the staking accounts.</p>
          <p class="mt-1">Please review carefully where these hbars are being sent.</p>
        </div>
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

**File:** front-end/src/renderer/components/Transaction/Details/txTypeComponentMapping.ts (L29-44)
```typescript
const txTypeComponentMapping = {
  [transactionTypeKeys.createFile]: FileDetails,
  [transactionTypeKeys.updateFile]: FileDetails,
  [transactionTypeKeys.appendToFile]: FileDetails,
  [transactionTypeKeys.createAccount]: AccountDetails,
  [transactionTypeKeys.updateAccount]: AccountDetails,
  [transactionTypeKeys.deleteAccount]: DeleteAccountDetails,
  [transactionTypeKeys.transfer]: TransferDetails,
  [transactionTypeKeys.approveAllowance]: AccountApproveAllowanceDetails,
  [transactionTypeKeys.freeze]: FreezeDetails,
  [transactionTypeKeys.systemDelete]: SystemDetails,
  [transactionTypeKeys.systemUndelete]: SystemDetails,
  [transactionTypeKeys.nodeCreate]: NodeDetails,
  [transactionTypeKeys.nodeUpdate]: NodeDetails,
  [transactionTypeKeys.nodeDelete]: NodeDetails,
};
```

**File:** front-end/src/renderer/utils/sdk/createTransactions.ts (L187-192)
```typescript
  const transaction = new AccountCreateTransaction()
    .setReceiverSignatureRequired(data.receiverSignatureRequired)
    .setDeclineStakingReward(data.declineStakingReward)
    .setInitialBalance(data.initialBalance || new Hbar(0))
    .setMaxAutomaticTokenAssociations(data.maxAutomaticTokenAssociations)
    .setAccountMemo(data.accountMemo);
```

**File:** front-end/src/renderer/utils/transactions.ts (L86-106)
```typescript
export const hasTransfersOutOfStaking = (transaction: Tx): boolean => {
  if (transaction instanceof TransferTransaction) {
    const transferMap = transaction.hbarTransfers;
    let stakingDebit = Long.fromInt(0);
    let stakingCredit = Long.fromInt(0);

    for (const [accountId, hbar] of transferMap) {
      const accountNum = accountId.num.toNumber();
      if (accountNum >= START_OF_STAKING_ACCOUNT_NUM && accountNum <= END_OF_STAKING_ACCOUNT_NUM) {
        if (hbar.isNegative()) {
          stakingDebit = stakingDebit.add(hbar.toTinybars());
        } else {
          stakingCredit = stakingCredit.add(hbar.toTinybars());
        }
      }
    }
    if (stakingCredit.add(stakingDebit).isNegative()) {
      return true;
    }
  }
  return false;
```

**File:** SECURITY.md (L44-45)
```markdown
- Impacts that only require DDoS.
- UX and UI impacts that do not materially disrupt use of the platform.
```

**File:** front-end/src/renderer/components/Transaction/Details/TransferDetails.vue (L80-90)
```vue
<template>
  <div v-if="transaction instanceof TransferTransaction && true" class="mt-5">
    <!-- Hbar transfers -->
    <div v-if="transferParsingComplete" class="row">
      <div class="col-6">
        <div class="mt-3">
          <template v-for="debit in transaction.hbarTransfersList" :key="debit.accountId">
            <div v-if="debit.amount.isNegative()" class="mt-3">
              <div class="row align-items-center px-3">
                <div
                  class="col-6 col-lg-5 flex-centered justify-content-start flex-wrap overflow-hidden"
```
