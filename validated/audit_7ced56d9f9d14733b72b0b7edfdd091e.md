### Title
Blind Bulk Approval in `ApproveAllController` Allows Malicious Creator to Obtain Signatures on Undisclosed Transaction Parameters

### Summary
The `ApproveAllController.vue` component presents approvers with only a generic "Are you sure you want to approve all transactions?" confirmation dialog before cryptographically signing every transaction in a group. No transaction-specific parameters — amounts, spender accounts, transfer recipients, or file contents — are displayed to the approver. A malicious organization user who creates a transaction group can embed an `AccountAllowanceApproveTransaction` with an arbitrarily large HBAR allowance and obtain a valid approver signature without the approver ever seeing the amount or spender.

### Finding Description

**Root cause — `ApproveAllController.vue`:**

The confirmation prompt is constructed at lines 50–54:

```js
const confirmTitle = computed(() =>
  props.approved ? 'Approve all transactions?' : 'Reject all transactions?',
);
const confirmText = computed(() => `Are you sure you want to ${action.value} all transactions?`);
```

No transaction-specific data is injected into the dialog. The signing loop at lines 80–96 then iterates over every group item, deserializes the raw bytes, and produces a cryptographic signature for each one — all without surfacing any decoded fields to the user:

```js
for (const item of group.groupItems) {
  if (await getUserShouldApprove(..., item.transaction.id)) {
    const transactionBytes = hexToUint8Array(item.transaction.transactionBytes);
    const transaction = Transaction.fromBytes(transactionBytes);
    const signature = getTransactionBodySignatureWithoutNodeAccountId(privateKey, transaction);
    await sendApproverChoice(..., props.approved);
  }
}
```

**Contrast with the single-transaction path:**

When an approver reviews a single transaction via `TransactionDetails.vue`, the `txTypeComponentMapping` routes to `AccountApproveAllowanceDetails.vue`, which renders the owner, spender, and amount. The "Approve All" path bypasses this entirely.

**Attack path:**

1. Malicious organization user (creator) creates a transaction group containing an `AccountAllowanceApproveTransaction` granting themselves a 1,000,000 HBAR allowance from the victim's account. The group description is set to something innocuous (e.g., "Monthly fee schedule update").
2. The creator assigns the victim as an approver.
3. The victim opens the group, sees the benign description, and clicks "Approve all".
4. The confirmation dialog shows only "Are you sure you want to approve all transactions?" — no amounts, no spender, no transaction type breakdown.
5. The victim enters their personal password and confirms.
6. `ApproveAllController` signs and submits the approval for every item, including the allowance transaction.
7. The creator calls `cryptoApproveAllowance` on-chain using the collected signatures, then drains the victim's account via `cryptoTransfer`.

### Impact Explanation

An approver's cryptographic signature is obtained over an `AccountAllowanceApproveTransaction` whose financial parameters (amount, spender) were never displayed. Once the allowance is on-chain, the spender (malicious creator) can transfer up to the approved amount from the victim's Hedera account with no further interaction. Impact is direct, irreversible asset loss proportional to the allowance amount set by the attacker.

### Likelihood Explanation

The "Approve All" button is a standard, documented workflow in the organization mode UI. The attacker requires only a normal organization user account — no admin or privileged keys. The victim must click "Approve All" rather than reviewing each transaction individually, which is the expected behavior for bulk approval of large groups. The attack is fully reachable by any organization member who can create transaction groups and assign approvers.

### Recommendation

Before the confirmation dialog is shown, enumerate and render the decoded parameters of every transaction in the group — at minimum: transaction type, amounts, and counterparty account IDs. For `AccountAllowanceApproveTransaction` entries, display owner, spender, and amount explicitly. Require the approver to scroll through or acknowledge each item before the "Approve all" button becomes active. This mirrors the per-transaction detail display already implemented in `AccountApproveAllowanceDetails.vue` and `TransactionDetails.vue`.

### Proof of Concept

**Preconditions:** Two organization accounts — attacker (creator) and victim (approver). Victim holds HBAR.

1. Attacker creates a transaction group via the API or UI. The group contains one `AccountAllowanceApproveTransaction`: owner = victim's account, spender = attacker's account, amount = 1,000,000 HBAR.
2. Attacker sets group description to "Routine maintenance batch".
3. Attacker assigns victim as approver for the group.
4. Victim navigates to the group details page and clicks "Approve all".
5. The `ActionController` confirmation dialog renders only:
   - Title: "Approve all transactions?"
   - Body: "Are you sure you want to approve all transactions?"
6. Victim enters personal password and confirms.
7. `handleApproveAll` (lines 57–111 of `ApproveAllController.vue`) iterates the group, deserializes the allowance transaction bytes, signs with the victim's key, and posts the approval to the backend.
8. Attacker collects the signature from the backend and submits the `AccountAllowanceApproveTransaction` to the Hedera network.
9. Attacker calls `cryptoTransfer` using the granted allowance, moving funds from victim's account to attacker's account.

**Expected result:** Victim's account is drained up to the approved amount. Victim had no opportunity to see the amount or spender before signing. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** front-end/src/renderer/pages/TransactionGroupDetails/ApproveAllController.vue (L50-54)
```vue
const confirmTitle = computed(() =>
  props.approved ? 'Approve all transactions?' : 'Reject all transactions?',
);

const confirmText = computed(() => `Are you sure you want to ${action.value} all transactions?`);
```

**File:** front-end/src/renderer/pages/TransactionGroupDetails/ApproveAllController.vue (L80-96)
```vue
      for (const item of group.groupItems) {
        if (await getUserShouldApprove(user.selectedOrganization.serverUrl, item.transaction.id)) {
          const transactionBytes = hexToUint8Array(item.transaction.transactionBytes);
          const transaction = Transaction.fromBytes(transactionBytes);
          const signature = getTransactionBodySignatureWithoutNodeAccountId(
            privateKey,
            transaction,
          );

          await sendApproverChoice(
            user.selectedOrganization.serverUrl,
            item.transaction.id,
            user.selectedOrganization.userKeys[0].id,
            signature,
            props.approved,
          );
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

**File:** front-end/src/renderer/pages/TransactionDetails/TransactionDetails.vue (L517-521)
```vue
              <Component
                :is="txTypeComponentMapping[getTransactionType(sdkTransaction, true)]"
                :transaction="sdkTransaction"
                :organization-transaction="orgTransaction"
              />
```
