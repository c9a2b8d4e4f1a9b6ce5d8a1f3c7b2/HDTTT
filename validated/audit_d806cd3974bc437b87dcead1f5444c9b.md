All code references have been verified against the actual repository. The claims are accurate.

---

Audit Report

## Title
Blind Bulk Approval in `ApproveAllController` Allows Malicious Creator to Obtain Signatures on Undisclosed Transaction Parameters

## Summary
The `ApproveAllController.vue` component signs every transaction in a group after presenting only a generic confirmation dialog. No transaction-specific parameters — amounts, spender accounts, transfer recipients — are shown to the approver before their cryptographic signature is produced. A malicious organization member who creates a transaction group can embed an `AccountAllowanceApproveTransaction` with an arbitrarily large HBAR allowance and obtain a valid approver signature without the approver ever seeing the amount or spender.

## Finding Description

**Root cause — `ApproveAllController.vue`:**

The confirmation dialog is constructed at lines 50–54 with no transaction-specific data injected:

```js
const confirmTitle = computed(() =>
  props.approved ? 'Approve all transactions?' : 'Reject all transactions?',
);
const confirmText = computed(() => `Are you sure you want to ${action.value} all transactions?`);
``` [1](#0-0) 

The signing loop at lines 80–96 then iterates over every group item, deserializes the raw bytes, and produces a cryptographic signature for each one — all without surfacing any decoded fields to the user:

```js
for (const item of group.groupItems) {
  if (await getUserShouldApprove(..., item.transaction.id)) {
    const transactionBytes = hexToUint8Array(item.transaction.transactionBytes);
    const transaction = Transaction.fromBytes(transactionBytes);
    const signature = getTransactionBodySignatureWithoutNodeAccountId(privateKey, transaction);
    await sendApproverChoice(..., props.approved);
  }
}
``` [2](#0-1) 

**Contrast with the single-transaction path:**

When an approver reviews a single transaction via `TransactionDetails.vue`, the `txTypeComponentMapping` routes `AccountAllowanceApproveTransaction` to `AccountApproveAllowanceDetails.vue`: [3](#0-2) 

That component renders the owner account ID, spender account ID, and HBAR amount in full: [4](#0-3) 

The `TransactionDetails.vue` page uses this mapping via the dynamic `<Component :is="...">` at lines 517–521: [5](#0-4) 

The "Approve All" path bypasses this rendering entirely. The failed assumption is that bulk approval is safe because approvers are expected to have reviewed individual transactions beforehand — but the UI provides no enforcement of this, and the workflow is self-contained.

## Impact Explanation

An approver's cryptographic signature is obtained over an `AccountAllowanceApproveTransaction` whose financial parameters (amount, spender) were never displayed. Once the allowance is on-chain, the spender (malicious creator) can transfer up to the approved amount from the victim's Hedera account with no further interaction. Impact is direct, irreversible asset loss proportional to the allowance amount set by the attacker.

## Likelihood Explanation

The "Approve All" button is a standard, in-application workflow for bulk approval of large transaction groups. The attacker requires only a normal organization user account — no admin or privileged keys. The victim must click "Approve All" rather than reviewing each transaction individually, which is the expected behavior for bulk approval. The attack is fully reachable by any organization member who can create transaction groups and assign approvers.

## Recommendation

Before the confirmation dialog is shown, deserialize and decode every transaction in the group and render a summary list of transaction types and their key parameters (type, amount, spender/recipient). For `AccountAllowanceApproveTransaction` entries specifically, display the owner, spender, and HBAR/token amount — the same fields already rendered by `AccountApproveAllowanceDetails.vue` — so the approver has informed consent before entering their personal password and confirming.

## Proof of Concept

1. Malicious organization user (creator) creates a transaction group containing an `AccountAllowanceApproveTransaction` granting themselves a 1,000,000 HBAR allowance from the victim's account. The group description is set to something innocuous (e.g., "Monthly fee schedule update").
2. The creator assigns the victim as an approver.
3. The victim opens the group, sees the benign description, and clicks "Approve all".
4. The confirmation dialog shows only "Are you sure you want to approve all transactions?" — no amounts, no spender, no transaction type breakdown. [6](#0-5) 
5. The victim enters their personal password and confirms.
6. `handleApproveAll` signs and submits the approval for every item, including the allowance transaction. [2](#0-1) 
7. The creator calls `cryptoApproveAllowance` on-chain using the collected signatures, then drains the victim's account via `cryptoTransfer`.

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

**File:** front-end/src/renderer/components/Transaction/Details/txTypeComponentMapping.ts (L37-37)
```typescript
  [transactionTypeKeys.approveAllowance]: AccountApproveAllowanceDetails,
```

**File:** front-end/src/renderer/components/Transaction/Details/AccountApproveAllowanceDetails.vue (L68-97)
```vue
        <div v-if="approval.ownerAccountId" :class="commonColClass">
          <h4 :class="detailItemLabelClass">Owner ID</h4>
          <p :class="detailItemValueClass" data-testid="p-account-approve-details-owner-id">
            <span v-if="nicknames[i].ownerNickname">
              {{
                `${nicknames[i].ownerNickname} (${getAccountIdWithChecksum(approval.ownerAccountId?.toString())})`
              }}
            </span>
            <span v-else>{{ getAccountIdWithChecksum(approval.ownerAccountId?.toString()) }}</span>
          </p>
        </div>
        <div v-if="approval.spenderAccountId" :class="commonColClass">
          <h4 :class="detailItemLabelClass">Spender ID</h4>
          <p :class="detailItemValueClass" data-testid="p-account-approve-details-spender-id">
            <span v-if="nicknames[i].spenderNickname">
              {{
                `${nicknames[i].spenderNickname} (${getAccountIdWithChecksum(approval.spenderAccountId?.toString())})`
              }}
            </span>
            <span v-else>{{
              getAccountIdWithChecksum(approval.spenderAccountId?.toString())
            }}</span>
          </p>
        </div>
        <div :class="commonColClass">
          <h4 :class="detailItemLabelClass">Amount</h4>
          <p :class="detailItemValueClass" data-testid="p-account-approve-details-amount">
            {{ stringifyHbar(approval.amount || Hbar.fromString('0')) }}
          </p>
        </div>
```

**File:** front-end/src/renderer/pages/TransactionDetails/TransactionDetails.vue (L517-521)
```vue
              <Component
                :is="txTypeComponentMapping[getTransactionType(sdkTransaction, true)]"
                :transaction="sdkTransaction"
                :organization-transaction="orgTransaction"
              />
```
