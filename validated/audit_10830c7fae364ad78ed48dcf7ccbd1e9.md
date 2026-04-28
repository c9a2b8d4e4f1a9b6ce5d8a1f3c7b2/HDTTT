I have all the information needed. Let me analyze each claim against the actual code.

**Confirmed facts:**

1. `v-html` binding at lines 421–429 of `CreateTransactionGroup.vue` — **confirmed exact**.
2. `transactionMemo` is a free-form string decoded from raw bytes, passed directly to `v-html` — **confirmed**.
3. `groupItem.description` passed to `v-html` — **confirmed**.
4. `makeTransfer` → `formatHbarTransfers` → interpolates `sender.accountId` and `receiver.accountId` into HTML string — **confirmed**, but `AccountId.toString()` from the Hedera SDK returns only `shard.realm.num` numeric format; no HTML injection possible here.
5. `AppStepper.vue` `bubbleIcon` interpolation — **confirmed in code**, but `bubbleIcon` is set by the application's own stepper config, not from attacker-controlled transaction data.
6. `mainWindow.ts`: `nodeIntegration: false`, `contextIsolation: true`, `sandbox: false` — **confirmed exact**.

---

Audit Report

## Title
Unsanitized `v-html` Rendering of Hedera Transaction Memo and Description Enables Stored XSS in Transaction Group View

## Summary
`CreateTransactionGroup.vue` renders the `transactionMemo` field (decoded from raw Hedera transaction bytes) and `groupItem.description` directly into the DOM via Vue's `v-html` directive with no sanitization. An attacker who controls either field can inject arbitrary HTML/JavaScript that executes in the Electron renderer process when a victim views the transaction group.

## Finding Description

In `front-end/src/renderer/pages/CreateTransactionGroup/CreateTransactionGroup.vue`, lines 421–429, a single `v-html` binding renders one of several values:

```vue
v-html="
  groupItem.type == 'Transfer Transaction'
    ? makeTransfer(index)
    : groupItem.description != ''
      ? groupItem.description
      : Transaction.fromBytes(groupItem.transactionBytes).transactionMemo
        ? Transaction.fromBytes(groupItem.transactionBytes).transactionMemo
        : createTransactionId(groupItem.payerAccountId, groupItem.validStart)
"
``` [1](#0-0) 

**Exploitable branch 1 — `transactionMemo`:** The Hedera SDK's `transactionMemo` is a free-form UTF-8 string embedded in the protobuf transaction bytes. Any party who constructs a transaction controls this field entirely. The raw string is passed to `v-html` with no sanitization. [2](#0-1) 

**Exploitable branch 2 — `groupItem.description`:** This field is populated from CSV import (`ImportCSVController.vue`) or from the organization back-end. A malicious CSV row or a crafted organization transaction can inject arbitrary HTML here. [3](#0-2) 

**Non-exploitable branch — `makeTransfer(index)`:** `formatHbarTransfers` interpolates `sender.accountId` and `receiver.accountId` into an HTML string. However, these are Hedera SDK `AccountId` objects whose `toString()` returns only the `shard.realm.num` numeric format (e.g., `0.0.12345`), which cannot contain HTML metacharacters. The amount values are also SDK-typed numerics. This branch is **not exploitable**. [4](#0-3) 

The `AppStepper.vue` `bubbleIcon` interpolation is set by the application's own stepper configuration, not from attacker-controlled transaction data, and is therefore **not an attack vector**. [5](#0-4) 

## Impact Explanation

The Electron window is configured with `nodeIntegration: false` and `contextIsolation: true`, which prevents direct Node.js API access from the renderer. [6](#0-5) 

However, `sandbox: false` is set, meaning the renderer process is not OS-sandboxed. [7](#0-6) 

XSS in the renderer can call any method exposed on `window.electronAPI` via the preload script, enabling an attacker to invoke IPC handlers — which in this application include database access, key management, and transaction signing operations — without any additional privilege escalation. This is a stored/persistent XSS (not self-XSS), so it is in scope per the SECURITY.md exclusion list.

## Likelihood Explanation

**Organization workflow (higher likelihood):** Any authenticated organization member can submit a transaction with a crafted `transactionMemo`. When another org member opens the transaction group view, the payload executes immediately. No cryptographic break is required; the Hedera SDK faithfully decodes whatever memo bytes are present.

**Personal workflow:** The attacker needs the victim to import a crafted `.bytes` transaction file or a malicious CSV — a realistic social-engineering step. The `groupItem.description` field from CSV import is equally unsanitized.

## Recommendation

Replace `v-html` with safe text interpolation (`{{ }}`) wherever the content does not require HTML rendering. If HTML rendering is genuinely required (e.g., for the transfer display), sanitize all attacker-influenced strings with a library such as [DOMPurify](https://github.com/cure53/DOMPurify) before passing them to `v-html`:

```typescript
import DOMPurify from 'dompurify';
// ...
v-html="DOMPurify.sanitize(groupItem.description)"
```

For `transactionMemo`, which is always plain text, use `{{ }}` interpolation exclusively.

## Proof of Concept

1. Create a Hedera `TransferTransaction` with `transactionMemo` set to:
   ```
   <img src=x onerror="window.electronAPI.someHandler()">
   ```
2. Serialize the transaction to bytes.
3. Share the bytes file with a victim (or submit via the organization workflow).
4. Victim opens the Create Transaction Group view and adds the transaction.
5. Vue renders the `v-html` binding; the `onerror` handler fires, executing arbitrary JavaScript in the Electron renderer process with access to all preload-exposed IPC methods.

### Citations

**File:** front-end/src/renderer/pages/CreateTransactionGroup/CreateTransactionGroup.vue (L421-429)
```vue
                v-html="
                  groupItem.type == 'Transfer Transaction'
                    ? makeTransfer(index)
                    : groupItem.description != ''
                      ? groupItem.description
                      : Transaction.fromBytes(groupItem.transactionBytes).transactionMemo
                        ? Transaction.fromBytes(groupItem.transactionBytes).transactionMemo
                        : createTransactionId(groupItem.payerAccountId, groupItem.validStart)
                "
```

**File:** front-end/src/renderer/utils/transferTransactions.ts (L29-29)
```typescript
    return `${sender.accountId} --> ${stringifyHbarWithFont(receiver.amount)} --> ${receiver.accountId}`;
```

**File:** front-end/src/renderer/components/ui/AppStepper.vue (L31-32)
```vue
    if (item.bubbleIcon) {
      return `<i class="bi bi-${item.bubbleIcon}"></i>`;
```

**File:** front-end/src/main/windows/mainWindow.ts (L31-32)
```typescript
      nodeIntegration: false,
      contextIsolation: true,
```

**File:** front-end/src/main/windows/mainWindow.ts (L33-33)
```typescript
      sandbox: false,
```
