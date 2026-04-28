### Title
Unsanitized User-Controlled Data Rendered via `v-html` in Transaction Group View Enables Stored XSS

### Summary
In `CreateTransactionGroup.vue`, a `v-html` directive renders `groupItem.description` and `Transaction.fromBytes(...).transactionMemo` directly as raw HTML without any sanitization. Both values are user-controlled and stored persistently (in the local SQLite DB or the organization backend). An attacker who can set a malicious description or transaction memo can inject arbitrary HTML/JavaScript that executes in the Electron renderer process of any user who opens the Create Transaction Group view.

### Finding Description

In `front-end/src/renderer/pages/CreateTransactionGroup/CreateTransactionGroup.vue` lines 421–429, the template uses `v-html` to render a ternary expression that falls through to `groupItem.description` and then to `Transaction.fromBytes(groupItem.transactionBytes).transactionMemo`:

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

Vue's `v-html` directive sets `innerHTML` directly, bypassing Vue's template escaping. Neither `groupItem.description` nor `transactionMemo` is passed through any sanitizer before being injected into the DOM.

The `description` field is a free-text string entered by the user and stored in the database. The `transactionMemo` is decoded directly from raw Hedera transaction bytes via the SDK — it is a free-text field with no format restriction enforced at the protocol level.

By contrast, the `makeTransfer` path calls `formatHbarTransfers`, which returns only hardcoded strings or account IDs formatted by the Hedera SDK:

```ts
return `${sender.accountId} --> ${stringifyHbarWithFont(receiver.amount)} --> ${receiver.accountId}`;
``` [2](#0-1) 

The `stringifyHbarWithFont` function likely returns HTML (hence the use of `v-html`), but account IDs are SDK-structured values. The description and memo paths, however, are fully attacker-controlled strings rendered as raw HTML.

The rest of the codebase correctly uses Vue's `{{ }}` interpolation (which auto-escapes) for similar fields — for example, the Transaction Details page renders `transactionMemo` safely:

```vue
{{ sdkTransaction.transactionMemo }}
``` [3](#0-2) 

And the email templates use `escapeHtml()` consistently: [4](#0-3) 

The `CreateTransactionGroup.vue` `v-html` usage is the isolated exception.

### Impact Explanation

This is a **Stored XSS** vulnerability in an Electron desktop application. The impact is elevated compared to browser-based XSS:

- **Personal mode**: A user who imports a crafted `.htx` transaction file or draft containing a malicious description/memo will trigger script execution in their own Electron renderer when they open the Create Transaction Group view.
- **Organization mode**: A malicious organization member (or a compromised account) can create a transaction with a payload in the `description` field (e.g., `<img src=x onerror="require('child_process').exec('calc.exe')">`). Every other organization member who opens the group view will execute the payload.
- In Electron, if `nodeIntegration` is enabled in the renderer, XSS escalates directly to **Remote Code Execution** on the victim's machine. Even with `contextIsolation`, the attacker can manipulate the UI, exfiltrate locally stored keys or session tokens via IPC, or perform actions on behalf of the victim.

### Likelihood Explanation

- The attack surface is reachable by any authenticated organization member who can create a transaction (a normal, non-privileged role).
- The payload is stored server-side and triggers automatically when any other user opens the group view — no social engineering beyond normal app usage is required.
- The `description` field has no length or format validation that would prevent HTML injection.
- The `transactionMemo` path is also exploitable by importing a crafted transaction file, which is a documented feature of the application.

### Recommendation

1. Replace `v-html` with `{{ }}` interpolation for all user-controlled text fields (`groupItem.description`, `transactionMemo`, `createTransactionId` output). If `v-html` is required for the `makeTransfer` path (due to `stringifyHbarWithFont` returning HTML), split the ternary into separate elements:

```vue
<span v-if="groupItem.type == 'Transfer Transaction'" v-html="makeTransfer(index)"></span>
<span v-else>{{ groupItem.description || sdkTransaction.transactionMemo || ... }}</span>
```

2. Audit all other `v-html` usages in the codebase for similar patterns.
3. Enforce `contextIsolation: true` and `nodeIntegration: false` in the Electron `BrowserWindow` configuration to limit XSS blast radius.

### Proof of Concept

1. In organization mode, create a new transaction with the **Description** field set to:
   ```
   <img src=x onerror="alert(document.cookie)">
   ```
2. Add the transaction to a group and save it.
3. Any organization member who navigates to **Create Transaction Group** and loads the group will see the JavaScript execute — the `v-html` binding at line 421–429 of `CreateTransactionGroup.vue` injects the description directly into the DOM.

Alternatively, craft a Hedera transaction bytes blob with `transactionMemo` set to the same payload, import it as a draft, and add it to a group. The memo path at line 426–427 will render it identically. [5](#0-4)

### Citations

**File:** front-end/src/renderer/pages/CreateTransactionGroup/CreateTransactionGroup.vue (L418-430)
```vue
              <div
                class="align-self-center text-truncate col text-center mx-5"
                :data-testid="'span-transaction-timestamp-' + index"
                v-html="
                  groupItem.type == 'Transfer Transaction'
                    ? makeTransfer(index)
                    : groupItem.description != ''
                      ? groupItem.description
                      : Transaction.fromBytes(groupItem.transactionBytes).transactionMemo
                        ? Transaction.fromBytes(groupItem.transactionBytes).transactionMemo
                        : createTransactionId(groupItem.payerAccountId, groupItem.validStart)
                "
              ></div>
```

**File:** front-end/src/renderer/utils/transferTransactions.ts (L29-29)
```typescript
    return `${sender.accountId} --> ${stringifyHbarWithFont(receiver.amount)} --> ${receiver.accountId}`;
```

**File:** front-end/src/renderer/pages/TransactionDetails/TransactionDetails.vue (L507-507)
```vue
                  {{ sdkTransaction.transactionMemo }}
```

**File:** back-end/libs/common/src/templates/layout.ts (L130-143)
```typescript
export function escapeHtml(str: string | null | undefined): string {
  if (str == null) {
    return "";
  }

  const value = String(str);

  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
```
