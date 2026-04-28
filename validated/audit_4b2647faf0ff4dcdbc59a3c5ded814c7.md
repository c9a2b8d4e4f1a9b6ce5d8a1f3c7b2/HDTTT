### Title
`v-html` with User-Controlled Transaction Data Enables Stored XSS in Transaction Group View

### Summary
`CreateTransactionGroup.vue` uses Vue's `v-html` directive to render `groupItem.description` and `transactionMemo` — both of which are user-controlled strings — without any sanitization. This is the direct Vue analog of the `dangerouslySetInnerHTML` misuse described in the external report. In organization mode, a malicious member can store an HTML payload in a transaction group description or transaction memo, which executes in any co-member's renderer process when they open the group.

### Finding Description

**Root cause — `v-html` on unsanitized user data:** [1](#0-0) 

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

The directive evaluates to one of three attacker-reachable strings in priority order:

1. **`groupItem.description`** — free-text entered by any user when creating a transaction group item. Stored in the backend database and fetched by `handleLoadGroup()` via `transactionGroup.fetchGroup(route.query.id, ...)`.
2. **`transactionMemo`** — the memo field of a Hedera transaction, decoded from `groupItem.transactionBytes`. An attacker can craft a Hedera transaction with an HTML payload in the memo and import it into the tool.

The group is loaded from the backend when another user opens the same group: [2](#0-1) 

Neither `groupItem.description` nor `transactionMemo` is sanitized before being passed to `v-html`.

A secondary instance exists in `AppStepper.vue`, where `getBubbleContent` interpolates the caller-supplied `item.bubbleIcon` prop directly into an HTML string that is then rendered via `v-html`: [3](#0-2) [4](#0-3) 

### Impact Explanation

This is an Electron desktop application. The renderer process runs in a Chromium context. Successful XSS in the renderer:

- **At minimum**: executes arbitrary JavaScript in the victim's renderer, enabling exfiltration of locally stored private key material, session tokens, and organization credentials visible to the renderer.
- **Potentially RCE**: if `nodeIntegration` or `contextIsolation: false` is set in the `BrowserWindow` options, the injected script gains full Node.js access, enabling file system reads/writes, process spawning, and complete host compromise.

For a tool that manages Hedera signing keys and submits financial transactions, key exfiltration directly enables unauthorized asset transfers.

### Likelihood Explanation

**Organization mode** is an explicitly supported workflow where multiple users share transaction groups. Any authenticated organization member can:
- Create a transaction group with a malicious `description` field.
- Import a crafted `.tx` file whose `transactionMemo` contains HTML.

The victim only needs to open the shared group for editing — a routine action. No social engineering beyond normal collaboration is required. The attacker needs only a valid organization account, which is a low privilege bar.

### Recommendation

1. **Remove `v-html` entirely** from the transaction group row. Replace it with a plain text binding (`{{ }}`) since neither `description` nor `transactionMemo` is ever expected to contain HTML:

```vue
<div ...>{{ displayText }}</div>
```

2. If rich rendering is genuinely required, sanitize with a library such as `DOMPurify` before passing to `v-html`:

```js
import DOMPurify from 'dompurify';
// ...
v-html="DOMPurify.sanitize(displayText)"
```

3. In `AppStepper.vue`, replace the string-interpolated HTML in `getBubbleContent` with conditional slot/component rendering so that `bubbleIcon` is never interpolated into raw HTML.

4. Audit `BrowserWindow` creation options to confirm `contextIsolation: true` and `nodeIntegration: false` are enforced, limiting blast radius if XSS occurs.

### Proof of Concept

1. Log in to the application as an organization member (Attacker).
2. Create a new Transaction Group. In the description field of any transaction item, enter:
   ```
   <img src=x onerror="alert(document.cookie)">
   ```
3. Save the group to the organization backend.
4. Log in as a second organization member (Victim) and open the same group for editing.
5. The `v-html` directive renders the description as HTML; the `onerror` handler fires, demonstrating arbitrary JavaScript execution in the victim's renderer process.

For the `transactionMemo` path: craft a Hedera transaction with the memo set to the same payload, serialize it to bytes, import it into a transaction group, and share the group. The memo is decoded and rendered via `v-html` when the group is opened.

### Citations

**File:** front-end/src/renderer/pages/CreateTransactionGroup/CreateTransactionGroup.vue (L154-172)
```vue
const handleLoadGroup = async () => {
  if (!route.query.id) {
    // transactionGroup.clearGroup();
    return;
  }

  assertUserLoggedIn(user.personal);

  await transactionGroup.fetchGroup(route.query.id.toString(), {
    where: {
      user_id: user.personal.id,
      GroupItem: {
        every: {
          transaction_group_id: route.query.id.toString(),
        },
      },
    },
  });
};
```

**File:** front-end/src/renderer/pages/CreateTransactionGroup/CreateTransactionGroup.vue (L420-430)
```vue
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

**File:** front-end/src/renderer/components/ui/AppStepper.vue (L31-33)
```vue
    if (item.bubbleIcon) {
      return `<i class="bi bi-${item.bubbleIcon}"></i>`;
    } else if (item.bubbleLabel) {
```

**File:** front-end/src/renderer/components/ui/AppStepper.vue (L58-59)
```vue
              v-html="getBubbleContent(index, item)"
            ></div>
```
