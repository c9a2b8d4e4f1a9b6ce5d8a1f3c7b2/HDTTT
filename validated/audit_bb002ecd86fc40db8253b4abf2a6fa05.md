Audit Report

## Title
HTML Injection via `v-html` Rendering of Untrusted `groupItem.description` and `transactionMemo` in Transaction Group View

## Summary
In `front-end/src/renderer/pages/CreateTransactionGroup/CreateTransactionGroup.vue`, user-controlled fields `groupItem.description` and `Transaction.fromBytes(groupItem.transactionBytes).transactionMemo` are rendered directly into the DOM via Vue's `v-html` directive without any HTML sanitization. In an organization context, a malicious member can craft a transaction with a description or memo containing arbitrary HTML, which executes in the Electron renderer of any other member who opens the Create Transaction Group page.

## Finding Description
The vulnerable binding is confirmed at lines 421–429 of `CreateTransactionGroup.vue`: [1](#0-0) 

```html
<div
  class="align-self-center text-truncate col text-center mx-5"
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

Vue's `v-html` sets `innerHTML` directly, bypassing the automatic HTML escaping that `{{ }}` mustache interpolation provides. Both user-controlled branches are unescaped:

**Branch 1 — `groupItem.description`:** Set via `TransactionInfoControls.vue`, which accepts up to 256 characters with no HTML encoding applied. [2](#0-1) 

**Branch 2 — `transactionMemo`:** Set via `BaseTransaction.vue`, validated only for length (100 chars) via `validate100CharInput`, with no HTML sanitization. [3](#0-2) 

The description is stored in the backend PostgreSQL database and served to all organization members. When a victim opens the Create Transaction Group page and the group contains a transaction with a malicious description, the payload is injected into their DOM.

## Impact Explanation
In an Electron application, HTML injection via `v-html` is equivalent to stored XSS. Even with `contextIsolation` enabled, a successful injection can:

- **Misrepresent transaction details at signing time:** A payload like `<b style="color:red">Transfer 1000 HBAR to attacker</b>` replaces the legitimate transaction summary in the group list, deceiving the signer about what they are approving. This is a concrete, immediate impact.
- **Steal sensitive data** visible in the renderer (private key nicknames, account IDs, session tokens displayed on screen) via injected `<script>` tags or event handlers.
- **Manipulate the DOM** to alter displayed amounts, recipient addresses, or approval UI elements.
- If `nodeIntegration` is enabled or `contextBridge` is misconfigured, escalate to arbitrary Node.js/OS code execution.

## Likelihood Explanation
Any authenticated organization member can create a transaction with a crafted description or memo — no elevated privileges are required. The attack is triggered passively when any other member opens the Create Transaction Group page. In a multi-member organization (the primary use case of this tool), this is a realistic, low-effort, stored attack. The SECURITY.md explicitly does **not** exclude persistent HTML injection: [4](#0-3) 

> "This does not exclude reflected HTML injection with or without JavaScript."
> "This does not exclude persistent plain text injection."

This is persistent (stored) HTML injection, which is squarely in scope.

## Recommendation
Replace `v-html` with safe text interpolation. Since the description and memo are plain-text fields, there is no legitimate need to render them as HTML:

```html
<!-- Replace v-html with a computed plain-text binding -->
<div
  class="align-self-center text-truncate col text-center mx-5"
  :data-testid="'span-transaction-timestamp-' + index"
>{{ resolveGroupItemLabel(groupItem, index) }}</div>
```

Move the ternary logic into a computed method `resolveGroupItemLabel` that returns a plain string. Vue's `{{ }}` interpolation automatically HTML-escapes the output, neutralizing any injected markup.

If rich HTML rendering is genuinely required for the `makeTransfer` branch, sanitize the output with a library such as [DOMPurify](https://github.com/cure53/DOMPurify) before passing it to `v-html`.

Additionally, enforce server-side validation that rejects HTML tags in the `description` and `transactionMemo` fields before they are persisted to the database.

## Proof of Concept

1. Attacker (authenticated org member) creates a new transaction and sets the **Transaction Description** to:
   ```
   <img src=x onerror="document.title='PWNED:'+document.cookie">
   ```
2. Attacker adds this transaction to a shared transaction group and submits it to the organization.
3. Victim (another org member) opens the **Create Transaction Group** page and loads the group.
4. The `v-html` binding at line 421 of `CreateTransactionGroup.vue` sets `innerHTML` to the attacker's payload.
5. The browser executes the `onerror` handler, demonstrating arbitrary JavaScript execution in the victim's Electron renderer context.
6. A more targeted payload can silently replace the displayed transfer amount/recipient in the group list, causing the victim to sign a transaction they believe is different from what is actually submitted.

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

**File:** front-end/src/renderer/components/Transaction/TransactionInfoControls.vue (L40-47)
```vue
      <AppTextArea
        :model-value="description"
        @update:model-value="v => $emit('update:description', v)"
        :filled="true"
        :limit="256"
        placeholder="Enter a description for the transaction"
        data-testid="input-transaction-description"
      />
```

**File:** front-end/src/renderer/components/Transaction/Create/BaseTransaction/BaseTransaction.vue (L250-258)
```vue
function handleInputValidation(e: Event) {
  const target = e.target as HTMLInputElement;
  try {
    validate100CharInput(target.value, 'Transaction Memo');
    memoError.value = false;
  } catch (error) {
    toastManager.error(getErrorMessage(error, 'Invalid Transaction Memo'));
    memoError.value = true;
  }
```

**File:** SECURITY.md (L33-35)
```markdown
- Reflected plain text injection (e.g. URL parameters, path, etc.).
- This does not exclude reflected HTML injection with or without JavaScript.
- This does not exclude persistent plain text injection.
```
