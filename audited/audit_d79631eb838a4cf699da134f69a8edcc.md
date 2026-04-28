### Title
Incoherent Boolean Return Value in `checkTokenValidity()` — Returns "Tokens Valid" When User Is Not Logged In

### Summary
`checkTokenValidity()` in `front-end/src/renderer/composables/useAppVisibility.ts` returns `true` (semantically "tokens are valid") when the user is **not** logged in. This mirrors the exact vulnerability class from the external report: a state-checking function returns an affirmative/present value for the condition it is supposed to detect as absent.

### Finding Description
In `useAppVisibility.ts`, the exported function `checkTokenValidity()` has the following early-return guard:

```typescript
async function checkTokenValidity(): Promise<boolean> {
  if (!isUserLoggedIn(user.personal)) return true;
  ...
}
``` [1](#0-0) 

When `!isUserLoggedIn(user.personal)` is true — meaning the user has **no active session and no tokens** — the function returns `true`, which callers interpret as "all tokens are valid." This is semantically incoherent: a non-logged-in state has no tokens to validate, yet the function signals validity.

The return value is consumed by `handleVisibilityChange()`:

```typescript
const tokensValid = await checkTokenValidity();
if (!tokensValid) {
  // trigger re-authentication
} else {
  await user.refetchOrganizationTokens(); // called when tokensValid === true
}
``` [2](#0-1) 

`checkTokenValidity` is also **exported** from the composable's return value, making it callable by any consumer: [3](#0-2) 

### Impact Explanation
Any direct caller of the exported `checkTokenValidity()` that invokes it when the user is not logged in will receive `true` and conclude that all organization tokens are valid. This suppresses re-authentication flows (`onTokenExpired` callback or `refetchOrganizations`) that should fire when credentials are absent or expired. In the worst case, a user whose session has been cleared would not be prompted to re-authenticate into their organizations, leaving the UI in a stale authenticated-appearing state.

### Likelihood Explanation
The primary internal consumer `handleVisibilityChange()` has its own redundant guard at line 51 (`if (!isUserLoggedIn(user.personal)) return;`), which prevents the bug from manifesting in that specific path. [4](#0-3) 

However, because `checkTokenValidity` is exported and the composable is used in `GlobalAppProcesses.vue` with a custom `onTokenExpired` callback, any future or existing direct call to `checkTokenValidity()` in a non-logged-in context will silently return the wrong value. The likelihood is **medium** — the bug is latent and masked by the outer guard today, but is one refactor or new call-site away from being actively exploitable.

### Recommendation
Change the early-return to reflect the actual semantic: if the user is not logged in, there are no tokens to check, and the function should either return `false` (no valid tokens) or a distinct sentinel. The simplest fix consistent with the function's contract:

```typescript
async function checkTokenValidity(): Promise<boolean> {
  if (!isUserLoggedIn(user.personal)) return false; // no session = no valid tokens
  ...
}
```

Alternatively, remove the exported `checkTokenValidity` from the public API of the composable if it is only intended for internal use, preventing misuse by external callers.

### Proof of Concept

1. A component imports and calls `checkTokenValidity()` directly (it is exported from `useAppVisibility`).
2. The user's session has expired or been cleared — `isUserLoggedIn(user.personal)` returns `false`.
3. `checkTokenValidity()` hits line 29: `if (!isUserLoggedIn(user.personal)) return true;`
4. The caller receives `true` and concludes tokens are valid.
5. Re-authentication (`onTokenExpired` / `refetchOrganizations`) is never triggered.
6. The user continues operating with stale/absent organization credentials, and organization-mode API calls will fail silently or with confusing errors rather than prompting re-login. [5](#0-4)

### Citations

**File:** front-end/src/renderer/composables/useAppVisibility.ts (L28-41)
```typescript
  async function checkTokenValidity(): Promise<boolean> {
    if (!isUserLoggedIn(user.personal)) return true;

    const activeOrgs = user.organizations.filter(org => isOrganizationActive(org));

    for (const org of activeOrgs) {
      const shouldSignIn = await shouldSignInOrganization(user.personal.id, org.id);
      if (shouldSignIn) {
        return false;
      }
    }

    return true;
  }
```

**File:** front-end/src/renderer/composables/useAppVisibility.ts (L51-51)
```typescript
    if (!isUserLoggedIn(user.personal)) return;
```

**File:** front-end/src/renderer/composables/useAppVisibility.ts (L56-70)
```typescript
      const tokensValid = await checkTokenValidity();

      // Always refresh organization tokens to ensure sessionStorage is in sync
      // This handles cases where sessionStorage was cleared but DB tokens are still valid
      if (!tokensValid) {
        if (onTokenExpired) {
          // Delegate token expiry handling to the provided callback to avoid
          // triggering re-authentication flows twice (e.g., via refetchOrganizations watcher)
          await onTokenExpired();
        } else {
          await user.refetchOrganizations();
        }
      } else {
        await user.refetchOrganizationTokens();
      }
```

**File:** front-end/src/renderer/composables/useAppVisibility.ts (L87-90)
```typescript
  return {
    isCheckingTokens,
    checkTokenValidity,
  };
```
