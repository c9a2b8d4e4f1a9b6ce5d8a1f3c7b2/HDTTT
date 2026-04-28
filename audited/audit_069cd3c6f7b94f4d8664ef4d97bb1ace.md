### Title
Electron `safeStorage` Keychain Mode Bypasses All User Authentication Before Transaction Signing

### Summary
When the macOS keychain mode is enabled, the application completely removes the application-level password gate before signing Hedera transactions. `electron.safeStorage` decrypts private keys silently with no user presence check (no Touch ID, no password prompt), while the non-keychain path explicitly requires a password. Any person with access to the running application session can sign arbitrary Hedera transactions without any authentication challenge.

### Finding Description

The application offers two modes for protecting private keys: password-based encryption and macOS keychain mode via Electron's `safeStorage` API.

**Root cause — password gate is explicitly disabled in keychain mode:**

In `SignPersonalRequestHandler.vue`, the authentication check reads:

```typescript
const password = user.getPassword();
if (!password && !user.personal.useKeychain) throw new Error('Password is required to sign');
```

When `useKeychain` is `true`, the condition short-circuits and the password check is skipped entirely. No alternative authentication (biometric, PIN, OS dialog) is substituted. [1](#0-0) 

**Root cause — `safeStorage.decryptString` is called with no user presence check:**

In the main-process `signTransaction`, when keychain mode is active:

```typescript
if (useKeychain) {
  const buffer = Buffer.from(keyPair.private_key, 'base64');
  decryptedPrivateKey = safeStorage.decryptString(buffer);   // silent, no prompt
}
``` [2](#0-1) 

Electron's `safeStorage` on macOS uses the system Keychain with accessibility set to `kSecAttrAccessibleAfterFirstUnlock` (or equivalent). It does **not** require Touch ID or a password confirmation per-operation; it decrypts silently for any code running as the same user once the session is unlocked. There is no `kSecAccessControlUserPresence` flag or equivalent enforced.

The same silent-decrypt pattern is repeated in `decryptPrivateKey`: [3](#0-2) 

And in `decryptData` for organization credentials: [4](#0-3) 

**Contrast with password mode:** In password mode, `decrypt(keyPair.private_key, userPassword)` is called, and `userPassword` must be non-null or an exception is thrown. The password is a runtime secret that must be actively supplied. In keychain mode, the decryption key is permanently accessible to the running process with zero user interaction. [5](#0-4) 

**Keychain mode is a first-class, user-facing option** presented at login on macOS: [6](#0-5) 

### Impact Explanation

An attacker who gains access to the running application session (unlocked macOS machine with the app open) can:

1. Open the transaction signing UI.
2. Select any pending or new Hedera transaction.
3. Click "Sign" — no password dialog appears, no biometric prompt fires.
4. The private key is silently decrypted from the Keychain and the transaction is signed and submitted to the Hedera network.

This enables unauthorized signing of account transfers, account updates, file operations, and any other Hedera transaction type the stored keys are authorized for. The impact is direct asset movement or unauthorized state change on the Hedera network.

### Likelihood Explanation

- Keychain mode is explicitly advertised and enabled by users who prefer convenience over password entry — exactly the population most likely to leave the app open and walk away.
- The attacker precondition is access to an unlocked macOS session with the app running — a realistic office/shared-workspace scenario requiring no privileged credentials, no network access, and no cryptographic break.
- The vulnerability is always present once keychain mode is initialized; it is not conditional on any configuration flag or race condition.

### Recommendation

Require explicit user presence before each signing operation when keychain mode is active. On macOS this means storing the signing key with `kSecAccessControlUserPresence` (Touch ID / device password required per access) rather than relying on the default `safeStorage` accessibility level. At minimum, present a native OS authentication dialog (e.g., `systemPreferences.promptTouchID` or `LocalAuthentication`) before calling `safeStorage.decryptString` for any signing operation. The security level must be set explicitly and not left to the library default, which is subject to change.

### Proof of Concept

**Preconditions:** macOS machine, app initialized in keychain mode (`useKeychain = true`), user session unlocked, app running.

1. User A sets up the app with keychain mode and stores a private key. User A walks away from the unlocked machine.
2. Attacker sits at the machine. The app is already open and the session is active.
3. Attacker navigates to any transaction creation or pending transaction signing screen.
4. Attacker clicks "Sign Transaction."
5. `SignPersonalRequestHandler.sign()` is called → `user.personal.useKeychain` is `true` → password check at line 67 is skipped → `signTransaction(...)` is called with `password = null`.
6. In the main process, `signTransaction` calls `safeStorage.decryptString(buffer)` → private key is returned silently → `transaction.sign(privateKey)` is called → signed bytes are returned.
7. The transaction is submitted to the Hedera network. No password, no biometric, no OS dialog was shown at any point.

### Citations

**File:** front-end/src/renderer/components/Transaction/TransactionProcessor/components/SignPersonalRequestHandler.vue (L66-67)
```vue
  const password = user.getPassword();
  if (!password && !user.personal.useKeychain) throw new Error('Password is required to sign');
```

**File:** front-end/src/main/services/localUser/transactions.ts (L115-117)
```typescript
    if (useKeychain) {
      const buffer = Buffer.from(keyPair.private_key, 'base64');
      decryptedPrivateKey = safeStorage.decryptString(buffer);
```

**File:** front-end/src/main/services/localUser/transactions.ts (L118-122)
```typescript
    } else if (userPassword) {
      decryptedPrivateKey = decrypt(keyPair.private_key, userPassword);
    } else {
      throw new Error('Password is required to decrypt private key');
    }
```

**File:** front-end/src/main/services/localUser/keyPairs.ts (L139-141)
```typescript
  if (useKeychain) {
    const buffer = Buffer.from(keyPair?.private_key || '', 'base64');
    return safeStorage.decryptString(buffer);
```

**File:** front-end/src/main/services/localUser/organizationCredentials.ts (L314-317)
```typescript
  const useKeychain = await getUseKeychainClaim();
  if (useKeychain) {
    const buffer = Buffer.from(data, 'base64');
    return safeStorage.decryptString(buffer);
```

**File:** front-end/src/renderer/pages/UserLogin/components/KeychainOption.vue (L27-36)
```vue
const handleUseKeychain = async () => {
  await initializeUseKeychain(true);

  await encrypt('gain_access');
  const staticUser = await getStaticUser();
  user.setAccountSetupStarted(true);
  await user.login(staticUser.id, staticUser.email, true);
  await user.refetchOrganizations();
  await setupStores();
};
```
