### Title
Plaintext Recovery Phrase Retained in Pinia Store Memory for Entire Session and Written Uncleared to Clipboard

### Summary

The `RecoveryPhrase` object stored in the global Pinia `storeUser` contains the full plaintext mnemonic word array (`words: string[]`) and the raw `Mnemonic` SDK object. Once set via `setRecoveryPhrase()`, this data persists in the Electron renderer process heap for the entire user session. Multiple flows — including key generation and hash migration — do not clear it after completing their operations. Additionally, the "Copy" button writes the full phrase to the system clipboard without ever clearing it. An attacker with code execution on the same machine (e.g., malware) can dump the V8 heap of the renderer process or read the clipboard to extract the plaintext mnemonic and take full control of the user's Hedera keys.

---

### Finding Description

**Root cause — plaintext mnemonic stored in Pinia reactive state:**

`RecoveryPhrase` is defined as:

```typescript
export type RecoveryPhrase = {
  mnemonic: Mnemonic;   // full SDK object
  words: string[];      // plaintext word array
  hash: string;
};
``` [1](#0-0) 

`createRecoveryPhrase()` constructs this object and stores both the `Mnemonic` SDK object and the raw `words` array: [2](#0-1) 

The result is assigned to the Pinia store's reactive ref: [3](#0-2) 

and exported globally: [4](#0-3) 

**Code paths that do NOT clear `recoveryPhrase` after completing their operation:**

1. **`Generate.vue` — `handleGenerate()`**: After the user completes account setup (generates + verifies the phrase), the function calls `handleNext()` and navigates forward without clearing `user.recoveryPhrase`. The phrase remains in the store for the rest of the session. [5](#0-4) 

2. **`Generate.vue` — `correctWords` ref**: The full mnemonic is also held in a component-level `correctWords` ref that is never zeroed on unmount. [6](#0-5) 

3. **`MigrateRecoveryPhraseHash.vue` — `handleContinue()`**: After updating key hashes, the function navigates to `transactions` without clearing `user.recoveryPhrase`. [7](#0-6) 

**Clipboard exposure — `handleCopyRecoveryPhrase()`:**

The "Copy" button writes the entire 24-word phrase to the system clipboard as a comma-separated string. The clipboard is never cleared afterward. [8](#0-7) 

**`logout()` does clear `recoveryPhrase`**, but only on explicit logout — not after completing individual key operations: [9](#0-8) 

This means the plaintext mnemonic lives in the renderer process heap from the moment it is set until the user explicitly logs out.

---

### Impact Explanation

The Electron renderer process is a Chromium process with an inspectable V8 heap. Any process on the same machine with sufficient OS-level permissions (e.g., malware, a compromised dependency, or a process running as the same OS user) can:

1. Attach to the renderer process via the V8 inspector or OS memory APIs.
2. Dump the heap and search for the 24-word BIP-39 phrase.
3. Use the recovered mnemonic to derive all Ed25519/ECDSA private keys and drain any associated Hedera accounts.

The clipboard vector is even simpler: any process or browser tab can read the clipboard after the user clicks "Copy," with no memory forensics required.

**Impact: Critical** — full, permanent loss of all keys derived from the exposed mnemonic.

---

### Likelihood Explanation

This is a desktop Electron application targeting Hedera Council members managing high-value accounts. The threat of malware on a developer or operator workstation is realistic and well-documented. The attacker does not need to compromise the application itself — only the OS user session. The clipboard vector requires no special privileges at all. The phrase is retained in memory for the entire session (potentially hours), maximizing the window of exposure.

**Likelihood: Medium** — requires local code execution or clipboard access, but no application-level privileges.

---

### Recommendation

1. **Clear `user.recoveryPhrase` immediately after it is no longer needed.** In `Generate.vue`, call `user.setRecoveryPhrase(null)` inside `handleGenerate()` after `handleNext()` resolves. Apply the same pattern in `MigrateRecoveryPhraseHash.vue`'s `handleContinue()`.

2. **Zero `correctWords` and `words` refs on component unmount** using `onUnmounted(() => { words.value = Array(24).fill(''); correctWords.value = Array(24).fill(''); })` in `Generate.vue`.

3. **Do not store `words: string[]` in the `RecoveryPhrase` type.** Store only the `hash` for comparison purposes. Reconstruct the `Mnemonic` object on demand from a short-lived local variable and discard it immediately after use.

4. **Clear the clipboard after copying.** Schedule `navigator.clipboard.writeText('')` with a short timeout (e.g., 30 seconds) after `handleCopyRecoveryPhrase()` executes.

5. **Do not store the raw `Mnemonic` SDK object** in the Pinia store. The `mnemonic` field in `RecoveryPhrase` holds a full SDK object that internally retains the entropy/words; removing it from the store reduces the heap footprint of sensitive data.

---

### Proof of Concept

**Heap dump path:**

1. Launch the Electron app with `--inspect` or attach to the renderer process PID via `chrome://inspect`.
2. Log in and navigate to Account Setup → Generate a recovery phrase.
3. Complete the verification step and proceed to the transactions view.
4. In the V8 inspector, take a heap snapshot.
5. Search the snapshot for any of the 24 BIP-39 words. The full `words` array is reachable from the `storeUser` Pinia store's `recoveryPhrase` reactive ref, which is a root-level GC reference and will not be collected.

**Clipboard path:**

1. Log in and navigate to Account Setup → Generate a recovery phrase.
2. Click the "Copy" button (`handleCopyRecoveryPhrase`).
3. From any other process or browser tab, read `navigator.clipboard.readText()` or the OS clipboard API.
4. The full 24-word phrase is returned as a comma-separated string with no expiry.

### Citations

**File:** front-end/src/renderer/types/userStore.ts (L95-99)
```typescript
export type RecoveryPhrase = {
  mnemonic: Mnemonic;
  words: string[];
  hash: string;
};
```

**File:** front-end/src/renderer/utils/userStoreHelpers.ts (L118-131)
```typescript
export const createRecoveryPhrase = async (words: string[]): Promise<RecoveryPhrase> => {
  try {
    const mnemonic = await Mnemonic.fromWords(words);
    const hash = await hashData(getRecoveryPhraseHashValue(words), true);

    return {
      mnemonic,
      words,
      hash,
    };
  } catch {
    throw Error('Invalid recovery phrase');
  }
};
```

**File:** front-end/src/renderer/stores/storeUser.ts (L48-48)
```typescript
  const recoveryPhrase: Ref<RecoveryPhrase|null> = ref(null);
```

**File:** front-end/src/renderer/stores/storeUser.ts (L88-98)
```typescript
  const logout = () => {
    personal.value = {
      isLoggedIn: false,
    };
    selectedOrganization.value = null;
    organizations.value = [];
    publicKeyToAccounts.value = [];
    keyPairs.value = [];
    recoveryPhrase.value = null;
    resetVersionCheck();
  };
```

**File:** front-end/src/renderer/stores/storeUser.ts (L272-272)
```typescript
    recoveryPhrase,
```

**File:** front-end/src/renderer/pages/AccountSetup/components/Generate.vue (L37-38)
```vue
const words = ref(Array(24).fill(''));
const correctWords = ref(Array(24).fill(''));
```

**File:** front-end/src/renderer/pages/AccountSetup/components/Generate.vue (L92-95)
```vue
const handleCopyRecoveryPhrase = () => {
  navigator.clipboard.writeText(words.value.join(', '));
  toastManager.success('Recovery phrase copied');
};
```

**File:** front-end/src/renderer/pages/AccountSetup/components/Generate.vue (L97-101)
```vue
const handleGenerate = async () => {
  if (user.recoveryPhrase === null) return;
  await recoveryPhraseNickname.set(user.recoveryPhrase.hash, mnemonicHashNickname.value);
  await props.handleNext();
};
```

**File:** front-end/src/renderer/pages/MigrateRecoveryPhraseHash/MigrateRecoveryPhraseHash.vue (L95-109)
```vue
const handleContinue = async () => {
  if (!user.recoveryPhrase) {
    return;
  }

  loadingText.value = 'Updating recovery phrase hash...';
  const { error } = await safeAwait(
    updateKeyPairsHash(keysToUpdate.value, user.recoveryPhrase.hash),
  );
  if (!error) {
    toastManager.success('Recovery phrase hash updated successfully');
    await router.push({ name: 'transactions' });
  }
  loadingText.value = null;
};
```
