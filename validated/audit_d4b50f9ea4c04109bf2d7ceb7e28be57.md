### Title
Recovery Phrase Written to System Clipboard in Plaintext via Explicit Copy Buttons

### Summary
The Hedera Transaction Tool desktop application exposes the 24-word recovery phrase (mnemonic) to the system clipboard in plaintext through two separate UI flows: account setup onboarding and migration summary. Any process running on the same machine can read the clipboard contents, enabling silent exfiltration of the most sensitive credential the application manages.

### Finding Description
Two distinct code paths write the full recovery phrase to the system clipboard:

**Path 1 — Account Setup (Onboarding):**
`front-end/src/renderer/pages/AccountSetup/components/Generate.vue`, function `handleCopyRecoveryPhrase` at lines 92–94:

```js
const handleCopyRecoveryPhrase = () => {
  navigator.clipboard.writeText(words.value.join(', '));
  toastManager.success('Recovery phrase copied');
};
```

This is bound to a "Copy" button rendered at line 188 of the same file, visible to the user immediately after phrase generation during onboarding. [1](#0-0) 

**Path 2 — Migration Summary:**
`front-end/src/renderer/pages/Migrate/components/Summary.vue`, function `copyRecoveryPhrase` at lines 62–66:

```js
const copyRecoveryPhrase = () => {
  const recoveryPhrase = user.recoveryPhrase?.words.join(', ') || '';
  navigator.clipboard.writeText(recoveryPhrase).then(() => {
    toastManager.success('Recovery phrase copied to clipboard');
  });
};
```

This is bound to a copy icon button rendered at lines 162–168 of the same file, displayed alongside the full plaintext recovery phrase in the migration summary view. [2](#0-1) 

In both cases, `navigator.clipboard.writeText()` places the full space/comma-separated 24-word mnemonic into the OS-level clipboard with no expiry, no clearing, and no warning. The clipboard persists until overwritten.

### Impact Explanation
The recovery phrase is the root secret from which all Hedera key pairs in the wallet are derived. Compromise of the recovery phrase gives an attacker full, permanent control over every key and account derived from it. Any process running on the same machine — including browser extensions, productivity software, clipboard managers, or malware — can silently read the clipboard at any time after the user clicks "Copy." The data remains in the clipboard indefinitely. This constitutes complete, irrecoverable loss of all assets controlled by keys derived from the phrase.

### Likelihood Explanation
The copy buttons are prominently placed in two high-traffic flows (initial onboarding and migration). Clipboard managers are extremely common on desktop operating systems and persist clipboard history by default. Many legitimate applications (e.g., password managers, note-taking apps, cloud sync tools) read clipboard content. A malicious or compromised background process requires no elevated privileges to call the OS clipboard API. The user action (clicking "Copy") is explicitly invited by the UI, making this a realistic, high-frequency exposure path rather than an edge case.

### Recommendation
- **Short term:** Remove both copy buttons entirely. Do not write the recovery phrase to the system clipboard under any circumstances.
- **Short term:** In the onboarding flow (`Generate.vue`), enforce phrase backup by requiring the user to manually retype a random subset of words (a verification step already partially implemented via `handleProceedToVerification`) rather than offering a clipboard shortcut.
- **Long term:** Audit all other `navigator.clipboard.writeText` call sites (confirmed also in `KeysTab.vue` for private keys) and apply the same restriction to any other high-sensitivity secrets.

### Proof of Concept

1. Launch the Hedera Transaction Tool and begin account setup.
2. Click "Generate" to produce a new 24-word recovery phrase.
3. Click the "Copy" button (rendered at `Generate.vue` line 188).
4. From any other process on the same machine, read the clipboard:
   ```js
   // Node.js / Electron renderer in another app
   const { clipboard } = require('electron');
   console.log(clipboard.readText());
   // Output: "word1, word2, word3, ... word24"
   ```
   Or on Linux/macOS from a terminal: `xclip -o -selection clipboard` / `pbpaste`
5. The full plaintext recovery phrase is returned with no authentication, no prompt, and no time limit.

The same steps apply to the migration summary flow via `Summary.vue` `copyRecoveryPhrase()`. [3](#0-2) [4](#0-3)

### Citations

**File:** front-end/src/renderer/pages/AccountSetup/components/Generate.vue (L92-95)
```vue
const handleCopyRecoveryPhrase = () => {
  navigator.clipboard.writeText(words.value.join(', '));
  toastManager.success('Recovery phrase copied');
};
```

**File:** front-end/src/renderer/pages/AccountSetup/components/Generate.vue (L184-191)
```vue
        <AppButton
          v-if="words.filter(w => w).length !== 0"
          color="secondary"
          data-testid="button-copy"
          @click="handleCopyRecoveryPhrase"
          class="ms-4"
          ><i class="bi bi-copy"></i> <span>Copy</span></AppButton
        >
```

**File:** front-end/src/renderer/pages/Migrate/components/Summary.vue (L62-67)
```vue
const copyRecoveryPhrase = () => {
  const recoveryPhrase = user.recoveryPhrase?.words.join(', ') || '';
  navigator.clipboard.writeText(recoveryPhrase).then(() => {
    toastManager.success('Recovery phrase copied to clipboard');
  });
};
```

**File:** front-end/src/renderer/pages/Migrate/components/Summary.vue (L161-168)
```vue
        <div class="position-relative">
          <AppButton
            color="primary"
            class="min-w-unset position-absolute top-0 end-0 m-2 py-1 px-3"
            @click="copyRecoveryPhrase"
          >
            <i class="bi bi-files"></i>
          </AppButton>
```
