### Title
Unprotected Full-Plaintext Copy of Recovery Phrase and Private Key to System Clipboard

### Summary
The application provides explicit "Copy" buttons that write the complete 24-word recovery phrase and decrypted private key as a single plaintext string to the system clipboard via `navigator.clipboard.writeText()`. No warning is shown, no auto-clear timer is set, and the sensitive material persists in the clipboard indefinitely. Any process, clipboard manager, or cloud sync service (e.g., iCloud Clipboard, Windows Clipboard History) with clipboard access can silently exfiltrate the full secret.

### Finding Description
Three distinct code paths write high-value secrets to the clipboard without any protective measures:

**1. Recovery phrase copy during account setup**
`front-end/src/renderer/pages/AccountSetup/components/Generate.vue`, `handleCopyRecoveryPhrase()` (lines 92–95):
```js
const handleCopyRecoveryPhrase = () => {
  navigator.clipboard.writeText(words.value.join(', '));
  toastManager.success('Recovery phrase copied');
};
```
The full 24-word mnemonic is joined into a single comma-separated string and written to the clipboard. No warning is displayed; only a success toast is shown. [1](#0-0) 

**2. Recovery phrase copy during migration summary**
`front-end/src/renderer/pages/Migrate/components/Summary.vue`, `copyRecoveryPhrase()` (lines 62–67):
```js
const copyRecoveryPhrase = () => {
  const recoveryPhrase = user.recoveryPhrase?.words.join(', ') || '';
  navigator.clipboard.writeText(recoveryPhrase).then(() => {
    toastManager.success('Recovery phrase copied to clipboard');
  });
};
```
Same pattern — full mnemonic, no warning, no auto-clear. [2](#0-1) 

**3. Decrypted private key copy in the Keys settings tab**
`front-end/src/renderer/pages/Settings/components/KeysTab/KeysTab.vue`, `handleCopy()` (lines 134–137), invoked from the private-key copy icon (lines 362–368):
```js
const handleCopy = (text: string, message: string) => {
  navigator.clipboard.writeText(text);
  toastManager.success(message);
};
```
After the user decrypts a private key (which requires their password), a copy icon is rendered next to the revealed key. Clicking it writes the raw private key string to the clipboard with no warning. [3](#0-2) [4](#0-3) 

In all three cases the clipboard is never cleared, no risk warning is presented, and the data is written as a single contiguous string rather than in split/partial form.

### Impact Explanation
The system clipboard is a shared, process-wide resource. Once the mnemonic or private key is written there it is accessible to:
- Any background process or application running under the same OS user account (password managers, screenshot tools, clipboard managers).
- Cloud clipboard sync services enabled by default on many platforms (iCloud Clipboard on macOS/iOS, Windows Clipboard History with sync, Android/Chrome clipboard sync), which transmit the secret to remote servers and linked devices.
- Malicious browser extensions or Electron renderer-context scripts that can call `navigator.clipboard.readText()`.

A full 24-word BIP-39 mnemonic gives complete, irrevocable control over all keys derived from it. A raw ED25519 or ECDSA private key gives direct signing authority over the associated Hedera account. Compromise of either results in total loss of funds and account control.

### Likelihood Explanation
The copy buttons are prominent, first-class UI elements presented to every user during the normal account setup and key management workflows. Users are implicitly encouraged to use them. The attack requires no special attacker capability beyond running any process on the same machine as the victim — a realistic condition for malware, browser extensions, or shared-device scenarios. Cloud clipboard sync is enabled by default on many consumer devices, making remote exfiltration trivially automatic without any active attacker presence on the local machine.

### Recommendation
1. **Remove or gate the one-click full-copy buttons** for the mnemonic and private key. If copy functionality must be retained, split the secret across multiple sequential copy operations (e.g., copy words 1–12, then 13–24) so the full secret never exists as a single clipboard entry.
2. **Auto-clear the clipboard** after a short timeout (e.g., 30 seconds) using a follow-up `navigator.clipboard.writeText('')` call scheduled via `setTimeout`.
3. **Display an explicit risk warning** before writing to the clipboard, informing the user that clipboard contents may be synced to other devices or read by other applications, and advising them to clear the clipboard immediately after use.
4. **Prefer manual transcription UX** — display the phrase in a read-only grid and instruct users to write it down, rather than providing a programmatic copy path.

### Proof of Concept
1. Open the application and navigate to account setup → Generate Recovery Phrase.
2. Generate a 24-word mnemonic; the "Copy" button (`button-copy`) becomes visible.
3. Click "Copy". `handleCopyRecoveryPhrase()` executes `navigator.clipboard.writeText(words.value.join(', '))`.
4. Open any text editor or run `xclip -o` / `pbpaste` / `Get-Clipboard` in a terminal — the full mnemonic is present in plaintext.
5. If iCloud Clipboard or Windows Clipboard History with sync is enabled, the mnemonic is now transmitted to Apple/Microsoft servers and all linked devices without any further user action.
6. Repeat steps 1–5 via Settings → Keys → reveal a private key → click the copy icon (`span-copy-private-key-{index}`); the raw private key string is identically exposed.

### Citations

**File:** front-end/src/renderer/pages/AccountSetup/components/Generate.vue (L92-95)
```vue
const handleCopyRecoveryPhrase = () => {
  navigator.clipboard.writeText(words.value.join(', '));
  toastManager.success('Recovery phrase copied');
};
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

**File:** front-end/src/renderer/pages/Settings/components/KeysTab/KeysTab.vue (L134-137)
```vue
const handleCopy = (text: string, message: string) => {
  navigator.clipboard.writeText(text);
  toastManager.success(message);
};
```

**File:** front-end/src/renderer/pages/Settings/components/KeysTab/KeysTab.vue (L359-369)
```vue
                    <span
                      :data-testid="`span-copy-private-key-${index}`"
                      class="bi bi-copy cursor-pointer ms-3"
                      @click="
                        handleCopy(
                          decryptedKeys.find(kp => kp.publicKey === keyPair.public_key)
                            ?.decrypted || '',
                          'Private Key copied successfully',
                        )
                      "
                    ></span>
```
