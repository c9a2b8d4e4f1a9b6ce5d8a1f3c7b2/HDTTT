All three referenced files are confirmed in the repository. Let me verify the exact line numbers and logic before rendering a verdict.

**Verified facts from the code:**

1. `recoveryPhrase: Ref<RecoveryPhrase|null> = ref(null)` — confirmed at line 48 of `storeUser.ts`. [1](#0-0) 

2. `createRecoveryPhrase` returns `{ mnemonic, words, hash }` — confirmed at lines 123–127 of `userStoreHelpers.ts`. [2](#0-1) 

3. `handleSkip` calls `await user.setRecoveryPhrase(null)` before navigating — confirmed at line 51 of `MigrateRecoveryPhraseHash.vue`. [3](#0-2) 

4. `handleContinue` calls `router.push({ name: 'transactions' })` with **no** `setRecoveryPhrase(null)` call — confirmed at lines 95–109. [4](#0-3) 

5. `onMounted` clears the phrase on entry (line 127), confirming the developer's intent that the phrase should not persist beyond the operation. [5](#0-4) 

6. `handleImport` in `GenerateOrImport.vue` calls `props.handleNext()` without clearing — confirmed at lines 62–66. [6](#0-5) 

7. Only `logout` clears `recoveryPhrase.value = null` — confirmed at line 96 of `storeUser.ts`. [7](#0-6) 

All claims are code-verified. The asymmetry between `handleSkip` and `handleContinue` is real and unambiguous.

---

# Audit Report

## Title
Plaintext Mnemonic Words Persist in Pinia Store After Recovery Phrase Migration Completes

## Summary
The global Pinia user store holds a `RecoveryPhrase` object containing 24 plaintext BIP-39 mnemonic words in the Electron renderer process heap. The `handleContinue` success path in `MigrateRecoveryPhraseHash.vue` navigates away after migration without clearing `user.recoveryPhrase`, leaving the plaintext word array in the V8 heap for the remainder of the session. The same omission exists in `GenerateOrImport.vue`'s `handleImport`. Only an explicit `logout()` call clears the phrase.

## Finding Description

**Root cause — global store retains plaintext words:**

`storeUser.ts` declares `recoveryPhrase` as a Pinia `ref`:

```ts
const recoveryPhrase: Ref<RecoveryPhrase|null> = ref(null);
``` [1](#0-0) 

`createRecoveryPhrase` in `userStoreHelpers.ts` stores the full plaintext word array alongside the `Mnemonic` object and hash:

```ts
return { mnemonic, words, hash };
``` [8](#0-7) 

**Primary missing clear — `handleContinue` in `MigrateRecoveryPhraseHash.vue`:**

The `onMounted` hook clears any pre-existing phrase on component entry, establishing the developer's intent that the phrase is scoped to this operation: [5](#0-4) 

`handleSkip` (the abort path) correctly calls `await user.setRecoveryPhrase(null)` before navigating: [9](#0-8) 

`handleContinue` (the success path) calls `router.push({ name: 'transactions' })` with no corresponding clear: [4](#0-3) 

After `handleContinue` returns, `user.recoveryPhrase.words` (24 plaintext BIP-39 words) remains live in the V8 heap.

**Secondary instance — `GenerateOrImport.vue` `handleImport`:**

After the user imports their phrase and clicks "Next", `handleImport` calls `props.handleNext()` without clearing the store: [6](#0-5) 

**Only `logout` clears the phrase:** [7](#0-6) 

## Impact Explanation
An attacker who obtains a V8 heap snapshot or crash dump of the Electron renderer process will find the 24-word mnemonic in plaintext. With the mnemonic, the attacker can derive all private keys at any BIP-32 index and drain all associated Hedera accounts. Impact is total wallet compromise. The `Mnemonic` SDK object stored alongside `words` also retains the entropy internally, compounding the exposure surface.

## Likelihood Explanation
The Electron renderer process is a Chromium renderer; V8 heap snapshots are a standard debugging artifact producible via DevTools or `--inspect`. If the application integrates any crash reporter that captures renderer heap data (common in Electron apps), the mnemonic is transmitted off-device on every crash. Even without a crash reporter, the mnemonic persists in memory for the entire session — potentially hours — rather than the seconds needed for the migration operation. The trigger path (user completes recovery phrase migration → navigates to transactions → app crashes or heap is inspected) is a realistic, low-privilege scenario.

## Recommendation

1. **`MigrateRecoveryPhraseHash.vue` — `handleContinue`:** Add `await user.setRecoveryPhrase(null)` immediately after `updateKeyPairsHash` succeeds and before `router.push`, mirroring the existing pattern in `handleSkip`.

2. **`GenerateOrImport.vue` — `handleImport`:** Add `await user.setRecoveryPhrase(null)` after `props.handleNext()` resolves (or have the parent caller clear it as part of the next-step transition).

3. **Audit all other callers** that read `user.recoveryPhrase` for a similar missing-clear pattern (e.g., `Generate.vue`'s `handleGenerate`, `RestoreKey` flow).

4. Consider zeroing the `words` array elements before nulling the ref to reduce the window during which GC has not yet collected the strings.

## Proof of Concept

1. Launch the application and log in with an account that has keys requiring hash migration (pre-argon2 `secret_hash` values).
2. The app redirects to `MigrateRecoveryPhraseHash`.
3. Enter the correct 24-word recovery phrase. `user.recoveryPhrase.words` is now populated.
4. Click **Continue**. `handleContinue` runs, migration succeeds, `router.push({ name: 'transactions' })` is called.
5. Open Electron DevTools in the renderer (`Ctrl+Shift+I`), navigate to **Memory → Take heap snapshot**.
6. Search the snapshot for any of the 24 BIP-39 words. All 24 words are present as live string objects in the `recoveryPhrase.words` array within the Pinia store's reactive state, confirming the plaintext mnemonic was never cleared.

### Citations

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

**File:** front-end/src/renderer/pages/MigrateRecoveryPhraseHash/MigrateRecoveryPhraseHash.vue (L50-65)
```vue
const handleSkip = async () => {
  await user.setRecoveryPhrase(null);

  let keysToMigrate = await getRequiredKeysToMigrate();
  if (isLoggedInOrganization(user.selectedOrganization) && keysToMigrate.length > 0) {
    await safeAwait(tryMigrateOrganizationKeys(keysToMigrate));
    keysToMigrate = await getRequiredKeysToMigrate();
  }
  for (const key of keysToMigrate) {
    await updateMnemonicHash(key.id, null);
    await updateIndex(key.id, -1);
  }
  await user.refetchKeys();

  await router.push({ name: 'transactions' });
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

**File:** front-end/src/renderer/pages/MigrateRecoveryPhraseHash/MigrateRecoveryPhraseHash.vue (L126-128)
```vue
onMounted(async () => {
  await user.setRecoveryPhrase(null);
});
```

**File:** front-end/src/renderer/pages/AccountSetup/components/GenerateOrImport.vue (L62-66)
```vue
const handleImport = async () => {
  if (user.recoveryPhrase === null) return;
  await recoveryPhraseNickname.set(user.recoveryPhrase.hash, mnemonicHashNickname.value);
  await props.handleNext();
};
```
