All code references have been verified against the actual source. Here is the audit result:

---

Audit Report

## Title
Uninitialized `client` Variable Causes Permanent DoS on All Transaction Operations in Local Mode

## Summary
In `front-end/src/main/services/localUser/transactions.ts`, the module-level `client: Client` variable is declared but never initialized at module load. All core transaction functions consume this variable without any null/undefined guard. If `setClient` fails mid-execution (e.g., when a custom network's `AddressBookQuery` throws), `client` is left as `undefined` or as a closed, unusable object, causing every subsequent transaction operation to throw a `TypeError` and rendering the entire local transaction workflow permanently broken until the app is restarted.

## Finding Description

**Root cause — uninitialized module-level variable:**

`front-end/src/main/services/localUser/transactions.ts` line 34 declares:

```typescript
let client: Client;
```

`client` is `undefined` at module load. The only initializer is `setClient` (lines 71–74):

```typescript
export const setClient = async (mirrorNetwork: string | string[], ledgerId?: string) => {
  client?.close();
  client = await getClientFromNetwork(mirrorNetwork, ledgerId);
};
``` [1](#0-0) [2](#0-1) 

**Failure path — custom network:**

For standard networks (`mainnet`, `testnet`, `previewnet`, `local-node`), `getClientFromNetwork` calls `Client.forName()` which is synchronous and cannot fail. However, for any custom mirror-node URL, `getClientFromNetwork` executes a live network call:

```typescript
const nodeAddressBook = await new AddressBookQuery()
  .setFileId(FileId.ADDRESS_BOOK)
  .execute(client);
``` [3](#0-2) 

If this call throws (unreachable host, TLS error, timeout), `setClient` propagates the exception. Critically, `client?.close()` was already called on line 72 before the assignment, so:
- If `client` was previously valid → it is now **closed** (unusable).
- If `client` was never set → it remains **`undefined`**.

**All downstream operations are unguarded:**

| Function | Line | Usage |
|---|---|---|
| `freezeTransaction` | 85 | `transaction.freezeWith(client)` |
| `signTransaction` | 101 | `transaction.freezeWith(client)` |
| `executeTransaction` | 142 | `transaction.execute(client)` |
| `executeQuery` | 175 | `client.setOperator(accountId, typedPrivateKey)` | [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

None of these functions check whether `client` is initialized before use. Calling any of them with `client === undefined` throws `TypeError: Cannot read properties of undefined`.

**IPC exposure:**

These functions are registered as IPC handlers and are callable from the renderer at any time via `window.electronAPI.local.transactions.*`. There is no enforcement that `setClient` must succeed before any of these handlers are invoked. [8](#0-7) 

## Impact Explanation

If a user configures a custom network that is temporarily unreachable:
1. `setClient` is called, closes the existing client (`client?.close()` on line 72), then throws.
2. `client` is now `undefined` (or a closed object).
3. Every call to `freezeTransaction`, `signTransaction`, `executeTransaction`, or `executeQuery` throws a `TypeError`.
4. The user cannot freeze, sign, or execute **any** Hedera transaction in local mode.
5. The only recovery is a full app restart (which resets the module-level `client` to `undefined` again — the problem recurs on the next failed `setClient` call).

This is a **permanent functional lock** on the core transaction workflow for the duration of the session.

## Likelihood Explanation

Custom network configuration is an explicitly supported workflow — the Settings UI exposes a "Custom" network option with a mirror node URL field. Any user pointing the app at a custom mirror node that is temporarily offline, misconfigured, or slow will trigger this path. No privileged access is required; this is a normal user action within the standard app workflow. The `storeNetwork.ts` store calls `setClient(newNetwork)` directly on every network switch, meaning any failed network switch corrupts the module-level `client` for the rest of the session. [9](#0-8) 

## Recommendation

1. **Restore the previous client on failure:** Save a reference to the old client before closing it, and restore it if `getClientFromNetwork` throws:

```typescript
export const setClient = async (mirrorNetwork: string | string[], ledgerId?: string) => {
  const previousClient = client;
  try {
    const newClient = await getClientFromNetwork(mirrorNetwork, ledgerId);
    previousClient?.close();
    client = newClient;
  } catch (err) {
    // previousClient is still valid; do not overwrite `client`
    throw err;
  }
};
```

2. **Add null guards in all consumer functions:** Each of `freezeTransaction`, `signTransaction`, `executeTransaction`, and `executeQuery` should check `if (!client) throw new Error('Client not initialized')` before use.

3. **Enforce initialization order at the IPC layer:** Consider returning a descriptive error from IPC handlers when `client` is not yet initialized, rather than allowing a raw `TypeError` to propagate.

## Proof of Concept

1. Launch the app and configure a custom network pointing to an unreachable mirror node URL (e.g., `https://unreachable.example.com`).
2. The app calls `setClient('unreachable.example.com')` via `storeNetwork.setNetwork`.
3. Inside `setClient`, `client?.close()` executes (closing any previously valid client).
4. `getClientFromNetwork` attempts `new AddressBookQuery().execute(client)` against the unreachable host and throws (timeout/connection refused).
5. The assignment `client = await getClientFromNetwork(...)` never completes; `client` remains `undefined`.
6. Attempt any transaction operation (e.g., `freezeTransaction`): `transaction.freezeWith(client)` throws `TypeError: Cannot read properties of undefined (reading 'freezeWith')`.
7. All transaction IPC handlers are now broken for the remainder of the session. Switching back to a valid network via the UI calls `setClient` again, but `client?.close()` on `undefined` is a no-op, and if the new `getClientFromNetwork` succeeds, `client` is restored — however, any intermediate failure repeats the lockout.

### Citations

**File:** front-end/src/main/services/localUser/transactions.ts (L34-34)
```typescript
let client: Client;
```

**File:** front-end/src/main/services/localUser/transactions.ts (L57-59)
```typescript
  const nodeAddressBook = await new AddressBookQuery()
    .setFileId(FileId.ADDRESS_BOOK)
    .execute(client);
```

**File:** front-end/src/main/services/localUser/transactions.ts (L71-74)
```typescript
export const setClient = async (mirrorNetwork: string | string[], ledgerId?: string) => {
  client?.close();
  client = await getClientFromNetwork(mirrorNetwork, ledgerId);
};
```

**File:** front-end/src/main/services/localUser/transactions.ts (L85-85)
```typescript
  transaction.freezeWith(client);
```

**File:** front-end/src/main/services/localUser/transactions.ts (L101-101)
```typescript
    transaction.freezeWith(client);
```

**File:** front-end/src/main/services/localUser/transactions.ts (L142-142)
```typescript
    const response = await transaction.execute(client);
```

**File:** front-end/src/main/services/localUser/transactions.ts (L175-175)
```typescript
  client.setOperator(accountId, typedPrivateKey);
```

**File:** front-end/src/main/modules/ipcHandlers/localUser/transactions.ts (L17-28)
```typescript
  createIPCChannel('transactions', [
    renameFunc(setClient, 'setClient'),
    renameFunc(freezeTransaction, 'freezeTransaction'),
    renameFunc(signTransaction, 'signTransaction'),
    renameFunc(executeTransaction, 'executeTransaction'),
    renameFunc(executeQuery, 'executeQuery'),
    renameFunc(storeTransaction, 'storeTransaction'),
    renameFunc(getTransactions, 'getTransactions'),
    renameFunc(getTransaction, 'getTransaction'),
    renameFunc(getTransactionsCount, 'getTransactionsCount'),
    renameFunc(encodeSpecialFile, 'encodeSpecialFile'),
  ]);
```

**File:** front-end/src/renderer/stores/storeNetwork.ts (L62-64)
```typescript
  async function setNetwork(newNetwork: Network) {
    await setClient(newNetwork);
    await setStoreClient(newNetwork);
```
