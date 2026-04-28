### Title
Missing `ledgerId` on Custom-Network Hedera Clients Enables Cross-Network Transaction Replay

### Summary
When a user configures the Hedera Transaction Tool to connect to a custom (non-standard) Hedera network, the Hedera SDK `Client` is constructed without calling `setLedgerId()`. Transactions frozen against this client embed no network-specific `ledger_id` in their protobuf body. A transaction body with no `ledger_id` is accepted by any Hedera network node (mainnet, testnet, previewnet, or another custom network), making it possible to replay a transaction crafted for one network on a different network — the direct analog of the Overprotocol ChainID = 1 replay issue.

### Finding Description

**Vulnerability class:** Cross-network transaction replay (missing network domain separator).

**Root cause — three independent code paths all omit `ledgerId` for custom networks:**

**Path 1 — Renderer store client** (`front-end/src/renderer/utils/sdk/index.ts`, lines 379–402):

```typescript
export const getClientFromMirrorNode = async (mirrorNetwork: string) => {
  // ...
  const client = Client.forNetwork({})
    .setMirrorNetwork(mirrorNodeGRPC)
    .setNetworkFromAddressBook(nodeAddressBook);
  return client;   // ← no setLedgerId() call
};
```

Called from `storeNetwork.setStoreClient` at line 92 for every custom network.

**Path 2 — Main-process execution client** (`front-end/src/main/services/localUser/transactions.ts`, lines 41–67):

```typescript
export const getClientFromNetwork = async (mirrorNetwork, ledgerId?: string) => {
  // ...
  const client = Client.forNetwork({}).setMirrorNetwork(mirrorNetwork);
  client.setNetworkFromAddressBook(nodeAddressBook);
  if (ledgerId) { client.setLedgerId(ledgerId); }  // only if caller passes it
  return client;
};
```

The only caller in the network-switch flow is `storeNetwork.setNetwork` → `setClient(newNetwork)` (line 63), which **never passes a `ledgerId`**. So for custom networks the main-process client also has no ledger ID.

**Path 3 — Back-end chain service** (`back-end/libs/common/src/utils/sdk/client.ts`, lines 38–52): identical optional-`ledgerId` pattern; `ledgerId` is never supplied by callers for custom networks.

**Contrast with named networks:** `Client.forName('mainnet')` automatically embeds ledger ID `0x00`; `Client.forName('testnet')` embeds `0x01`. The local-node branch explicitly calls `.setLedgerId('3')` (line 88 of `storeNetwork.ts`). Custom networks are the only case where this step is skipped.

**Freeze path that embeds the missing field** (`front-end/src/main/services/localUser/transactions.ts`, lines 82–101):

```typescript
export const freezeTransaction = async (transactionBytes) => {
  const transaction = Transaction.fromBytes(transactionBytes);
  transaction.freezeWith(client);   // client has no ledgerId → body has no ledger_id
  return transaction.toBytes();
};
```

`signTransaction` with `needsFreeze = true` follows the same path (line 101). The resulting serialised bytes contain no `ledger_id` field and are therefore network-agnostic.

### Impact Explanation

A transaction body with no `ledger_id` is accepted by Hedera mainnet nodes (the field is optional for backward compatibility). If an attacker obtains the serialised transaction bytes — from the local SQLite store, the backend PostgreSQL database, the Organisation-mode API response, or network interception — they can submit those bytes directly to Hedera mainnet (or testnet) via any Hedera SDK or gRPC call, provided:

- the payer account ID exists on the target network (Hedera account IDs are sequential and largely overlap across networks), and
- the signing keys control that account on the target network (common when the same key material is reused across environments, which is the typical enterprise pattern this tool is designed for).

Successful replay on mainnet causes real HBAR or token transfers, account-key rotations, file updates, or other irreversible state changes that the signer never authorised for that network.

### Likelihood Explanation

The tool explicitly supports custom networks via the mirror-node URL input in `NetworkSettings.vue`. Enterprise and council deployments routinely run private Hedera networks for staging/testing with the same key material as mainnet. The transaction bytes are persisted in plaintext (hex) in the backend database and are returned in API responses, giving Organisation-mode participants direct access. The 180-second transaction validity window is the main limiting factor, but in Organisation-mode the transaction is stored and can be replayed at any point within that window after the final signature is collected. No privilege beyond normal tool usage is required.

### Recommendation

1. **Require `ledgerId` for custom networks.** In both `getClientFromMirrorNode` (`front-end/src/renderer/utils/sdk/index.ts`) and `getClientFromNetwork` (`front-end/src/main/services/localUser/transactions.ts` and `back-end/libs/common/src/utils/sdk/client.ts`), make `ledgerId` a required parameter (not optional) when the network is not one of the three named networks. Expose a UI field for it alongside the mirror-node URL input in `NetworkSettings.vue`.

2. **Propagate `ledgerId` through `setNetwork`.** `storeNetwork.setNetwork` must pass the ledger ID to `setClient(newNetwork, ledgerId)` so the main-process client is also bound to the correct network.

3. **Validate `ledger_id` on ingest.** The backend `validateAndPrepareTransaction` (`back-end/apps/api/src/transactions/transactions.service.ts`, lines 896–978) should reject transaction bytes whose embedded `ledger_id` does not match the `mirrorNetwork` field of the request.

### Proof of Concept

1. In the tool's Settings → Network, enter a custom mirror-node URL (e.g., `custom-hedera.example.com`). The tool calls `setNetwork('custom-hedera.example.com')` → `setClient('custom-hedera.example.com')` with no `ledgerId`.

2. Create any transaction (e.g., `CryptoTransfer`) and sign it. `freezeTransaction` calls `transaction.freezeWith(client)` where `client.ledgerId` is `null`. Serialise with `toBytes()`.

3. Inspect the resulting protobuf bytes: the `TransactionBody.ledger_id` field is absent (zero-length bytes).

4. Submit those bytes to Hedera mainnet via any SDK: `Transaction.fromBytes(bytes).execute(Client.forMainnet())`. If the payer account and signing keys exist on mainnet, the transaction executes — transferring HBAR or mutating state on mainnet — without the signer ever having authorised a mainnet transaction. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** front-end/src/renderer/utils/sdk/index.ts (L379-402)
```typescript
export const getClientFromMirrorNode = async (mirrorNetwork: string) => {
  const mirrorNodeGRPC = mirrorNetwork.endsWith(':443') ? mirrorNetwork : `${mirrorNetwork}:443`;

  const nodeAddressBookProto = await getNodeAddressBook(mirrorNodeGRPC);

  nodeAddressBookProto.nodeAddress?.forEach(node => {
    if (node.nodeAccountId?.shardNum) {
      node.nodeAccountId.shardNum = Long.fromValue(node.nodeAccountId.shardNum);
    }
    if (node.nodeAccountId?.accountNum) {
      node.nodeAccountId.accountNum = Long.fromValue(node.nodeAccountId.accountNum);
    }
    if (node.nodeAccountId?.realmNum) {
      node.nodeAccountId.realmNum = Long.fromValue(node.nodeAccountId.realmNum);
    }
  });

  const nodeAddressBook = NodeAddressBook._fromProtobuf(nodeAddressBookProto);

  const client = Client.forNetwork({})
    .setMirrorNetwork(mirrorNodeGRPC)
    .setNetworkFromAddressBook(nodeAddressBook);

  return client;
```

**File:** front-end/src/renderer/stores/storeNetwork.ts (L62-93)
```typescript
  async function setNetwork(newNetwork: Network) {
    await setClient(newNetwork);
    await setStoreClient(newNetwork);

    mirrorNodeBaseURL.value = getMirrorNodeREST(newNetwork);
    network.value = newNetwork;
    exchangeRateSet.value = await getExchangeRateSet(mirrorNodeBaseURL.value);

    nodeNumbers.value = await getNodeNumbersFromNetwork(mirrorNodeBaseURL.value);
  }

  async function setStoreClient(newNetwork: Network) {
    client.value.close();

    if (
      [CommonNetwork.MAINNET, CommonNetwork.TESTNET, CommonNetwork.PREVIEWNET].includes(newNetwork)
    ) {
      client.value = Client.forName(newNetwork);
      return;
    }

    if (newNetwork === CommonNetwork.LOCAL_NODE) {
      client.value = Client.forNetwork({
        '127.0.0.1:50211': '0.0.3',
      })
        .setMirrorNetwork('127.0.0.1:5600')
        .setLedgerId('3');
      return;
    }

    client.value = await getClientFromMirrorNode(newNetwork);
  }
```

**File:** front-end/src/main/services/localUser/transactions.ts (L41-74)
```typescript
export const getClientFromNetwork = async (mirrorNetwork: string | string[], ledgerId?: string) => {
  if (!Array.isArray(mirrorNetwork)) {
    mirrorNetwork = [mirrorNetwork];
  }

  mirrorNetwork = mirrorNetwork.map(network => network.toLocaleLowerCase());

  if ([MAINNET, TESTNET, PREVIEWNET, LOCAL_NODE].includes(mirrorNetwork[0])) {
    return Client.forName(mirrorNetwork[0]);
  }

  mirrorNetwork = mirrorNetwork.map(network =>
    network.endsWith(':443') ? network : `${network}:443`,
  );
  const client = Client.forNetwork({}).setMirrorNetwork(mirrorNetwork);

  const nodeAddressBook = await new AddressBookQuery()
    .setFileId(FileId.ADDRESS_BOOK)
    .execute(client);

  client.setNetworkFromAddressBook(nodeAddressBook);

  if (ledgerId) {
    client.setLedgerId(ledgerId);
  }

  return client;
};

// Sets the client
export const setClient = async (mirrorNetwork: string | string[], ledgerId?: string) => {
  client?.close();
  client = await getClientFromNetwork(mirrorNetwork, ledgerId);
};
```

**File:** front-end/src/main/services/localUser/transactions.ts (L82-101)
```typescript
export const freezeTransaction = async (transactionBytes: Uint8Array) => {
  const transaction = Transaction.fromBytes(transactionBytes);

  transaction.freezeWith(client);

  return transaction.toBytes();
};

// Signs a transaction
export const signTransaction = async (
  transactionBytes: Uint8Array,
  publicKeys: string[],
  userId: string,
  userPassword: string | null,
  needsFreeze = true,
) => {
  const transaction = Transaction.fromBytes(transactionBytes);

  if (needsFreeze) {
    transaction.freezeWith(client);
```

**File:** back-end/libs/common/src/utils/sdk/client.ts (L38-52)
```typescript
  const client = Client.forNetwork({}).setMirrorNetwork(
    MirrorNetworkGRPC.fromBaseURL(mirrorNetwork[0]),
  );

  const nodeAddressBook = await new AddressBookQuery()
    .setFileId(FileId.ADDRESS_BOOK)
    .execute(client);

  client.setNetworkFromAddressBook(nodeAddressBook);

  if (ledgerId) {
    client.setLedgerId(ledgerId);
  }

  return client;
```
