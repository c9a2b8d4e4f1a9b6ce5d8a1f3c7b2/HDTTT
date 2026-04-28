### Title
Arbitrary `mirrorNetwork` URL Accepted Without Whitelist Enables SSRF via gRPC

### Summary
The `CreateTransactionDto` accepts a free-form `mirrorNetwork` string with no enum or URL whitelist validation. Any authenticated user can supply an attacker-controlled URL as the mirror network. The backend then makes an outbound gRPC connection to that URL (via `AddressBookQuery`) during both transaction creation and execution, constituting a Server-Side Request Forgery (SSRF) vulnerability. This is the direct analog of the external report's "arbitrary token address" class: user-supplied resource locators are accepted without whitelisting.

### Finding Description

**Root cause — `CreateTransactionDto` accepts any string for `mirrorNetwork`:** [1](#0-0) 

Only `@IsNotEmpty()` and `@IsString()` are applied. No `@IsEnum()`, `@IsIn()`, or URL-pattern constraint exists.

**Exploit path — `createTransactions()` passes the raw value directly to `getClientFromNetwork()`:** [2](#0-1) 

**`getClientFromNetwork()` makes an outbound gRPC connection to any non-standard value:** [3](#0-2) 

When `mirrorNetwork` is not `mainnet`, `testnet`, `previewnet`, or `local-node`, the function constructs a gRPC client pointing at the attacker-supplied URL and immediately executes an `AddressBookQuery` against it — an outbound network call to an arbitrary host.

**The malicious value is persisted and re-used during execution by the chain service:** [4](#0-3) 

`transaction.mirrorNetwork` (the attacker-supplied value) is passed again to `getClientFromNetwork()` at execution time, triggering a second outbound connection.

### Impact Explanation

1. **SSRF via gRPC** — the backend makes outbound gRPC connections to any host:port the attacker specifies. This allows probing internal services (Kubernetes sidecars, metadata endpoints, internal APIs) that are reachable from the backend pod but not from the public internet.
2. **Address-book poisoning** — if the attacker controls the gRPC endpoint and returns a crafted `NodeAddressBook`, `client.setNetworkFromAddressBook()` will configure the SDK client to route subsequent Hedera transactions to attacker-controlled nodes.
3. **Persistent trigger** — the malicious `mirrorNetwork` is stored in the database and re-triggered every time the chain service attempts to execute the transaction, multiplying the SSRF calls without further attacker interaction.

### Likelihood Explanation

- Requires only a valid authenticated session (normal user registration).
- No privileged keys, admin access, or leaked credentials needed.
- The attack path is a single API call (`POST /transactions`) with a crafted `mirrorNetwork` field.
- The `ValidationPipe` with `whitelist: true` strips unknown DTO fields but does **not** constrain the value of known string fields — so the guard provides no protection here. [5](#0-4) 

### Recommendation

Restrict `mirrorNetwork` to an allowlist of known-safe values at the DTO level:

```typescript
import { IsIn } from 'class-validator';

@IsIn(['mainnet', 'testnet', 'previewnet', 'local-node'])
mirrorNetwork: string;
```

If custom mirror networks must be supported (e.g., for enterprise deployments), validate the value against an operator-configured allowlist stored in environment configuration, and reject any value not present in that list before calling `getClientFromNetwork()`.

### Proof of Concept

```
POST /transactions
Authorization: Bearer <valid_user_jwt>
Content-Type: application/json

{
  "name": "ssrf-probe",
  "description": "test",
  "transactionBytes": "<valid_hex_encoded_transaction>",
  "signature": "<valid_signature>",
  "creatorKeyId": 1,
  "mirrorNetwork": "http://169.254.169.254"
}
```

**Expected outcome:** The backend calls `getClientFromNetwork("http://169.254.169.254")`, which constructs a gRPC client and executes `AddressBookQuery` against `169.254.169.254:443` (AWS/GCP instance metadata endpoint or any internal host). The attacker observes timing differences or error messages to confirm reachability of internal hosts. The malicious `mirrorNetwork` value is persisted and re-triggered on every execution attempt by the chain service.

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction.dto.ts (L26-28)
```typescript
  @IsNotEmpty()
  @IsString()
  mirrorNetwork: string;
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L400-405)
```typescript
  async createTransactions(dtos: CreateTransactionDto[], user: User): Promise<Transaction[]> {
    if (dtos.length === 0) return [];

    await attachKeys(user, this.entityManager);

    const client = await getClientFromNetwork(dtos[0].mirrorNetwork);
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

**File:** back-end/libs/common/src/execute/execute.service.ts (L128-132)
```typescript
  private async _executeTransaction(
    transaction: Transaction,
    sdkTransaction: SDKTransaction,
  ): Promise<TransactionExecutedDto | null> {
    const client = await getClientFromNetwork(transaction.mirrorNetwork);
```

**File:** back-end/apps/chain/src/setup-app.ts (L6-10)
```typescript
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
    }),
```
