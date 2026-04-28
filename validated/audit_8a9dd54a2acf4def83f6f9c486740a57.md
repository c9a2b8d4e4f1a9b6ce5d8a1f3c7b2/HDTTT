### Title
Single-Network Client Used to Validate All Transactions in Batch, Causing Legitimate Transactions to Fail with `TNVN`

### Summary
`createTransactions` in `transactions.service.ts` creates a single Hedera SDK `Client` from `dtos[0].mirrorNetwork` and uses it unconditionally to validate every transaction in the batch — including those whose `mirrorNetwork` differs from the first DTO. Any transaction targeting a different network fails the node-account-ID check (`isTransactionValidForNodes`) with `ErrorCodes.TNVN`, even though it is perfectly valid for its own network. Because `Promise.all` is used, one such failure aborts the entire batch.

### Finding Description

**Root cause — single client for all DTOs:** [1](#0-0) 

```typescript
async createTransactions(dtos: CreateTransactionDto[], user: User): Promise<Transaction[]> {
    ...
    const client = await getClientFromNetwork(dtos[0].mirrorNetwork); // ← only first DTO's network

    try {
      const validatedData = await Promise.all(
        dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)), // ← same client for ALL
      );
```

**Node validation inside `validateAndPrepareTransaction` uses that single client:** [2](#0-1) 

```typescript
const allowedNodes = getNodeAccountIdsFromClientNetwork(client);
if (!isTransactionValidForNodes(sdkTransaction, allowedNodes)) {
    throw new BadRequestException(ErrorCodes.TNVN);
}
```

`getNodeAccountIdsFromClientNetwork` returns the node set for the network the client was built from: [3](#0-2) 

`isTransactionValidForNodes` requires every node ID in the transaction to be present in that set: [4](#0-3) 

If `dtos[1]` targets `mainnet` while `dtos[0]` targets `testnet`, the client holds testnet nodes. `mainnet` node IDs are not in that set, so `isTransactionValidForNodes` returns `false` and throws `TNVN`. `Promise.all` propagates the rejection, aborting the entire batch.

**Entry point — `POST /transaction-groups`:** [5](#0-4) 

```typescript
const transactionDtos = dto.groupItems.map(item => item.transaction);
const transactions = await this.transactionsService.createTransactions(transactionDtos, user);
```

Each `groupItem.transaction` carries its own `mirrorNetwork` field. The API schema does not enforce that all items share the same network.

### Impact Explanation
Any authenticated user who submits a `POST /transaction-groups` request containing transactions for more than one `mirrorNetwork` value will have the entire group creation rejected with `TNVN`, even though every individual transaction is valid for its own network. This is a functional DoS: legitimate, well-formed transactions are unconditionally blocked by a check that is applied with the wrong network context.

### Likelihood Explanation
The `POST /transaction-groups` endpoint is reachable by any authenticated, verified user — no admin or privileged role is required. [6](#0-5) 

The front-end currently always uses the same network for all items in a group, so ordinary UI users are not affected today. However, the API is documented and directly accessible; any API client (including the organization's own tooling or third-party integrations) that submits a mixed-network group will trigger the bug. The attacker precondition is simply a valid JWT and a crafted JSON body — no leaked secrets or privileged access required.

### Recommendation
Create a per-DTO client keyed on `mirrorNetwork`, or validate each transaction against its own network's client:

```typescript
// Group DTOs by mirrorNetwork, create one client per unique network
const clientMap = new Map<string, Client>();
try {
  for (const dto of dtos) {
    if (!clientMap.has(dto.mirrorNetwork)) {
      clientMap.set(dto.mirrorNetwork, await getClientFromNetwork(dto.mirrorNetwork));
    }
  }
  const validatedData = await Promise.all(
    dtos.map(dto => this.validateAndPrepareTransaction(dto, user, clientMap.get(dto.mirrorNetwork)!)),
  );
  ...
} finally {
  for (const client of clientMap.values()) client.close();
}
```

This mirrors the fix applied in the referenced BadgerDAO report: move the check inside the conditional branch where it is actually relevant, rather than applying it unconditionally to all items.

### Proof of Concept

**Preconditions:** valid JWT for any non-admin user; two Hedera transactions — one frozen for testnet nodes, one frozen for mainnet nodes.

**Request:**
```http
POST /transaction-groups
Authorization: Bearer <valid_jwt>
Content-Type: application/json

{
  "description": "mixed-network group",
  "atomic": false,
  "groupItems": [
    {
      "seq": 0,
      "transaction": {
        "name": "tx-testnet",
        "transactionBytes": "<testnet_tx_hex>",
        "mirrorNetwork": "testnet",
        "signature": "<sig>",
        "creatorKeyId": 1
      }
    },
    {
      "seq": 1,
      "transaction": {
        "name": "tx-mainnet",
        "transactionBytes": "<mainnet_tx_hex>",
        "mirrorNetwork": "mainnet",
        "signature": "<sig>",
        "creatorKeyId": 1
      }
    }
  ]
}
```

**Expected (correct) behavior:** both transactions are created; each is validated against its own network's node list.

**Actual behavior:** `getClientFromNetwork("testnet")` is called once. When `validateAndPrepareTransaction` runs for the mainnet DTO, `getNodeAccountIdsFromClientNetwork(client)` returns testnet nodes. Mainnet node IDs are absent → `isTransactionValidForNodes` returns `false` → `BadRequestException(TNVN)` is thrown → `Promise.all` rejects → the entire group creation fails with a 400 error, even though the mainnet transaction is perfectly valid. [7](#0-6) [2](#0-1)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L400-411)
```typescript
  async createTransactions(dtos: CreateTransactionDto[], user: User): Promise<Transaction[]> {
    if (dtos.length === 0) return [];

    await attachKeys(user, this.entityManager);

    const client = await getClientFromNetwork(dtos[0].mirrorNetwork);

    try {
      // Validate all DTOs upfront
      const validatedData = await Promise.all(
        dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)),
      );
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L933-937)
```typescript
    // Check nodes
    const allowedNodes = getNodeAccountIdsFromClientNetwork(client);
    if (!isTransactionValidForNodes(sdkTransaction, allowedNodes)) {
      throw new BadRequestException(ErrorCodes.TNVN);
    }
```

**File:** back-end/libs/common/src/utils/sdk/client.ts (L55-63)
```typescript
export const getNodeAccountIdsFromClientNetwork = (client: Client): Set<string> => {
  const network = client.network as { [key: string]: string | AccountId };
  const values = Object.values(network ?? {});
  return new Set(
    values.map((v) =>
      v instanceof AccountId ? v.toString() : AccountId.fromString(String(v)).toString(),
    ),
  );
};
```

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L342-362)
```typescript
export const isTransactionValidForNodes = (
  sdkTransaction: SDKTransaction,
  allowedNodeAccountIds: Set<string>
): boolean  => {
  const nodeAccountIds = (sdkTransaction as any)._nodeAccountIds;
  const txNodeIds: string[] = [];
  if (
    nodeAccountIds &&
    typeof nodeAccountIds.length === 'number' &&
    typeof nodeAccountIds.get === 'function'
  ) {
    for (let i = 0; i < nodeAccountIds.length; i++) {
      const id = nodeAccountIds.get(i);
      const accountId =
        id instanceof AccountId ? id : AccountId.fromString(String(id));
      txNodeIds.push(accountId.toString());
    }
  }

  return txNodeIds.every((id) => allowedNodeAccountIds.has(id));
};
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L46-53)
```typescript
    // Extract all transaction DTOs
    const transactionDtos = dto.groupItems.map(item => item.transaction);

    // Batch create all transactions
    const transactions = await this.transactionsService.createTransactions(
      transactionDtos,
      user,
    );
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L27-50)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionGroupsController {
  constructor(private readonly transactionGroupsService: TransactionGroupsService) {}

  /* Submit a transaction group */
  @ApiOperation({
    summary: 'Create a transaction group',
    description:
      'Create a transaction group for the organization. ' +
      'The group contains group items that each point to a transaction ' +
      'that the organization is to approve, sign, and execute.',
  })
  @ApiResponse({
    status: 201,
    type: TransactionGroupDto,
  })
  @Post()
  @Serialize(TransactionGroupDto)
  createTransactionGroup(
    @GetUser() user: User,
    @Body() dto: CreateTransactionGroupDto,
  ): Promise<TransactionGroup> {
    return this.transactionGroupsService.createTransactionGroup(user, dto);
  }
```
