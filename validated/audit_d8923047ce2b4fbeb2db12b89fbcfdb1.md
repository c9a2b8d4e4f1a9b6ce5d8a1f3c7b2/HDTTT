### Title
Wrong Property Names in `getComponentServiceEndpoint` Cause Node Endpoint Data to Always Be Empty, Breaking Transaction Integrity Comparison

### Summary

In `front-end/src/renderer/utils/sdk/getData.ts`, the function `getComponentServiceEndpoint` accesses `serviceEndpoint.getIpAddressV4`, `serviceEndpoint.getPort`, and `serviceEndpoint.getDomainName` — Java-style getter names that do not exist as properties on the `@hiero-ledger/sdk` `ServiceEndpoint` object. The correct JavaScript SDK property names are `ipAddressV4`, `port`, and `domainName`. As a result, all three fields always resolve to their fallback empty values. This silently corrupts the node endpoint data returned for every `NodeCreateTransaction` and `NodeUpdateTransaction`, and — critically — causes `transactionsDataMatch` to consider two node transactions with entirely different endpoints as identical.

### Finding Description

**Root cause — wrong property names:** [1](#0-0) 

```typescript
const ipAddressV4 =
  serviceEndpoint.getIpAddressV4 && serviceEndpoint.getIpAddressV4.length > 0
    ? serviceEndpoint.getIpAddressV4.join('.')
    : '';
const port = serviceEndpoint.getPort ? serviceEndpoint.getPort.toString() : '';
const domainName = serviceEndpoint.getDomainName || '';
```

The `@hiero-ledger/sdk` `ServiceEndpoint` class exposes `ipAddressV4` (a `Uint8Array`), `port` (a `number`), and `domainName` (a `string`) as plain properties. The names `getIpAddressV4`, `getPort`, and `getDomainName` do not exist on the object, so they evaluate to `undefined` (falsy). Every branch falls through to the empty-string default, and `getComponentServiceEndpoint` always returns `{ ipAddressV4: '', port: '', domainName: '' }` regardless of the actual transaction content. [2](#0-1) 

**Propagation into `getNodeData`:**

`getNodeData` calls `getComponentServiceEndpoints` (which maps over `getComponentServiceEndpoint`) for both `gossipEndpoints` and `serviceEndpoints`: [3](#0-2) 

So every `NodeCreateTransaction` and `NodeUpdateTransaction` is extracted with all endpoint IP/port/domain fields blank.

**Propagation into `transactionsDataMatch`:**

`transactionsDataMatch` compares two transactions by serialising the output of `getAllData` to JSON: [4](#0-3) 

Because `getAllData` calls `getNodeData` → `getComponentServiceEndpoints` → `getComponentServiceEndpoint`, and all endpoint fields are always `''`, two `NodeCreateTransaction` objects with completely different gossip/service endpoints produce identical JSON. `transactionsDataMatch` returns `true` for transactions that are materially different.

**Attack path in the multi-signature workflow:**

1. Legitimate user drafts a `NodeCreateTransaction` with specific gossip/service endpoints and submits it to the organisation server.
2. A malicious co-signer (or a compromised server) replaces the stored transaction bytes with a different `NodeCreateTransaction` pointing to attacker-controlled node endpoints.
3. Reviewing signers see empty endpoint fields in the UI (the bug suppresses all endpoint display).
4. If the frontend performs a `transactionsDataMatch` check between the locally cached draft and the server copy, the check passes because both produce all-empty endpoint data — the substitution is undetected.
5. Signers approve and the malicious node configuration is submitted to the Hedera network.

### Impact Explanation

- **Node governance integrity**: `NodeCreateTransaction` and `NodeUpdateTransaction` are privileged governance transactions. Silently substituting their gossip/service endpoints means the network could be directed to communicate with attacker-controlled infrastructure.
- **Signature collation bypass**: The `transactionsDataMatch` guard — intended to detect tampering between signing rounds — is completely ineffective for node transactions, removing the only client-side integrity check.
- **UI deception**: Reviewers see blank endpoint fields and cannot verify what they are signing, making informed approval impossible.

### Likelihood Explanation

- Any authenticated user of the organisation backend who can reach the transaction storage endpoint can attempt to substitute transaction bytes.
- The bug is deterministic and requires no special timing or cryptographic capability — it fires on every node transaction.
- Node governance transactions are rare but high-value targets; the attacker only needs to act once during the signing window.

### Recommendation

Replace the non-existent Java-style getter names with the correct JavaScript SDK property names in `getComponentServiceEndpoint`:

```typescript
// BEFORE (broken)
const ipAddressV4 =
  serviceEndpoint.getIpAddressV4 && serviceEndpoint.getIpAddressV4.length > 0
    ? serviceEndpoint.getIpAddressV4.join('.')
    : '';
const port = serviceEndpoint.getPort ? serviceEndpoint.getPort.toString() : '';
const domainName = serviceEndpoint.getDomainName || '';

// AFTER (correct)
const ipAddressV4 =
  serviceEndpoint.ipAddressV4 && serviceEndpoint.ipAddressV4.length > 0
    ? Array.from(serviceEndpoint.ipAddressV4).join('.')
    : '';
const port = serviceEndpoint.port != null ? serviceEndpoint.port.toString() : '';
const domainName = serviceEndpoint.domainName || '';
```

Add a unit test that constructs a `ServiceEndpoint` with known values and asserts that `getComponentServiceEndpoint` returns the correct non-empty strings.

### Proof of Concept

```typescript
import { ServiceEndpoint } from '@hiero-ledger/sdk';
import { getComponentServiceEndpoint } from 'front-end/src/renderer/utils/sdk/getData';

// Construct an endpoint with real data
const ep = new ServiceEndpoint()
  .setIpAddressV4(new Uint8Array([192, 168, 1, 1]))
  .setPort(50211);

const result = getComponentServiceEndpoint(ep);

// Expected (correct): { ipAddressV4: '192.168.1.1', port: '50211', domainName: '' }
// Actual (buggy):     { ipAddressV4: '',             port: '',       domainName: '' }
console.assert(result.ipAddressV4 === '192.168.1.1', 'FAIL: ipAddressV4 is empty');
console.assert(result.port === '50211',              'FAIL: port is empty');
```

Because `getComponentServiceEndpoint` always returns empty strings, `transactionsDataMatch` called on two `NodeCreateTransaction` objects with different endpoints returns `true`, confirming the integrity-check bypass. [5](#0-4)

### Citations

**File:** front-end/src/renderer/utils/sdk/getData.ts (L220-246)
```typescript
export const getComponentServiceEndpoint = (
  serviceEndpoint: ServiceEndpoint | null,
): ComponentServiceEndpoint | null => {
  if (!serviceEndpoint) {
    return null;
  }

  const ipAddressV4 =
    serviceEndpoint.getIpAddressV4 && serviceEndpoint.getIpAddressV4.length > 0
      ? serviceEndpoint.getIpAddressV4.join('.')
      : '';
  const port = serviceEndpoint.getPort ? serviceEndpoint.getPort.toString() : '';
  const domainName = serviceEndpoint.getDomainName || '';

  return {
    ipAddressV4,
    port,
    domainName,
  };
};

export const getComponentServiceEndpoints = (
  serviceEndpoints: ServiceEndpoint[],
): ComponentServiceEndpoint[] => {
  const result =  serviceEndpoints.map(getComponentServiceEndpoint);
  return result.filter((i) => i !== null)
};
```

**File:** front-end/src/renderer/utils/sdk/getData.ts (L256-258)
```typescript
  const gossipEndpoints = getComponentServiceEndpoints(transaction.gossipEndpoints || []);
  const serviceEndpoints = getComponentServiceEndpoints(transaction.serviceEndpoints || []);
  const grpcWebProxyEndpoint = getComponentServiceEndpoint(transaction.grpcWebProxyEndpoint);
```

**File:** front-end/src/renderer/utils/sdk/getData.ts (L460-468)
```typescript
export function transactionsDataMatch(t1: Transaction, t2: Transaction): boolean {
  const t1Data = getAllData(t1);
  const t2Data = getAllData(t2);
  t1Data.validStart = undefined
  t2Data.validStart = undefined
  t1Data.startTimestamp = undefined;
  t2Data.startTimestamp = undefined;
  return JSON.stringify(t1Data) === JSON.stringify(t2Data);
}
```
