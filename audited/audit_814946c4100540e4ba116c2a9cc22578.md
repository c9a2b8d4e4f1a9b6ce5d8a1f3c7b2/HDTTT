### Title
Approver Signature Does Not Bind to Approval Intent or Server Domain, Enabling Cross-Server Replay and Intent Tampering

### Summary
The approver signature in the transaction approval flow is computed over raw Hedera transaction body bytes only, with no inclusion of the `approved` boolean, the backend server URL, or any organization-specific domain context. This means a valid approval signature captured from one organization server can be replayed on a different server hosting the same Hedera transaction bytes, and the `approved` field can be tampered with in transit while the signature remains valid.

### Finding Description

**Root cause — what is signed:**

The front-end computes the approver signature in `getTransactionBodySignatureWithoutNodeAccountId`: [1](#0-0) 

```typescript
export const getTransactionBodySignatureWithoutNodeAccountId = (
  privateKey: PrivateKey,
  transaction: Transaction,
) => {
  const transactionBody = transaction._makeTransactionBody(null); // null = no node account ID
  const bodyBytes = proto.TransactionBody.encode(transactionBody).finish();
  const signature = privateKey.sign(bodyBytes);
  return uint8ToHex(signature);
};
```

The signed payload is **only** the Hedera transaction body bytes (with node account ID stripped). It does not include:
- The `approved` boolean (approve vs. reject intent)
- The backend server URL / organization identifier
- The backend database transaction ID

**What is sent to the server:** [2](#0-1) 

```typescript
const signature = getTransactionBodySignatureWithoutNodeAccountId(privateKey, sdkTransaction);
await sendApproverChoice(
  user.selectedOrganization.serverUrl,
  transaction.id,
  orgKey.id,
  signature,
  props.approved,   // ← NOT included in the signature
);
```

**What the server verifies:** [3](#0-2) 

```typescript
const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
if (
  !verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTransaction, dto.signature, publicKey)
)
  throw new BadRequestException(ErrorCodes.SNMP);
```

The server verifies the signature against the transaction body bytes only: [4](#0-3) 

After verification, `dto.approved` is stored directly without any cryptographic binding: [5](#0-4) 

**Attack path 1 — Approval intent flip (MITM):**
1. Approver Alice sends `POST /transactions/{id}/approvers/choice` with `{ signature, approved: true }`.
2. An attacker intercepts the request (e.g., on the same network segment, or via TLS stripping).
3. The attacker changes `approved: true` → `approved: false` while keeping the same `signature`.
4. The server verifies the signature (valid, since it covers only the transaction body bytes) and records Alice as having **rejected** the transaction.

**Attack path 2 — Cross-server replay:**
1. Alice approves transaction T on Organization Server A. Her signature `sig = sign(transactionBodyBytes)` is stored in Server A's database.
2. An attacker who administers Organization Server B creates the same Hedera transaction (identical `transactionBytes`) on Server B and adds Alice as an approver.
3. The attacker submits Alice's signature from Server A to Server B with `approved: true` (or `false`).
4. Server B verifies the signature against the same transaction body bytes — it passes — and records Alice's approval without her knowledge or consent.

### Impact Explanation
An attacker can forge or flip an approver's decision on a transaction:
- A legitimate approval can be converted to a rejection (blocking a valid transaction from reaching execution threshold).
- A legitimate rejection can be converted to an approval (causing an unwanted transaction to proceed).
- In a multi-organization deployment, a signature obtained from one server is unconditionally valid on any other server hosting the same Hedera transaction bytes.

The approval/rejection decision is the core authorization gate before a transaction is submitted to the Hedera network. Corrupting it can cause unauthorized fund transfers, account key changes, or node operations.

### Likelihood Explanation
- **Intent flip**: Requires network-level interception of the HTTP request. Realistic in enterprise LAN environments or where TLS termination is misconfigured. The tool is explicitly designed for Hedera Council/staff use in organizational settings, making controlled network environments common.
- **Cross-server replay**: Requires the attacker to control or have admin access to one organization server and to obtain the victim's signature (from that server's database or from network traffic). Realistic in multi-organization deployments where the same Hedera transaction is coordinated across organizations.

### Recommendation
Include the `approved` boolean, the backend server URL (or a stable organization identifier), and the backend transaction ID in the signed payload. This is the application-layer analog of EIP-712 domain separation.

**Client-side change** (`getTransactionBodySignatureWithoutNodeAccountId` or a new helper):
```typescript
const domainBytes = Buffer.from(JSON.stringify({
  serverUrl: organizationServerUrl,
  transactionId: backendTransactionId,
  approved: approvedBoolean,
}));
const payload = Buffer.concat([bodyBytes, domainBytes]);
const signature = privateKey.sign(payload);
```

**Server-side change** (`verifyTransactionBodyWithoutNodeAccountIdSignature` or `approveTransaction`):
```typescript
const domainBytes = Buffer.from(JSON.stringify({
  serverUrl: configuredServerUrl,
  transactionId: transactionId,
  approved: dto.approved,
}));
const payload = Buffer.concat([bodyBytes, domainBytes]);
return publicKey.verify(payload, signature);
```

This ensures the signature cryptographically binds to the approval intent and the specific server, preventing both intent tampering and cross-server replay.

### Proof of Concept

**Intent flip (no special tooling required):**
```
1. Alice (legitimate approver) sends:
   POST /transactions/42/approvers/choice
   Body: { userKeyId: 7, signature: "aabbcc...", approved: true }

2. Attacker intercepts and modifies:
   POST /transactions/42/approvers/choice
   Body: { userKeyId: 7, signature: "aabbcc...", approved: false }
   (signature unchanged)

3. Server calls verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTx, "aabbcc...", publicKey)
   → returns true (signature is over bodyBytes only, not over `approved`)

4. Server stores: approved = false, signature = "aabbcc..."
   Alice's approval is recorded as a rejection.
```

**Cross-server replay:**
```
1. Alice approves transaction T on Server A:
   signature_A = sign(transactionBodyBytes_T)  // stored in Server A DB

2. Attacker (admin on Server B) creates transaction T' with identical transactionBytes on Server B.
   Attacker adds Alice as approver for T' on Server B.

3. Attacker submits:
   POST https://server-b/transactions/99/approvers/choice
   Body: { userKeyId: Alice's key ID on Server B, signature: signature_A, approved: true }

4. Server B: verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTx_T', signature_A, Alice's pubkey)
   → transactionBodyBytes_T == transactionBodyBytes_T' → returns true

5. Alice's approval is recorded on Server B without her consent.
```

### Citations

**File:** front-end/src/renderer/utils/sdk/index.ts (L330-340)
```typescript
export const getTransactionBodySignatureWithoutNodeAccountId = (
  privateKey: PrivateKey,
  transaction: Transaction,
) => {
  // @ts-expect-error - _makeTransactionBody is a private method
  const transactionBody = transaction._makeTransactionBody(null);
  const bodyBytes = proto.TransactionBody.encode(transactionBody).finish();

  const signature = privateKey.sign(bodyBytes);
  return uint8ToHex(signature);
};
```

**File:** front-end/src/renderer/pages/TransactionDetails/ApproveTransactionController.vue (L99-107)
```vue
  const signature = getTransactionBodySignatureWithoutNodeAccountId(privateKey, sdkTransaction);

  await sendApproverChoice(
    user.selectedOrganization.serverUrl,
    transaction.id,
    orgKey.id,
    signature,
    props.approved,
  );
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L590-596)
```typescript
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    /* Verify the signature matches the transaction */
    if (
      !verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTransaction, dto.signature, publicKey)
    )
      throw new BadRequestException(ErrorCodes.SNMP);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L599-610)
```typescript
    await this.dataSource.transaction(async transactionalEntityManager => {
      await transactionalEntityManager
        .createQueryBuilder()
        .update(TransactionApprover)
        .set({
          userKeyId: dto.userKeyId,
          signature: dto.signature,
          approved: dto.approved,
        })
        .whereInIds(userApprovers.map(a => a.id))
        .execute();
    });
```

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L266-285)
```typescript
export const verifyTransactionBodyWithoutNodeAccountIdSignature = (
  transaction: SDKTransaction,
  signature: string | Buffer,
  publicKey: string | PublicKey,
) => {
  const bodyBytes = getTransactionBodyBytes(transaction);

  /* Deserialize Public Key */
  publicKey = publicKey instanceof PublicKey ? publicKey : PublicKey.fromString(publicKey);

  /* Deserialize Signature */
  signature = typeof signature === 'string' ? decode(signature) : signature;

  try {
    return publicKey.verify(bodyBytes, signature);
  } catch (err) {
    console.log(err);
    return false;
  }
};
```
