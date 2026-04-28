All referenced code is confirmed. The vulnerability is real and demonstrable. Here is the audit report:

---

Audit Report

## Title
`approved` Field in `ApproverChoiceDto` Is Not Covered by the Cryptographic Signature, Enabling Silent Intent Flip

## Summary
The transaction approval flow requires approvers to submit a cryptographic signature alongside an `approved: boolean` field. The signature is computed exclusively over the raw transaction body bytes — the `approved` field is never included in the signed data. Because the same signature is equally valid for both `approved: true` and `approved: false`, any party who can intercept or modify the API request (a MITM attacker, a rogue organization server, or a compromised backend operator) can flip the approver's intent without invalidating the signature.

## Finding Description

**Signing (front-end):**

In `ApproveTransactionController.vue`, the approver signs only the transaction body bytes. The `approved` prop is passed separately to `sendApproverChoice` and is never included in the signed payload:

```ts
// front-end/src/renderer/pages/TransactionDetails/ApproveTransactionController.vue:99-106
const signature = getTransactionBodySignatureWithoutNodeAccountId(privateKey, sdkTransaction);
await sendApproverChoice(
  user.selectedOrganization.serverUrl,
  transaction.id,
  orgKey.id,
  signature,
  props.approved,   // ← NOT signed, sent as a plain field
);
``` [1](#0-0) 

`getTransactionBodySignatureWithoutNodeAccountId` signs only `proto.TransactionBody.encode(transaction._makeTransactionBody(null)).finish()` — the `approved` boolean is absent from this byte string: [2](#0-1) 

**DTO (no binding between signature and intent):**

`ApproverChoiceDto` holds `signature` and `approved` as independent fields with no cryptographic binding between them: [3](#0-2) 

**Verification (back-end):**

`verifyTransactionBodyWithoutNodeAccountIdSignature` verifies the signature against the same transaction body bytes, with no awareness of `approved`: [4](#0-3) 

After the signature passes, the server persists `dto.approved` verbatim: [5](#0-4) 

## Impact Explanation
An attacker controlling the organization server (or performing MITM on the connection) can silently flip every approver's decision. In a threshold-approval workflow, this can:
- Block transactions that have legitimate approval by converting approvals to rejections.
- Force approval of transactions that approvers intended to reject.

The cryptographic signature provides no protection against this manipulation because it does not commit to the approver's intent. The `approved` field is accepted and stored verbatim from the (potentially tampered) request body.

## Likelihood Explanation
The organization server URL is user-configurable via `user.selectedOrganization.serverUrl`. [6](#0-5) 

A malicious organization operator — a realistic attacker profile for a multi-tenant approval tool — can exploit this without any privileged access to the Hedera network or to user private keys. No brute force or cryptographic break is required; the attacker simply modifies the `approved` field in the JSON body before it reaches the backend.

## Recommendation
Include the `approved` boolean in the signed payload. The simplest approach is to sign a canonical byte string that commits to both the transaction body and the approver's intent, for example:

```
signedBytes = SHA256(transactionBodyBytes || 0x01)  // for approved=true
signedBytes = SHA256(transactionBodyBytes || 0x00)  // for approved=false
```

The back-end must then reconstruct the same byte string (using the stored `dto.approved` value) before calling `publicKey.verify(...)`. This ensures that a signature produced for `approved: true` cannot be replayed for `approved: false`.

Alternatively, a structured message envelope (e.g., `{ transactionId, approved, bodyBytesHash }` serialized deterministically) can be signed and verified end-to-end.

## Proof of Concept

1. Approver A signs the transaction body bytes and submits:
   ```json
   POST /transactions/{id}/approvers/approve
   { "userKeyId": 42, "signature": "<valid_sig>", "approved": true }
   ```
2. The attacker (malicious org server or MITM) intercepts the request and changes `approved: true` → `approved: false`, leaving `signature` unchanged.
3. The back-end calls `verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTransaction, dto.signature, publicKey)` — this returns `true` because the signature covers only the transaction body bytes, which were not modified. [7](#0-6) 
4. The back-end stores `approved: false`, recording the approver as having rejected the transaction they intended to approve. [8](#0-7) 
5. In a threshold-approval workflow, this silently prevents the transaction from reaching the required approval count, or forces approval of a transaction the approver intended to reject.

### Citations

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

**File:** back-end/apps/api/src/transactions/dto/approver-choice.dto.ts (L5-16)
```typescript
export class ApproverChoiceDto {
  @IsNumber()
  @IsNotEmpty()
  userKeyId: number;

  @IsNotEmpty()
  @TransformBuffer()
  signature: Buffer;

  @IsBoolean()
  @IsNotEmpty()
  approved: boolean;
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L592-596)
```typescript
    /* Verify the signature matches the transaction */
    if (
      !verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTransaction, dto.signature, publicKey)
    )
      throw new BadRequestException(ErrorCodes.SNMP);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L598-610)
```typescript
    /* Update the approver with the signature */
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
