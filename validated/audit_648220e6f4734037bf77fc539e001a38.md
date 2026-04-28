The code confirms the vulnerability. Here is the audit report:

---

Audit Report

## Title
Missing Cryptographic Signature Validity Check in `processTransactionSignatures` Allows Invalid Signatures to Be Stored and Counted

## Summary
In `signers.service.ts`, the `processTransactionSignatures` method accepts a user-submitted `SignatureMap`, verifies only that each public key belongs to the authenticated user, and then calls `sdkTransaction.addSignature(publicKey, map)` without ever cryptographically verifying that the signature bytes are valid for the transaction body. A `validateSignature` utility that performs exactly this check exists in the codebase and is imported in `transactions.service.ts`, but is entirely absent from the signature upload path.

## Finding Description

**Root cause — `processTransactionSignatures` in `signers.service.ts`:**

The method iterates over the submitted `SignatureMap`. For each public key it:

1. Confirms the key belongs to the authenticated user via `userKeyMap` lookup (the only check performed): [1](#0-0) 

2. Calls `sdkTransaction.addSignature(publicKey, map)` with no cryptographic verification of the signature bytes: [2](#0-1) 

3. Compares resulting bytes only to detect whether anything changed (`isSameBytes`), not whether the signatures are valid: [3](#0-2) 

If `isSameBytes` is `false` (i.e., the invalid signature bytes were attached), the transaction bytes are overwritten with the poisoned value and a `TransactionSigner` record is inserted: [4](#0-3) 

**The missing check — `validateSignature` exists but is never called here:**

`validateSignature` in `transaction.ts` performs the required cryptographic check via `publicKey.verify(bodyBytes, signature)` and throws `'Invalid signature'` on failure: [5](#0-4) 

This function is imported and used in `transactions.service.ts`: [6](#0-5) 

It is completely absent from `signers.service.ts`. The DTO-level decorator `IsSignatureMap` only validates structural format (valid account IDs, transaction IDs, non-empty byte arrays) and cannot substitute for this check because it has no access to the stored transaction body bytes needed for `publicKey.verify`: [7](#0-6) 

## Impact Explanation
A malicious authenticated user can submit a `SignatureMap` containing their own registered public key paired with arbitrary garbage signature bytes. The service confirms key ownership, attaches the invalid bytes via `addSignature`, detects a byte change (`isSameBytes = false`), overwrites the stored `transactionBytes` with the poisoned value, and inserts a `TransactionSigner` record counting the user toward the signing threshold. When the threshold is met and the transaction is submitted to the Hedera network, it is rejected due to the invalid signature, resulting in a permanently failed multi-sig transaction, wasted fees, and a stuck workflow for all other legitimate signers.

## Likelihood Explanation
Any authenticated user with at least one registered key can trigger this. No elevated privileges are required. The attacker only needs to construct a `SignatureMap` with their own public key and random bytes as the signature — trivially achievable using the Hedera SDK client-side — and issue a standard authenticated `POST` request to the signature upload endpoint.

## Recommendation
Call `validateSignature` (already defined in `transaction.ts`) inside `processTransactionSignatures` before calling `addSignature`. Specifically, after deserializing the SDK transaction from stored bytes, pass both the transaction and the submitted `SignatureMap` to `validateSignature`. If it throws, propagate the error and abort processing for that transaction. This ensures `publicKey.verify(bodyBytes, signature)` is executed for every submitted signature before any bytes are stored or signer records are inserted.

## Proof of Concept
1. Authenticate as a user with a registered key `K` (public key hex `pk`).
2. Construct a `SignatureMap` JSON payload where `pk` maps to 64 bytes of `0x00` (or any random bytes) as the signature.
3. `POST /transactions/:id/signers` with this payload.
4. The service confirms `pk` belongs to the user (line 244–248 of `signers.service.ts`), calls `addSignature` (line 251), detects `isSameBytes = false`, overwrites `transactionBytes` with the invalid signature attached, and inserts a `TransactionSigner` row.
5. If the signing threshold is now met, `processTransactionStatus` schedules the transaction for submission.
6. The Hedera network rejects the transaction with `INVALID_SIGNATURE`, permanently failing the multi-sig workflow.

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L244-248)
```typescript
          let userKey = userKeyMap.get(raw);
          if (!userKey) {
            userKey = userKeyMap.get(publicKey.toStringDer());
          }
          if (!userKey) throw new Error(ErrorCodes.PNY);
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L251-251)
```typescript
          sdkTransaction = sdkTransaction.addSignature(publicKey, map);
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L262-264)
```typescript
    const isSameBytes = Buffer.from(sdkTransaction.toBytes()).equals(
      transaction.transactionBytes
    );
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L296-309)
```typescript
      if (!isSameBytes) {
        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
        transactionsToUpdate.push({ id, transactionBytes: transaction.transactionBytes });
      }

      // Collect inserts
      if (userKeys.length > 0) {
        const newSigners = userKeys.map(userKey => ({
          userId: user.id,
          transactionId: id,
          userKeyId: userKey.id,
        }));
        signersToInsert.push(...newSigners);
      }
```

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L213-248)
```typescript
export const validateSignature = (transaction: SDKTransaction, signatureMap: SignatureMap) => {
  const signerPublicKeys: PublicKey[] = [];

  const { rowLength, nodeAccountIdRow, transactionIdCol } =
    getSignedTransactionsDimensions(transaction);

  for (const [nodeAccountId, transactionIds] of signatureMap._map) {
    for (const [transactionId, publicKeys] of transactionIds._map) {
      for (const [publicKeyDer, signature] of publicKeys._map) {
        const publicKey = PublicKey.fromString(publicKeyDer);
        const publicKeyHex = publicKey.toStringRaw();

        const alreadySigned =
          transaction._signerPublicKeys.has(publicKeyHex) ||
          transaction._signerPublicKeys.has(publicKeyDer);

        if (!alreadySigned) {
          const row = nodeAccountIdRow[nodeAccountId];
          const col = transactionIdCol[transactionId];

          const bodyBytes = transaction._signedTransactions.get(col * rowLength + row).bodyBytes;

          const signatureValid = publicKey.verify(bodyBytes, signature);

          if (signatureValid) {
            signerPublicKeys.push(publicKey);
          } else {
            throw new Error('Invalid signature');
          }
        }
      }
    }
  }

  return signerPublicKeys;
};
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L64-64)
```typescript
  validateSignature,
```

**File:** back-end/libs/common/src/decorators/is-signature-map.decorator.ts (L47-59)
```typescript
          for (const publicKey in publicKeys) {
            const signature = publicKeys[publicKey];
            const decodedSignature = new Uint8Array(decode(signature));

            if (decodedSignature.length === 0) {
              throw new BadRequestException(ErrorCodes.ISNMP);
            }

            signatureMap.addSignature(
              AccountId.fromString(nodeAccountId),
              TransactionId.fromString(transactionId),
              PublicKey.fromString(publicKey),
              decodedSignature,
```
