The code confirms the claim. Here is the audit report:

---

Audit Report

## Title
Unauthenticated Transaction Signer Enumeration: Missing Access Control on `GET /transactions/:transactionId/signers`

## Summary
`SignersController.getSignaturesByTransactionId` performs no transaction-level access control, allowing any authenticated and verified user to retrieve the full signer list (including associated public keys) for any transaction. The parallel `observers` and `approvers` endpoints both enforce per-transaction access checks; the `signers` endpoint does not.

## Finding Description

All three sub-resource controllers share the same controller-level guards:

```ts
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
```

These guards only confirm the caller is authenticated and email-verified. Transaction-level access control must be enforced in the service layer.

**Observers** — `ObserversService.getTransactionObserversByTransactionId` receives the `user` object and throws `UnauthorizedException` if the caller is not the creator, observer, signer, or approver of the transaction: [1](#0-0) 

**Approvers** — `ApproversService.getVerifiedApproversByTransactionId` applies the identical access check: [2](#0-1) 

**Signers** — `SignersController.getSignaturesByTransactionId` passes **no user** to the service: [3](#0-2) 

`SignersService.getSignaturesByTransactionId` issues a bare repository query keyed only on `transactionId`, with no caller identity check: [4](#0-3) 

The inconsistency is further confirmed by the e2e test suite, which explicitly asserts that a user with no relationship to a transaction receives HTTP 200 and the full signer list: [5](#0-4) 

## Impact Explanation

Any authenticated, verified user can:

- Enumerate every `TransactionSigner` row for every transaction in the organization, including transactions they have no relationship to.
- Retrieve the `userKey` relation (public key material) for each signer, mapping public keys to user identities across the entire organization.
- Correlate signing patterns to infer organizational structure and key ownership.

This is a cross-tenant data exposure: the system's own access model (creator / observer / signer / approver) is enforced on observers and approvers but silently bypassed for signers.

## Likelihood Explanation

Exploitation requires only a valid JWT for a verified account — the lowest privilege level in the system. The attack is a single authenticated HTTP GET request with no race condition, chaining, or special timing required. Any malicious insider or compromised low-privilege account can immediately exploit this.

## Recommendation

Mirror the access-control pattern already used by `ObserversService` and `ApproversService`:

1. Pass the authenticated `user` from `SignersController.getSignaturesByTransactionId` into the service method.
2. In `SignersService.getSignaturesByTransactionId`, load the transaction with its `creatorKey`, `observers`, `signers`, and `approvers` relations.
3. Before returning results, verify the caller is the creator, an observer, a signer, or an approver of that transaction — or that the transaction is in a publicly-visible terminal status (EXECUTED, EXPIRED, FAILED, CANCELED, ARCHIVED). Throw `UnauthorizedException` otherwise.

## Proof of Concept

```
# 1. Register and verify a low-privilege account (normal user flow).
# 2. Obtain a JWT via POST /auth/login.
# 3. Enumerate transaction IDs:

for id in $(seq 1 1000); do
  curl -s -H "Authorization: Bearer <JWT>" \
    https://<host>/transactions/$id/signers
done

# Each response returns the full TransactionSigner list including the
# userKey (public key) relation, with no relationship check performed.
```

The controller passes no user to the service: [3](#0-2) 

The service performs no access check: [4](#0-3)

### Citations

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L103-110)
```typescript
    if (
      userKeysToSign.length === 0 &&
      transaction.creatorKey?.userId !== user.id &&
      !transaction.observers.some(o => o.userId === user.id) &&
      !transaction.signers.some(s => s.userKey?.userId === user.id) &&
      !approvers.some(a => a.userId === user.id)
    )
      throw new UnauthorizedException("You don't have permission to view this transaction");
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L142-149)
```typescript
    if (
      userKeysToSign.length === 0 &&
      transaction.creatorKey?.userId !== user.id &&
      !transaction.observers.some(o => o.userId === user.id) &&
      !transaction.signers.some(s => s.userKey?.userId === user.id) &&
      !approvers.some(a => a.userId === user.id)
    )
      throw new UnauthorizedException("You don't have permission to view this transaction");
```

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L54-58)
```typescript
  getSignaturesByTransactionId(
    @Param('transactionId', ParseIntPipe) transactionId: number,
  ): Promise<TransactionSigner[]> {
    return this.signaturesService.getSignaturesByTransactionId(transactionId, true);
  }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L78-96)
```typescript
  getSignaturesByTransactionId(
    transactionId: number,
    withDeleted: boolean = false,
  ): Promise<TransactionSigner[]> {
    if (!transactionId) {
      return null;
    }
    return this.repo.find({
      where: {
        transaction: {
          id: transactionId,
        },
      },
      relations: {
        userKey: true,
      },
      withDeleted,
    });
  }
```

**File:** back-end/apps/api/test/spec/transaction-signers.e2e-spec.ts (L371-386)
```typescript
    it('(GET) should return all signatures for a transaction requested by a user that is not part of the transaction', async () => {
      const transaction = addedTransactions.userTransactions[0];

      const { status, body } = await endpoint.get(`${transaction.id}/signers`, adminAuthToken);

      expect(status).toBe(200);
      expect(body.length).toBeGreaterThan(0);

      expect(body[0]).toEqual(
        expect.objectContaining({
          userKey: expect.objectContaining({
            id: userKey1003.id,
          }),
        }),
      );
    });
```
