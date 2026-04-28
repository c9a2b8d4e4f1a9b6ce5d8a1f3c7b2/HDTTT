After thoroughly reviewing the code, the claim is accurate and verifiable. Here is the audit report:

---

# Audit Report

## Title
Missing Access Control in `uploadSignatureMaps` Allows Any Authenticated User to Inject Signatures Into Arbitrary Transactions

## Summary
`SignersService.uploadSignatureMaps` (the handler for `POST /transactions/signers`) processes signature submissions for any active transaction without verifying that the authenticated user has any relationship (creator, signer, observer, or approver) to the target transaction. The sibling endpoint `importSignatures` (`POST /transactions/signatures/import`) correctly calls `verifyAccess` before processing; `uploadSignatureMaps` does not.

## Finding Description

**Root cause — missing `verifyAccess` call in `uploadSignatureMaps`:**

`SignersService.uploadSignatureMaps` calls `validateAndProcessSignatures`, which only checks:
1. Transaction exists in the database.
2. Transaction status is `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`.
3. Every public key in the submitted signature map belongs to the authenticated user's registered keys (`userKeyMap`).

There is no check that the user is a creator, signer, observer, or approver of the target transaction.

In `signers.service.ts`, `validateAndProcessSignatures` builds a key lookup from the caller's own keys and rejects any public key not in that map: [1](#0-0) [2](#0-1) 

This confirms that the only gate is "does this public key belong to the caller?" — not "does the caller have any relationship to this transaction?"

By contrast, `importSignatures` in `transactions.service.ts` explicitly calls `verifyAccess` before any processing: [3](#0-2) 

`verifyAccess` checks all required relationships: [4](#0-3) 

`uploadSignatureMaps` has no equivalent call anywhere in its call chain: [5](#0-4) 

## Impact Explanation

A successful exploit allows an authenticated-but-unauthorized user to:

1. **Mutate transaction bytes** — `sdkTransaction.addSignature` is called and the updated bytes are persisted to the `transaction` table for any active transaction they can enumerate by ID. [6](#0-5) [7](#0-6) 

2. **Create unauthorized `TransactionSigner` records** — the attacker's user ID and key ID are inserted as a signer of the target transaction, granting them a persistent foothold in the transaction's audit trail. [8](#0-7) 

3. **Trigger premature status transitions** — after persisting, `processTransactionStatus` is called, which may advance the transaction to `WAITING_FOR_EXECUTION` or `EXECUTED` if the injected signature satisfies a threshold key requirement. [9](#0-8) 

4. **Dismiss notifications** — `bulkUpdateNotificationReceivers` marks sign-indicator notifications as read for the attacker's user ID on the target transaction. [10](#0-9) 

## Likelihood Explanation

- The attacker only needs a valid authenticated session (any registered, verified user).
- Transaction IDs are sequential integers, trivially enumerable.
- The attacker must have at least one registered key (`UserKey`) in the system, which is a normal prerequisite for any signing user.
- No privileged role is required; a standard user account is sufficient.
- The endpoint is publicly documented via Swagger (`@ApiOperation`, `@ApiBody`). [11](#0-10) 

## Recommendation

Add a `verifyAccess` check inside `validateAndProcessSignatures` (or at the top of `uploadSignatureMaps`) mirroring the pattern already used in `importSignatures`. The transaction must be loaded with its relations (`creatorKey`, `approvers`, `signers`, `observers`) before the check, as `verifyAccess` requires them:

```typescript
// In validateAndProcessSignatures, after fetching the transaction:
if (!(await this.transactionsService.verifyAccess(transaction, user))) {
  return { id, error: ErrorCodes.TNF };
}
```

The `loadTransactionData` query should also be updated to eagerly load the required relations so `verifyAccess` can evaluate them without additional round-trips. [12](#0-11) 

## Proof of Concept

1. Register two accounts: **Alice** (creator of transaction T) and **Bob** (no relationship to T).
2. Bob registers a key pair in the system (`POST /user-keys`).
3. Bob signs the raw transaction bytes for T locally using his private key.
4. Bob calls `POST /transactions/signers` with `[{ id: T.id, signatureMap: <bob_signed_map> }]` using his JWT.
5. The server accepts the request: Bob's public key is found in his own `userKeyMap`, status checks pass, and the signature is added.
6. Observe: the `transaction_signer` table now contains a row for Bob on transaction T; the `transactionBytes` column for T is updated with Bob's signature; if Bob's key satisfies a threshold, the transaction status may advance. [13](#0-12)

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L99-124)
```typescript
  async uploadSignatureMaps(
    dto: UploadSignatureMapDto[],
    user: User,
  ): Promise<{ signers: TransactionSigner[]; notificationReceiverIds: number[] }> {
    // Load all necessary data
    const { transactionMap, signersByTransaction } = await this.loadTransactionData(dto);

    // Validate and process signatures
    const validationResults = await this.validateAndProcessSignatures(
      dto,
      user,
      transactionMap,
      signersByTransaction
    );

    // Persist changes to database
    const { transactionsToProcess, signers, notificationsToDismiss } = await this.persistSignatureChanges(validationResults, user);

    // Update transaction statuses and emit notifications
    await this.updateStatusesAndNotify(transactionsToProcess);

    return {
      signers: Array.from(signers),
      notificationReceiverIds: notificationsToDismiss,
    };
  }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L127-133)
```typescript
  private async loadTransactionData(dto: UploadSignatureMapDto[]) {
    const transactionIds = dto.map(item => item.id);

    // Batch load all transactions
    const transactions = await this.dataSource.manager.find(Transaction, {
      where: { id: In(transactionIds) },
    });
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L155-199)
```typescript
  private async validateAndProcessSignatures(
    dto: UploadSignatureMapDto[],
    user: User,
    transactionMap: Map<number, Transaction>,
    signersByTransaction: Map<number, Set<number>>
  ) {
    // Build user key lookup once
    const userKeyMap = new Map<string, UserKey>();
    for (const key of user.keys) {
      userKeyMap.set(key.publicKey, key);
    }

    return Promise.all(
      dto.map(async ({ id, signatureMap: map }) => {
        try {
          const transaction = transactionMap.get(id);
          if (!transaction) return { id, error: ErrorCodes.TNF };

          // Validate transaction status
          const statusError = this.validateTransactionStatus(transaction);
          if (statusError) return { id, error: statusError };

          // Process signatures
          const { sdkTransaction, userKeys, isSameBytes } = await this.processTransactionSignatures(
            transaction,
            map,
            userKeyMap,
            signersByTransaction.get(id) || new Set()
          );

          return {
            id,
            transaction,
            sdkTransaction,
            userKeys,
            isSameBytes,
            error: null,
          };
        } catch (err) {
          console.error(`[TX ${id}] Error:`, err.message);
          return { id, error: err.message };
        }
      })
    );
  }
```

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

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L296-299)
```typescript
      if (!isSameBytes) {
        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());
        transactionsToUpdate.push({ id, transactionBytes: transaction.transactionBytes });
      }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L302-309)
```typescript
      if (userKeys.length > 0) {
        const newSigners = userKeys.map(userKey => ({
          userId: user.id,
          transactionId: id,
          userKeyId: userKey.id,
        }));
        signersToInsert.push(...newSigners);
      }
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L374-403)
```typescript
  private async bulkUpdateNotificationReceivers(
    manager: any,
    notificationsToUpdate: { userId: number; transactionId: number }[]
  ) {
    if (!notificationsToUpdate.length) return [];

    // Separate arrays of userIds and transactionIds
    const userIds = notificationsToUpdate.map(n => n.userId);
    const txIds = notificationsToUpdate.map(n => n.transactionId);

    // Use UNNEST to preserve 1:1 pairing between userIds and transactionIds
    const [rows] = await manager.query(
      `
      WITH input(user_id, tx_id) AS (
        SELECT * FROM UNNEST($1::int[], $2::int[])
      )
      UPDATE notification_receiver nr
      SET "isRead" = true,
          "updatedAt" = NOW()
      FROM notification n, input i
      WHERE nr."notificationId" = n.id
        AND n.type = 'TRANSACTION_INDICATOR_SIGN'
        AND i.tx_id = n."entityId"
        AND i.user_id = nr."userId"
        AND nr."isRead" = false
      RETURNING nr.id, nr."userId"
      `,
      [userIds, txIds]
    );
    return rows;
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L421-437)
```typescript
  private async updateStatusesAndNotify(
    transactionsToProcess: Array<{ id: number; transaction: Transaction }>
  ) {
    if (transactionsToProcess.length === 0) return;

    // Process statuses in bulk
    let statusMap: Map<number, TransactionStatus>;
    try {
      statusMap = await processTransactionStatus(
        this.txRepo,
        this.transactionSignatureService,
        transactionsToProcess.map(t => t.transaction)
      );
    } catch (err) {
      console.error('Bulk status processing failed:', err);
      statusMap = new Map();
    }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L529-532)
```typescript
        /* Verify that the transaction exists and access is verified */
        if (!(await this.verifyAccess(transaction, user))) {
          throw new BadRequestException(ErrorCodes.TNF);
        }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L786-809)
```typescript
  async verifyAccess(transaction: Transaction, user: User): Promise<boolean> {
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (
      [
        TransactionStatus.EXECUTED,
        TransactionStatus.EXPIRED,
        TransactionStatus.FAILED,
        TransactionStatus.CANCELED,
        TransactionStatus.ARCHIVED,
      ].includes(transaction.status)
    )
      return true;

    const userKeysToSign = await this.userKeysToSign(transaction, user, true);

    return (
      userKeysToSign.length !== 0 ||
      transaction.creatorKey?.userId === user.id ||
      !!transaction.observers?.some(o => o.userId === user.id) ||
      !!transaction.signers?.some(s => s.userKey?.userId === user.id) ||
      !!transaction.approvers?.some(a => a.userId === user.id)
    );
  }
```

**File:** back-end/apps/api/src/transactions/signers/signers.controller.ts (L100-119)
```typescript
  @Post()
  @HttpCode(201)
  async uploadSignatureMap(
    @Body() body: UploadSignatureMapDto | UploadSignatureMapDto[],
    @GetUser() user: User,
    @Query('includeNotifications') includeNotifications?: boolean,
  ): Promise<TransactionSigner[] | UploadSignatureMapResponseDto> {
    const transformedSignatureMaps = await transformAndValidateDto(UploadSignatureMapDto, body);

    const { signers, notificationReceiverIds } = await this.signaturesService.uploadSignatureMaps(
      transformedSignatureMaps,
      user,
    );

    if (includeNotifications) {
      return { signers, notificationReceiverIds };
    }

    return signers;
  }
```
