### Title
`approveTransaction` Accepts Approvals for SDK-Expired Transactions Due to Missing `isExpired` Check

### Summary

`ApproversService.approveTransaction()` validates transaction status against the database (`WAITING_FOR_SIGNATURES` / `WAITING_FOR_EXECUTION`) but never calls `isExpired()` on the deserialized SDK transaction. `SignersService.validateTransactionStatus()` performs both checks. During the window between when a transaction's `validStart + transactionValidDuration` elapses and when the scheduler marks it `EXPIRED` in the database, any approver can submit and persist an approval for a transaction the Hedera network will unconditionally reject.

### Finding Description

**Root cause — missing `isExpired` call in `approveTransaction`:**

`SignersService.validateTransactionStatus()` performs two checks:

1. DB status must be `WAITING_FOR_SIGNATURES` or `WAITING_FOR_EXECUTION`
2. `isExpired(sdkTransaction)` must return `false` [1](#0-0) 

`isExpired` is imported and used in `signers.service.ts`: [2](#0-1) 

`ApproversService.approveTransaction()` only performs the DB-status check (lines 584–588) and then immediately deserializes the SDK transaction and records the approval. `isExpired` is **not imported** and **not called** anywhere in `approvers.service.ts`: [3](#0-2) [4](#0-3) 

`isExpired` computes expiry from the SDK transaction's `validStart` and `transactionValidDuration`: [5](#0-4) 

The scheduler marks transactions `EXPIRED` asynchronously and periodically: [6](#0-5) 

**Exploit path:**

1. A transaction is created with a short `transactionValidDuration` (minimum is 15 seconds on Hedera).
2. The transaction's SDK-level expiry elapses (`now >= validStart + duration`), but the scheduler has not yet run to flip the DB status to `EXPIRED`.
3. During this window, an approver calls `POST /transactions/:id/approvers/approve`.
4. `approveTransaction` passes the DB-status check (still `WAITING_FOR_SIGNATURES`), deserializes the SDK transaction, verifies the signature, and **persists the approval** to the database.
5. The scheduler eventually marks the transaction `EXPIRED`. The recorded approval is now permanently attached to an unexecutable transaction.

### Impact Explanation

- **State integrity violation**: Approvals are persisted for transactions the Hedera network will unconditionally reject. The invariant that "an approval record implies the transaction is still executable" is broken.
- **Wasted approver effort / misleading UX**: Approvers are not informed that the transaction is already expired at the SDK level; they expend key-management effort (decrypting keys, computing signatures) for a no-op.
- **Inconsistent enforcement**: The signing endpoint correctly rejects expired transactions with `ErrorCodes.TE`; the approval endpoint does not, creating an asymmetric trust boundary within the same transaction lifecycle.

### Likelihood Explanation

- Any authenticated approver can trigger this with no privileged access — the `POST /transactions/:id/approvers/approve` endpoint is reachable by any verified organization user who is listed as an approver.
- The window exists whenever the scheduler's polling interval is non-zero (it is). Transactions with short `transactionValidDuration` values widen the window.
- No special tooling is required; a normal API call suffices. [7](#0-6) 

### Recommendation

Import `isExpired` in `approvers.service.ts` and add the expiry check immediately after the DB-status check in `approveTransaction`, mirroring `SignersService.validateTransactionStatus()`:

```typescript
// After line 588 in approvers.service.ts
const sdkTx = SDKTransaction.fromBytes(transaction.transactionBytes);
if (isExpired(sdkTx)) {
  throw new BadRequestException(ErrorCodes.TE);
}
```

This makes the approval path consistent with the signing path.

### Proof of Concept

1. Create a transaction with `transactionValidDuration` set to its minimum (e.g., 15 s).
2. Wait for `validStart + 15 s` to elapse (SDK expiry), but act before the scheduler's next poll.
3. As a registered approver, call:
   ```
   POST /transactions/{id}/approvers/approve
   Body: { userKeyId: <id>, signature: <valid_sig>, approved: true }
   ```
4. Observe HTTP 200 and the approval record written to `transaction_approver` in the database.
5. Confirm that `isExpired(SDKTransaction.fromBytes(transaction.transactionBytes))` returns `true` for the same transaction bytes — the approval was accepted for an already-expired transaction.
6. Contrast with `POST /transactions/{id}/signers` on the same transaction, which returns `ErrorCodes.TE` (400). [8](#0-7) [1](#0-0)

### Citations

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L12-12)
```typescript
  isExpired,
```

**File:** back-end/apps/api/src/transactions/signers/signers.service.ts (L201-215)
```typescript
  private validateTransactionStatus(transaction: Transaction): string | null {
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    ) {
      return ErrorCodes.TNRS;
    }

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);
    if (isExpired(sdkTransaction)) {
      return ErrorCodes.TE;
    }

    return null;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L1-37)
```typescript
import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';

import {
  DataSource,
  DeepPartial,
  EntityManager,
  FindManyOptions,
  FindOneOptions,
  Repository,
} from 'typeorm';

import { PublicKey, Transaction as SDKTransaction } from '@hiero-ledger/sdk';

import {
  attachKeys,
  emitTransactionStatusUpdate,
  emitTransactionUpdate,
  ErrorCodes,
  TransactionSignatureService,
  NatsPublisherService,
  userKeysRequiredToSign,
  verifyTransactionBodyWithoutNodeAccountIdSignature,
} from '@app/common';
import {
  Transaction,
  TransactionApprover,
  TransactionStatus,
  User,
} from '@entities';

import {
  ApproverChoiceDto,
  CreateTransactionApproverDto,
  CreateTransactionApproversArrayDto,
  UpdateTransactionApproverDto,
} from '../dto';
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L547-621)
```typescript
  async approveTransaction(
    dto: ApproverChoiceDto,
    transactionId: number,
    user: User,
  ): Promise<boolean> {
    /* Get all the approvers */
    const approvers = await this.getVerifiedApproversByTransactionId(transactionId, user);

    /* If user is approver, filter the records that belongs to the user */
    const userApprovers = approvers.filter(a => a.userId === user.id);

    /* Check if the user is an approver */
    if (userApprovers.length === 0)
      throw new UnauthorizedException('You are not an approver of this transaction');

    /* Check if the user has already approved the transaction */
    if (userApprovers.every(a => a.signature)) throw new BadRequestException(ErrorCodes.TAP);

    /* Ensures the user keys are passed */
    await attachKeys(user, this.dataSource.manager);
    if (user.keys.length === 0) return false;

    const signatureKey = user.keys.find(key => key.id === dto.userKeyId);

    /* Gets the public key that the signature belongs to */
    const publicKey = PublicKey.fromString(signatureKey?.publicKey);

    /* Get the transaction body */
    const transaction = await this.dataSource.manager.findOne(Transaction, {
      where: { id: transactionId },
      relations: { creatorKey: true, observers: true },
    });

    /* Check if the transaction exists */
    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    /* Checks if the transaction is requires approval */
    if (
      transaction.status !== TransactionStatus.WAITING_FOR_SIGNATURES &&
      transaction.status !== TransactionStatus.WAITING_FOR_EXECUTION
    )
      throw new BadRequestException(ErrorCodes.TNRA);

    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    /* Verify the signature matches the transaction */
    if (
      !verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTransaction, dto.signature, publicKey)
    )
      throw new BadRequestException(ErrorCodes.SNMP);

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

    const notificationEvent = [{ entityId: transaction.id }];

    if (!dto.approved || userApprovers.every(a => a.approved)) {
      emitTransactionStatusUpdate(this.notificationsPublisher, notificationEvent);
    } else {
      emitTransactionUpdate(this.notificationsPublisher, notificationEvent);
    }

    return true;
  }
```

**File:** back-end/libs/common/src/utils/sdk/transaction.ts (L37-46)
```typescript
export const isExpired = (transaction: SDKTransaction) => {
  if (!transaction.transactionId?.validStart) {
    return true;
  }

  const validStart = transaction.transactionId.validStart.toDate();
  const duration = transaction.transactionValidDuration;

  return new Date().getTime() >= validStart.getTime() + duration * 1_000;
};
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.spec.ts (L266-287)
```typescript
  it('should updates for expired transactions', async () => {
    const rawResult = [
      { id: 1 },
      { id: 2 },
      { id: 3 },
    ];

    setupQueryBuilderMock(rawResult);

    await service.handleExpiredTransactions();

    expect(transactionRepo.createQueryBuilder).toHaveBeenCalled();
    expect(mockQueryBuilder.update).toHaveBeenCalled();
    expect(mockQueryBuilder.set).toHaveBeenCalledWith({ status: TransactionStatus.EXPIRED });
    expect(mockQueryBuilder.returning).toHaveBeenCalled();
    expect(mockQueryBuilder.execute).toHaveBeenCalled();

    expect(emitTransactionStatusUpdate).toHaveBeenCalledWith(
      notificationsPublisher,
      rawResult.map(t => expect.objectContaining({ entityId: t.id })),
    );
  });
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L65-73)
```typescript
  @Post('/approve')
  @OnlyOwnerKey<ApproverChoiceDto>('userKeyId')
  approveTransaction(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Body() body: ApproverChoiceDto,
  ): Promise<boolean> {
    return this.approversService.approveTransaction(body, transactionId, user);
  }
```
