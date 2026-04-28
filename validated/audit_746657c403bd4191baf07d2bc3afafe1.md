### Title
Silent Error Swallowing in Scheduled Execution Callbacks Causes Transactions to Permanently Expire Instead of Execute

### Summary

In `transaction-scheduler.service.ts`, the `collateAndExecute` and `collateGroupAndExecute` methods schedule `setTimeout` callbacks that perform pre-execution preparation (signature collation via `computeSignatureKey` + `smartCollate`). If any exception is thrown inside these callbacks — for example, a transient mirror node failure during `computeSignatureKey` — the `catch` block only logs the error and the `finally` block deletes the timeout. The transaction is left permanently in `WAITING_FOR_EXECUTION` status with no retry scheduled. The `handleExpiredTransactions` cron will eventually expire it, making the transaction permanently unexecutable.

### Finding Description

**Root cause — `collateAndExecute`:** [1](#0-0) 

The callback calls `this.transactionSignatureService.computeSignatureKey(transaction)` which internally queries the Hedera mirror node. If the mirror node is temporarily unavailable and all retries are exhausted, it throws an `HttpException`. This exception is caught at line 319:

```typescript
} catch (error) {
  console.log(error);   // ← error silently swallowed
} finally {
  this.schedulerRegistry.deleteTimeout(name);  // ← timeout deleted, never re-registered
}
``` [2](#0-1) 

The same pattern exists in `collateGroupAndExecute`: [3](#0-2) 

And in `addExecutionTimeout` and `addGroupExecutionTimeout`: [4](#0-3) [5](#0-4) 

**Why there is no recovery path:**

The cron jobs that call `prepareTransactions` only pick up transactions whose `validStart` falls within a future window: [6](#0-5) 

Once the `validStart` has passed (or is within the 3-minute expiry window), the `handleExpiredTransactions` cron marks the transaction `EXPIRED`: [7](#0-6) 

So the execution window is permanently missed. The transaction is never marked `FAILED` — it is silently expired.

**Mirror node retry exhaustion is realistic:**

The `MirrorNodeClient` has a finite retry limit (`MAX_RETRIES = 3`): [8](#0-7) 

After 3 failed attempts it throws, propagating up through `computeSignatureKey` into the scheduler callback's unguarded path.

**The test suite confirms the silent-swallow behavior:** [9](#0-8) 

The test for "handle error in callback" asserts only that `addGroupExecutionTimeout` was not called — it does not assert that the transaction was marked FAILED or retried. This confirms the design leaves the transaction in an unrecoverable state.

### Impact Explanation

Any transaction in `WAITING_FOR_EXECUTION` whose scheduled collation callback encounters a transient error (mirror node outage, rate limit exhaustion, network blip) will:
1. Have its execution timeout permanently deleted.
2. Remain in `WAITING_FOR_EXECUTION` with no retry.
3. Be expired by the `handleExpiredTransactions` cron once its `validStart` is more than 3 minutes in the past.

The transaction is permanently unexecutable. For a multi-signature transaction tool used by Hedera Council, this means a fully-signed, ready-to-execute transaction is silently discarded due to a transient infrastructure error — with no alert, no retry, and no way for users to recover without creating a new transaction from scratch.

### Likelihood Explanation

The mirror node is an external dependency queried on every execution attempt. Transient failures (HTTP 503, rate limiting, ECONNREFUSED) are realistic in production. The `MirrorNodeClient` retries 3 times with backoff, but a sustained outage of even a few seconds during the narrow execution window (the callback fires 10 seconds before `validStart`) will exhaust retries and trigger the silent-swallow path. No attacker action is required — normal infrastructure instability is sufficient.

### Recommendation

1. **Mark the transaction as FAILED** (not just log) when the collation callback catches an unrecoverable error, so the state is explicit and users are notified:

```typescript
} catch (error) {
  console.error('Collation failed for transaction', transaction.id, error);
  await this.transactionRepo.createQueryBuilder()
    .update(Transaction)
    .set({ status: TransactionStatus.FAILED, executedAt: new Date() })
    .where('id = :id AND status = :currentStatus', {
      id: transaction.id,
      currentStatus: TransactionStatus.WAITING_FOR_EXECUTION,
    })
    .execute();
  emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: transaction.id }]);
}
```

2. **Distinguish transient from permanent errors**: For transient errors (network failures), schedule a retry with backoff before giving up. For permanent errors (transaction oversize), mark as FAILED immediately (already done correctly).

3. **Add alerting**: At minimum, log at `error` level (not `console.log`) so operations teams are aware of silent execution failures.

### Proof of Concept

1. A fully-signed transaction reaches `WAITING_FOR_EXECUTION` status.
2. The `handleTransactionsBetweenNowAndAfterThreeMinutes` cron fires and calls `prepareTransactions`, which calls `collateAndExecute(transaction)`.
3. A `setTimeout` callback is registered to fire 10 seconds before `validStart`.
4. The mirror node becomes temporarily unavailable (e.g., HTTP 503 for 10+ seconds).
5. Inside the callback, `computeSignatureKey` calls the mirror node, exhausts 3 retries, and throws `HttpException: Mirror node request failed`.
6. The `catch` block executes `console.log(error)` and the `finally` block calls `schedulerRegistry.deleteTimeout(name)`.
7. The transaction remains in `WAITING_FOR_EXECUTION`. No new timeout is registered.
8. The `handleExpiredTransactions` cron (running every 10 seconds) eventually sets the transaction to `EXPIRED` once `validStart < now - 3 minutes`.
9. The transaction is permanently lost — never executed, never marked FAILED, no user notification of the root cause.

### Citations

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L86-97)
```typescript
  /* For transactions with valid start between currently valid and 3 minutes */
  @Cron(CronExpression.EVERY_10_SECONDS, {
    name: 'status_update_between_now_and_three_minutes',
  })
  async handleTransactionsBetweenNowAndAfterThreeMinutes() {
    const transactions = await this.updateTransactions(
      this.getThreeMinutesBefore(),
      this.getThreeMinutesLater(),
    );

    await this.prepareTransactions(transactions);
  }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L100-128)
```typescript
  @Cron(CronExpression.EVERY_10_SECONDS, {
    name: 'status_update_expired_transactions',
  })
  async handleExpiredTransactions() {
    const result = await this.transactionRepo
      .createQueryBuilder()
      .update(Transaction)
      .set({ status: TransactionStatus.EXPIRED })
      .where('status IN (:...statuses) AND validStart < :before', {
        statuses: [
          TransactionStatus.NEW,
          TransactionStatus.REJECTED,
          TransactionStatus.WAITING_FOR_EXECUTION,
          TransactionStatus.WAITING_FOR_SIGNATURES,
        ],
        before: this.getThreeMinutesBefore(),
      })
      .returning(['id'])
      .execute();

    if (result.raw.length > 0) {
      emitTransactionStatusUpdate(
        this.notificationsPublisher,
        result.raw.map(t => ({
          entityId: t.id,
        })),
      );
    }
  }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L260-264)
```typescript
      } catch (error) {
        console.log(error);
      } finally {
        this.schedulerRegistry.deleteTimeout(name);
      }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L278-323)
```typescript
    const callback = async () => {
      try {
        const requiredKeys = await this.transactionSignatureService.computeSignatureKey(transaction);

        const sdkTransaction = await smartCollate(transaction, requiredKeys);

        // If the transaction is still too large,
        // set it to failed with the TRANSACTION_OVERSIZE status code
        // update the transaction, emit the event, and delete the timeout
        if (sdkTransaction === null) {
          const result = await this.transactionRepo
            .createQueryBuilder()
            .update(Transaction)
            .set({
              status: TransactionStatus.FAILED,
              executedAt: new Date(),
              statusCode: Status.TransactionOversize._code,
            })
            .where('id = :id AND status = :currentStatus', {
              id: transaction.id,
              currentStatus: TransactionStatus.WAITING_FOR_EXECUTION,
            })
            .returning('id')
            .execute();

          if (result.raw.length > 0) {
            emitTransactionStatusUpdate(
              this.notificationsPublisher,
              result.raw.map(row => ({ entityId: row.id })),
            );
          }
          return;
        }

        // TODO then make sure that front end doesn't allow chunks larger than 2k'
        //NOTE: the transactionBytes are set here but are not to be saved. Otherwise,
        // any signatures that were removed in order to make the transaction fit
        // would be lost.
        transaction.transactionBytes = Buffer.from(sdkTransaction.toBytes());

        this.addExecutionTimeout(transaction);
      } catch (error) {
        console.log(error);
      } finally {
        this.schedulerRegistry.deleteTimeout(name);
      }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L338-345)
```typescript
    const callback = async () => {
      try {
        await this.executeService.executeTransactionGroup(transactionGroup);
      } catch (error) {
        console.log(error);
      } finally {
        this.schedulerRegistry.deleteTimeout(name);
      }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts (L361-368)
```typescript
    const callback = async () => {
      try {
        await this.executeService.executeTransaction(transaction);
      } catch (error) {
        console.log(error);
      } finally {
        this.schedulerRegistry.deleteTimeout(name);
      }
```

**File:** back-end/libs/common/src/transaction-signature/mirror-node.client.ts (L106-134)
```typescript
  private async fetchWithRetry<T>(
    url: string,
    etag?: string,
    attempt = 1,
  ): Promise<HttpResult<T>> {
    try {
      return await this.getMirrorNodeData<T>(url, etag);
    } catch (error) {
      const shouldRetry = this.isRetryableError(error);

      if (!shouldRetry || attempt >= RETRY_CONFIG.MAX_RETRIES) {
        this.logger.error(
          `Request failed after ${attempt} attempt(s) for ${url}: ${error.message}`
        );
        throw new HttpException(
          `Mirror node request failed: ${error.message}`,
          error.response?.status || HttpStatus.SERVICE_UNAVAILABLE,
        );
      }

      const delay = this.calculateBackoffDelay(attempt);
      this.logger.warn(
        `Request failed (attempt ${attempt}/${RETRY_CONFIG.MAX_RETRIES}), ` +
        `retrying in ${delay}ms: ${error.message}`
      );

      await this.delay(delay);
      return this.fetchWithRetry<T>(url, etag, attempt + 1);
    }
```

**File:** back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.spec.ts (L799-807)
```typescript
    it('should handle error in callback', async () => {
      jest.mocked(smartCollate).mockRejectedValue(new Error('Error'));

      service.collateGroupAndExecute(mockTransactionGroup);

      await jest.advanceTimersToNextTimerAsync();

      expect(service.addGroupExecutionTimeout).not.toHaveBeenCalled();
    });
```
