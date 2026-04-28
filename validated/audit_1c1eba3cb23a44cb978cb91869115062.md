### Title
Silent Failure of Observer/Approver Registration in Transaction Group Submission Leaves Parties Unregistered

### Summary
When submitting transaction groups for large file updates (`BigFileOrganizationRequestHandler.vue`) or multiple account updates (`MultipleAccountUpdateRequestHandler.vue`), the observer and approver registration step is wrapped in `safeAwait` whose return value is never inspected. Any failure in registering the intended parties is silently discarded, and the transaction group is reported as successfully submitted. The result is a live transaction with no registered observers or approvers — an exact analog to the UMA "unregistered parties" class.

---

### Finding Description

After a transaction group is submitted to the backend, both handlers call `submitApproversObservers` to register the intended observers and approvers. The call is wrapped in `safeAwait`, which catches all non-native exceptions and returns `{ error }` instead of re-throwing. The return value is **never checked**:

```js
// BigFileOrganizationRequestHandler.vue line 234
// MultipleAccountUpdateRequestHandler.vue line 313
await safeAwait(submitApproversObservers(group));
emit('transaction:group:submit:success', id);   // always fires
```

`safeAwait` is defined to swallow all application-level errors:

```ts
export const safeAwait = async <T>(promise: Promise<T>): Promise<ISafeResult<T>> => {
  try { ... return { data } ... }
  catch (error: unknown) {
    throwNative(error as Error);   // only re-throws EvalError, TypeError, etc.
    return { error };              // all other errors silently returned
  }
};
```

Inside `submitApproversObservers`, each per-item registration is itself wrapped in `Promise.allSettled`, adding a second layer of silence:

```js
async function submitApproversObservers(group: IGroup) {
  const promises = group.groupItems.map(groupItem => {
    const observerPromise = props.observers?.length > 0
      ? addObservers(serverUrl, groupItem.transactionId, props.observers)
      : Promise.resolve();
    const approverPromise = props.approvers?.length > 0
      ? addApprovers(serverUrl, groupItem.transactionId, props.approvers)
      : Promise.resolve();
    return Promise.allSettled([observerPromise, approverPromise]);
  });
  await Promise.allSettled(promises);   // all rejections discarded
}
```

The backend `ObserversService.createTransactionObservers` enforces that only the transaction creator can add observers. If the `creatorKeyId` lookup fails (falls back to `-1`) or any transient error occurs, the HTTP call fails, `Promise.allSettled` discards it, `safeAwait` discards the outer error, and `emit('transaction:group:submit:success', id)` fires unconditionally.

By contrast, the single-transaction path in `OrganizationRequestHandler.vue` at least shows an error toast (though it still emits success):

```js
results.forEach(result => {
  if (result.status === 'rejected') {
    toastManager.error(result.reason.message);   // at least visible
  }
});
```

The group-submission paths have no such fallback.

---

### Impact Explanation

1. **Observer access control broken**: Observers are stored in `transaction_observer` and queried to gate visibility. If registration silently fails, the intended observers have no row in that table and cannot see the transaction at all — a direct access-control failure.
2. **Approver governance bypassed**: Approvers are stored in `transaction_approver`. If registration silently fails, no approver exists for the transaction. The transaction can proceed through its lifecycle (`WAITING_FOR_SIGNATURES → WAITING_FOR_EXECUTION → EXECUTED`) with zero approvals collected, defeating the governance model.
3. **No user feedback**: The creator sees a success toast and believes the transaction is properly configured. There is no indication that the parties were not registered.

---

### Likelihood Explanation

- Any transient network error, HTTP 4xx/5xx from the backend, or a `creatorKeyId` of `-1` (which occurs when `user.selectedOrganization.userKeys.find(k => k.publicKey === keyToSignWith)` returns `undefined`) will cause the registration to fail.
- The `creatorKeyId || -1` fallback is present in all three group-submission paths and will cause the backend to reject the observer/approver POST with a 401 (creator check fails), which is then silently swallowed.
- This is a realistic, non-adversarial failure mode that can occur in normal usage.

---

### Recommendation

1. **Check the `safeAwait` result** and surface the error to the user before emitting success:
   ```js
   const { error } = await safeAwait(submitApproversObservers(group));
   if (error) {
     toastManager.error('Failed to register observers/approvers: ' + getErrorMessage(error));
     // optionally abort or allow retry
   }
   emit('transaction:group:submit:success', id);
   ```
2. **Remove the double-silence**: `submitApproversObservers` should propagate failures rather than using `Promise.allSettled` without inspecting results.
3. **Validate `creatorKeyId` before submission**: If the key lookup returns `undefined`, abort the submission rather than sending `-1`.

---

### Proof of Concept

1. User opens a large file update or multiple-account-update flow with observers/approvers configured.
2. The transaction group is submitted successfully (`submitTransactionGroup` returns an `id`).
3. `submitApproversObservers` is called; the backend returns HTTP 401 because `creatorKeyId` is `-1` (key not found in `userKeys`).
4. `Promise.allSettled` discards the rejection; `safeAwait` catches the outer error and returns `{ error }`.
5. The return value is never read; `emit('transaction:group:submit:success', id)` fires.
6. The user sees a success message. The `transaction_observer` and `transaction_approver` tables have no rows for this transaction.
7. The intended observers query `GET /transactions/:id/observers` and receive 401 ("You don't have permission to view this transaction") — they are invisible to the transaction.
8. The transaction proceeds to execution with no approver records, bypassing any approval requirement.

**Relevant file/line references:**

- `safeAwait` call with unchecked result: [1](#0-0) 
- Same pattern in multiple-account handler: [2](#0-1) 
- `submitApproversObservers` double-silencing via `Promise.allSettled`: [3](#0-2) 
- `safeAwait` implementation — returns `{ error }` without re-throwing: [4](#0-3) 
- `creatorKeyId || -1` fallback that triggers backend 401: [5](#0-4) 
- Backend creator-only guard on observer creation: [6](#0-5) 
- Observer access-control query that gates transaction visibility: [7](#0-6)

### Citations

**File:** front-end/src/renderer/components/Transaction/TransactionProcessor/components/BigFileOrganizationRequestHandler.vue (L219-221)
```vue
        creatorKeyId:
          user.selectedOrganization.userKeys.find(k => k.publicKey === keyToSignWith)?.id || -1,
      },
```

**File:** front-end/src/renderer/components/Transaction/TransactionProcessor/components/BigFileOrganizationRequestHandler.vue (L225-240)
```vue
  try {
    const { id } = await submitTransactionGroup(
      user.selectedOrganization.serverUrl,
      'Automatically created group for large file update',
      false,
      true,
      apiGroupItems,
    );
    const group = await getTransactionGroupById(user.selectedOrganization.serverUrl, id, false);
    await safeAwait(submitApproversObservers(group));
    emit('transaction:group:submit:success', id);
  } catch (error) {
    emit('transaction:group:submit:fail', error);
    throw error;
  }
}
```

**File:** front-end/src/renderer/components/Transaction/TransactionProcessor/components/BigFileOrganizationRequestHandler.vue (L242-261)
```vue
async function submitApproversObservers(group: IGroup) {
  assertIsLoggedInOrganization(user.selectedOrganization);
  const serverUrl = user.selectedOrganization.serverUrl;

  const promises = group.groupItems.map(groupItem => {
    const observerPromise =
      props.observers?.length > 0
        ? addObservers(serverUrl, groupItem.transactionId, props.observers)
        : Promise.resolve();

    const approverPromise =
      props.approvers?.length > 0
        ? addApprovers(serverUrl, groupItem.transactionId, props.approvers)
        : Promise.resolve();

    return Promise.allSettled([observerPromise, approverPromise]);
  });

  await Promise.allSettled(promises);
}
```

**File:** front-end/src/renderer/components/Transaction/TransactionProcessor/components/MultipleAccountUpdateRequestHandler.vue (L304-319)
```vue
  try {
    const { id } = await submitTransactionGroup(
      user.selectedOrganization.serverUrl,
      description || 'Automatically created group for multiple accounts update',
      false,
      true,
      apiGroupItems,
    );
    const group = await getTransactionGroupById(user.selectedOrganization.serverUrl, id, false);
    await safeAwait(submitApproversObservers(group));
    emit('transaction:group:submit:success', id);
  } catch (error) {
    emit('transaction:group:submit:fail', error);
    throw error;
  }
}
```

**File:** front-end/src/renderer/utils/safeAwait.ts (L25-37)
```typescript
export const safeAwait = async <T>(promise: Promise<T>): Promise<ISafeAwaitResult<T>> => {
  try {
    const data = await promise;
    if (data instanceof Error) {
      throwNative(data);
      return { error: data };
    }
    return { data } as ISafeAwaitResultData<T>;
  } catch (error: unknown) {
    throwNative(error as Error);
    return { error };
  }
};
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L44-45)
```typescript
    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to delete it');
```

**File:** back-end/libs/common/src/sql/queries/transaction.queries.ts (L165-175)
```typescript
  if (roles.observer) {
    const userParam = addParam(user.id);
    eligibilityConditions.push(`
      EXISTS (
        SELECT 1
        FROM ${sql.table(TransactionObserver)} tobs
        WHERE tobs.${sql.col(TransactionObserver, 'transactionId')} = t.${sql.col(Transaction, 'id')}
          AND tobs.${sql.col(TransactionObserver, 'userId')} = ${userParam}
      )
    `);
  }
```
