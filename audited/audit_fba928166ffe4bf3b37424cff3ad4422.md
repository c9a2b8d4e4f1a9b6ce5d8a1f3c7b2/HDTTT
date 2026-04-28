### Title
Unhandled `Transaction.fromBytes` Exception Chained with Unsafe `JSON.parse` in Catch Block Crashes Electron Renderer

### Summary
`executeTransaction` in `front-end/src/main/services/localUser/transactions.ts` calls `Transaction.fromBytes(transactionBytes)` outside any try/catch block. When this throws (e.g., on malformed bytes), the raw non-JSON error propagates to the catch block in `ExecutePersonalRequestHandler.vue`, which unconditionally calls `JSON.parse(err.message)` — also without a try/catch. The `JSON.parse` call throws a `SyntaxError` that is completely unhandled, crashing the Electron renderer process.

### Finding Description

**Root cause — Step 1:** `Transaction.fromBytes` is called before the try/catch in `executeTransaction`:

```typescript
// front-end/src/main/services/localUser/transactions.ts
export const executeTransaction = async (transactionBytes: Uint8Array) => {
  const transaction = Transaction.fromBytes(transactionBytes); // ← throws, no guard

  try {
    const response = await transaction.execute(client);
    ...
  } catch (error: any) {
    ...
    throw new Error(JSON.stringify({ status, message: error.message })); // JSON-wraps SDK errors only
  }
};
``` [1](#0-0) 

The try/catch only wraps `transaction.execute(client)` and later operations. A `Transaction.fromBytes` failure bypasses the catch entirely and propagates a raw `Error` (e.g., `"Error: invalid transaction bytes"`) — **not** a JSON string — to the caller.

**Root cause — Step 2:** The caller's catch block blindly calls `JSON.parse` on whatever error message arrives:

```typescript
// ExecutePersonalRequestHandler.vue
} catch (err: any) {
    const data = JSON.parse(err.message); // ← SyntaxError if err.message is not JSON
    status = data.status;
    toastManager.error(data.message);
}
``` [2](#0-1) 

This assumption holds only when the error originates from inside the inner try/catch (which JSON-wraps SDK errors). When `Transaction.fromBytes` throws before that block, the message is plain text, and `JSON.parse` throws a `SyntaxError` that is completely unhandled.

**Additional unguarded call-sites (same class):**

- `ValidateRequestHandler.vue` line 35: `Transaction.fromBytes(request.transactionBytes)` — no try/catch. [3](#0-2) 

- `executeQuery` line 177: `Query.fromBytes(queryBytes)` — outside the try/catch that wraps `query.execute`. [4](#0-3) 

### Impact Explanation
An unhandled `SyntaxError` thrown inside a Vue component's async handler causes an unhandled promise rejection in the Electron renderer process. This crashes or freezes the renderer, making the entire desktop application unusable until restarted. All in-progress work (unsigned transactions, draft state) is lost. The crash is deterministic and reproducible with any malformed byte sequence.

### Likelihood Explanation
The attacker-controlled entry point is the `transactionBytes` field delivered to the execution pipeline. Two realistic paths exist without privileged access:

1. **Malicious organization server**: A user who connects to an attacker-controlled organization server receives transaction bytes crafted to be malformed. When the user clicks "Execute," the crash chain fires. The organization server role is reachable by any party that can host a compatible API endpoint and convince a user to connect.

2. **Malicious transaction file import**: The external-signing feature allows importing `.txf` files. A crafted file with invalid `transactionBytes` triggers the same path when the user attempts execution.

Both paths require one user action (execute/import) that is part of the normal application workflow.

### Recommendation

**Fix 1** — Wrap `Transaction.fromBytes` in `executeTransaction`:
```typescript
export const executeTransaction = async (transactionBytes: Uint8Array) => {
  let transaction: Transaction;
  try {
    transaction = Transaction.fromBytes(transactionBytes);
  } catch (error: any) {
    throw new Error(JSON.stringify({ status: null, message: 'Invalid transaction bytes' }));
  }
  try {
    ...
  } catch (error: any) { ... }
};
```

**Fix 2** — Guard `JSON.parse` in `ExecutePersonalRequestHandler.vue`:
```typescript
} catch (err: any) {
  let data: { status?: number; message?: string } = {};
  try { data = JSON.parse(err.message); } catch { data = { message: err.message }; }
  status = data.status ?? 0;
  toastManager.error(data.message ?? 'Execution failed');
}
```

Apply the same `try/catch` guard to `Query.fromBytes` in `executeQuery` and `Transaction.fromBytes` in `ValidateRequestHandler.vue`.

### Proof of Concept

1. Start the Electron app and connect to an organization server (or use personal mode with an imported file).
2. Inject a transaction record whose `transactionBytes` field is arbitrary garbage (e.g., `new Uint8Array([0x00, 0x01, 0x02])`).
3. Click **Execute** on that transaction.

### Citations

**File:** front-end/src/main/services/localUser/transactions.ts (L138-155)
```typescript
export const executeTransaction = async (transactionBytes: Uint8Array) => {
  const transaction = Transaction.fromBytes(transactionBytes);

  try {
    const response = await transaction.execute(client);

    const receipt = await response.getReceipt(client);

    return { responseJSON: JSON.stringify(response.toJSON()), receiptBytes: receipt.toBytes() };
  } catch (error: any) {
    let status = error.status?._code || null;
    if (!status) {
      status = getStatusCodeFromMessage(error.message);
    }

    throw new Error(JSON.stringify({ status, message: error.message }));
  }
};
```

**File:** front-end/src/main/services/localUser/transactions.ts (L177-178)
```typescript
  const query = Query.fromBytes(queryBytes);

```

**File:** front-end/src/renderer/components/Transaction/TransactionProcessor/components/ExecutePersonalRequestHandler.vue (L99-107)
```vue
  } catch (err: any) {
    const data = JSON.parse(err.message);
    status = data.status;

    emit('transaction:executed', false, null, null);
    toastManager.error(data.message);
  } finally {
    isExecuting.value = false;
  }
```

**File:** front-end/src/renderer/components/Transaction/TransactionProcessor/components/ValidateRequestHandler.vue (L35-36)
```vue
    const transaction = Transaction.fromBytes(request.transactionBytes);
    if (!transaction) throw new Error('Transaction not provided');
```
