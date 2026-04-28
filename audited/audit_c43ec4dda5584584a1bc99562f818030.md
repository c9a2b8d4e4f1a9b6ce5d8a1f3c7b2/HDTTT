### Title
`removeGroupItem` Does Not Renumber `seq` Fields, Causing `editGroupItem` to Silently Corrupt the Wrong Transaction After Deletion

### Summary
`storeTransactionGroup.ts` stores `GroupItem` objects in an ordered array where each item carries a `seq: string` field. `editGroupItem` treats `Number.parseInt(newGroupItem.seq)` as the **array index** of the item to replace. `removeGroupItem` removes an item by array position using `slice` but never renumbers the `seq` fields of the surviving items. After any deletion, `seq` values diverge from array indices, so every subsequent `editGroupItem` call silently writes to the wrong transaction slot.

### Finding Description

**Root cause — `removeGroupItem` leaves `seq` values stale:** [1](#0-0) 

The function removes the element at `index` via `slice` but never iterates over the remaining items to reset their `seq` fields.

**`editGroupItem` uses `seq` as an array index:** [2](#0-1) 

`editIndex = Number.parseInt(newGroupItem.seq)` is used directly as the position in `groupItems.value` to splice. If `seq` no longer matches the item's actual array position, a different item is overwritten.

**`hasObservers` / `hasApprovers` also index by `seq`:** [3](#0-2) 

Both functions use the `seq` argument as a raw array index (`groupItems.value[seq]`), so they too read the wrong item — or `undefined` — after a deletion.

**`duplicateGroupItem` compounds the drift:** [4](#0-3) 

The new item's `seq` is computed as `parseInt(lastItem.seq) + 1`, which continues to diverge from the actual array index.

**Concrete state-corruption path:**

1. User builds a group: `[{seq:'0'}, {seq:'1'}, {seq:'2'}]` → array indices 0, 1, 2.
2. User deletes item at index 0 → array becomes `[{seq:'1'}, {seq:'2'}]` at indices 0, 1.
3. User edits the item they believe is at seq `'1'` (now at array index 0). `editGroupItem({seq:'1', …})` computes `editIndex = 1` and overwrites the item at array index 1 (the one with seq `'2'`).
4. The intended item (array index 0) is untouched; the unintended item (array index 1) receives the new transaction bytes.

### Impact Explanation
The Hedera Transaction Tool is used by the Hedera Council to construct and submit multi-signature transactions that move real HBAR. After a deletion, any edit silently targets the wrong transaction slot. The user sees no error; the modified transaction (wrong recipient, wrong amount, wrong memo) is what gets signed by all co-signers and submitted to the Hedera network. Because the corruption is silent and the UI shows the edited values on the correct-looking row, the error is unlikely to be caught before submission.

### Likelihood Explanation
Removing one transaction from a multi-transaction group and then editing another is a routine, documented workflow exposed directly in the `CreateTransactionGroup` UI. The bug is deterministic: it triggers on every `editGroupItem` call that follows any `removeGroupItem` call where the removed item was not the last element. No special attacker capability is required — any user of the tool can trigger it through normal UI interactions.

### Recommendation
After removing an item, renumber all surviving items so `seq` stays in sync with array position:

```typescript
function removeGroupItem(index: number) {
  groupItems.value = [
    ...groupItems.value.slice(0, index),
    ...groupItems.value.slice(index + 1),
  ].map((item, i) => ({ ...item, seq: i.toString() })); // renumber
  setModified();
}
```

Alternatively, change `editGroupItem` to locate the target by `seq` value rather than treating it as an array index:

```typescript
function editGroupItem(newGroupItem: GroupItem) {
  const editIndex = groupItems.value.findIndex(
    item => item.seq === newGroupItem.seq,
  );
  if (editIndex === -1) return;
  // … rest of function unchanged
}
```

The same fix must be applied to `hasObservers` and `hasApprovers` if they are ever called with a `seq` value that may have drifted from the array index.

### Proof of Concept

```typescript
// Reproduce in storeTransactionGroup unit tests (Vitest/Pinia)
store.addGroupItem(createGroupItem({ seq: '0', description: 'tx-A' }));
store.addGroupItem(createGroupItem({ seq: '1', description: 'tx-B' }));
store.addGroupItem(createGroupItem({ seq: '2', description: 'tx-C' }));

// Delete the first item
store.removeGroupItem(0);
// Array is now [{seq:'1', desc:'tx-B'}, {seq:'2', desc:'tx-C'}]

// User intends to edit tx-B (seq='1', now at array index 0)
store.editGroupItem(createGroupItem({ seq: '1', description: 'EDITED' }));

// Expected: groupItems[0].description === 'EDITED'  (tx-B was edited)
// Actual:   groupItems[0].description === 'tx-B'    (tx-B untouched)
//           groupItems[1].description === 'EDITED'  (tx-C was silently overwritten)
```

### Citations

**File:** front-end/src/renderer/stores/storeTransactionGroup.ts (L115-139)
```typescript
  function editGroupItem(newGroupItem: GroupItem) {
    const editIndex = Number.parseInt(newGroupItem.seq);
    if (!(editIndex >= 0 && editIndex < groupItems.value.length)) return;
    const uniqueValidStart = findUniqueValidStart(
      newGroupItem.payerAccountId,
      newGroupItem.validStart.getTime(),
      editIndex,
    );
    if (uniqueValidStart.getTime() !== newGroupItem.validStart.getTime()) {
      const transaction = Transaction.fromBytes(newGroupItem.transactionBytes);
      transaction.setTransactionId(
        createTransactionId(newGroupItem.payerAccountId, uniqueValidStart),
      );
      newGroupItem = {
        ...newGroupItem,
        transactionBytes: transaction.toBytes(),
        validStart: uniqueValidStart,
      };
    }
    groupItems.value = [
      ...groupItems.value.slice(0, editIndex),
      newGroupItem,
      ...groupItems.value.slice(editIndex + 1),
    ];
    setModified();
```

**File:** front-end/src/renderer/stores/storeTransactionGroup.ts (L142-145)
```typescript
  function removeGroupItem(index: number) {
    groupItems.value = [...groupItems.value.slice(0, index), ...groupItems.value.slice(index + 1)];
    setModified();
  }
```

**File:** front-end/src/renderer/stores/storeTransactionGroup.ts (L153-176)
```typescript
  function duplicateGroupItem(index: number) {
    const lastItem = groupItems.value[groupItems.value.length - 1];
    const baseItem = groupItems.value[index];
    const newDate = findUniqueValidStart(
      baseItem.payerAccountId,
      baseItem.validStart.getTime() + 1,
    );
    const transaction = Transaction.fromBytes(baseItem.transactionBytes);
    transaction.setTransactionId(createTransactionId(baseItem.payerAccountId, newDate));
    const newItem = {
      transactionBytes: transaction.toBytes(),
      type: baseItem.type,
      description: baseItem.description,
      seq: (Number.parseInt(lastItem.seq) + 1).toString(),
      keyList: baseItem.keyList,
      observers: baseItem.observers,
      approvers: baseItem.approvers,
      payerAccountId: baseItem.payerAccountId,
      validStart: newDate,
    };

    groupItems.value = [...groupItems.value, newItem];
    setModified();
  }
```

**File:** front-end/src/renderer/stores/storeTransactionGroup.ts (L245-255)
```typescript
  function hasObservers(seq: number) {
    return !(
      groupItems.value[seq].observers === undefined || groupItems.value[seq].observers.length === 0
    );
  }

  function hasApprovers(seq: number) {
    return !(
      groupItems.value[seq].approvers === undefined || groupItems.value[seq].approvers.length === 0
    );
  }
```
