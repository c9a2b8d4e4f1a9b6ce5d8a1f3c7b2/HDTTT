### Title
Wrong Group Item Edited Due to String Character Indexing in `BaseGroupHandler.vue`

### Summary
In `BaseGroupHandler.vue`, the expression `route.params.seq[0]` is used to retrieve the sequence number of the group item being edited. Because Vue Router stores route params as strings, `[0]` performs JavaScript string character indexing rather than array element access. For any transaction group with 10 or more items, this silently truncates the index to its first digit, causing `editGroupItem` in `storeTransactionGroup.ts` to overwrite the wrong transaction in the group.

### Finding Description

**Root cause — `BaseGroupHandler.vue` line 54:**

When a user clicks "Edit" on a group item, `CreateTransactionGroup.vue` navigates to the edit route with the current array `index` as the `seq` param: [1](#0-0) 

`seq: index` is a number (e.g. `10`). Vue Router serialises it to the string `"10"` in `route.params.seq`.

Back in `BaseGroupHandler.vue`, the seq is recovered as: [2](#0-1) 

`route.params.seq` is a plain string (`"10"`), so `route.params.seq[0]` is JavaScript string character access, returning `"1"` — not the intended `"10"`. This is confirmed by the falsy check elsewhere in the codebase (`!route.params.seq`), which would always be `false` for an array, proving the param is a string. [3](#0-2) 

**Propagation — `storeTransactionGroup.ts` lines 116–138:**

`editGroupItem` uses `Number.parseInt(newGroupItem.seq)` directly as the array index: [4](#0-3) 

The bounds guard `!(editIndex >= 0 && editIndex < groupItems.value.length)` does **not** catch this because `1` is a valid index in any group with 2+ items. The item at position `1` is silently overwritten with the data the user intended for position `10`.

The mapping of truncated indices for groups of 10–19 items:

| Intended index | `seq[0]` | Item actually overwritten |
|---|---|---|
| 10 | "1" | item 1 |
| 11 | "1" | item 1 |
| 15 | "1" | item 1 |
| 20 | "2" | item 2 |

### Impact Explanation
A user managing a transaction group with 10 or more items who edits any item at position ≥ 10 will silently overwrite a different, earlier item in the group. The intended item remains unchanged. If the group is then saved or submitted, the wrong Hedera transaction bytes are persisted or executed on-chain. Depending on the transaction type (e.g. token transfers, account updates), this can result in unintended fund movements or account state changes on the Hedera network with no warning to the user.

### Likelihood Explanation
The trigger condition — a group with 10+ items — is a normal, documented workflow (no upper bound on group size is enforced anywhere in the codebase). Any user who builds a moderately large transaction group and attempts to edit a late-position item will hit this silently. No privileged access or adversarial intent is required; it is a pure correctness failure reachable through normal UI interaction.

### Recommendation
Replace the character-index access with the full string value. In `BaseGroupHandler.vue` line 54, change:

```typescript
// Before (broken for index >= 10)
const seq = action === 'add'
  ? transactionGroup.groupItems.length.toString()
  : route.params.seq[0];

// After (correct)
const seq = action === 'add'
  ? transactionGroup.groupItems.length.toString()
  : Array.isArray(route.params.seq)
      ? route.params.seq[0]
      : route.params.seq as string;
```

Alternatively, pass the index via `route.query.groupIndex` (which is already set correctly as a full number) and use that for both lookup and edit, eliminating the ambiguous `seq` param entirely.

### Proof of Concept

1. Open the Hedera Transaction Tool desktop application and log in.
2. Navigate to **Create Transaction Group**.
3. Add 11 or more transactions to the group (e.g. 11 simple transfer transactions with different memos: `"tx-0"` through `"tx-10"`).
4. Click **Edit** on the transaction at position **10** (the 11th item, labelled `"tx-10"`).
5. Change its memo to `"EDITED"` and save back to the group.
6. Observe the group list: the item at position **1** (`"tx-1"`) now shows memo `"EDITED"`, while the item at position **10** (`"tx-10"`) is unchanged.
7. The root cause: `route.params.seq` = `"10"`, `route.params.seq[0]` = `"1"`, so `editGroupItem` replaces index `1` instead of index `10`. [5](#0-4) [6](#0-5)

### Citations

**File:** front-end/src/renderer/pages/CreateTransactionGroup/CreateTransactionGroup.vue (L128-135)
```vue
function handleEditGroupItem(index: number, type: string) {
  type = type.replace(/\s/g, '');
  router.push({
    name: 'createTransaction',
    params: { type, seq: index },
    query: { groupIndex: index, group: 'true' },
  });
}
```

**File:** front-end/src/renderer/components/Transaction/Create/BaseTransaction/BaseGroupHandler.vue (L50-70)
```vue
  const route = router.currentRoute.value;
  const groupIndex = Number(route.query?.groupIndex?.toString() || 0);

  const seq =
    action === 'add' ? transactionGroup.groupItems.length.toString() : route.params.seq[0];
  const groupId = action === 'add' ? undefined : transactionGroup.groupItems[groupIndex]?.groupId;

  return {
    transactionBytes: transactionBytes,
    type,
    accountId: '',
    seq,
    groupId,
    keyList: keys,
    observers,
    approvers,
    payerAccountId: payerId,
    validStart,
    description,
  };
};
```

**File:** front-end/src/renderer/components/Transaction/Create/BaseTransaction/BaseTransactionModal.vue (L243-243)
```vue
        v-if="!route.params.seq && !route.query.draftId && !isFromScratch"
```

**File:** front-end/src/renderer/stores/storeTransactionGroup.ts (L115-145)
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
  }

  function removeGroupItem(index: number) {
    groupItems.value = [...groupItems.value.slice(0, index), ...groupItems.value.slice(index + 1)];
    setModified();
  }
```
