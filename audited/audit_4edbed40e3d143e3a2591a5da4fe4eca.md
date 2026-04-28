### Title
Stale `seq`-to-array-index Mapping in `updateGroup` Causes Transaction Draft Data Corruption After Group Item Removal

### Summary

`updateGroup` in `transactionGroupsService.ts` reconciles the in-memory `groupItems` array with the SQLite database using raw array indices (`0`, `1`, `2`…) as `seq` lookup keys. After a user removes an item from the middle of an existing saved group, the in-memory array shifts but the database `seq` values do not. On the next save, `updateGroup` deletes the wrong DB record and overwrites the wrong draft, permanently corrupting the group's transaction data. A user who then submits the group executes the wrong set of Hedera transactions.

### Finding Description

**Vulnerability class:** State corruption / stale index mapping after element removal (direct analog of the external H-01 report).

**Root cause — `updateGroup` conflates array position with DB `seq`:** [1](#0-0) 

```
const fetchedItems = await ...getGroupItems(id);          // DB rows: seq='0','1','2'
if (fetchedItems.length > groupItems.length) {
  for (const [index, item] of fetchedItems.entries()) {
    if (index < groupItems.length) continue;
    // ← uses array index, not item.seq
    await ...deleteGroupItem(id, index.toString());        // BUG
  }
}
``` [2](#0-1) 

```
for (const [index, item] of groupItems.entries()) {
  if (item.groupId) {
    // ← uses array index as seq key into DB
    const savedItem = await getGroupItem(id, index.toString());  // BUG
    await ...updateDraft(savedItem.transaction_draft_id!, ...);
  }
}
```

**How `seq` values are assigned and why they diverge:**

When a group is first saved, `addGroupWithDrafts` assigns `seq = index.toString()` sequentially: [3](#0-2) 

After the group is fetched back, each in-memory `GroupItem.seq` is set from the DB value: [4](#0-3) 

When the user removes an item, `removeGroupItem` splices the array but **never updates the `seq` fields of the surviving items**: [5](#0-4) 

After removal the in-memory array is `[item(seq='0'), item(seq='2')]` but the DB still holds `seq='0'`, `seq='1'`, `seq='2'`.

**Step-by-step corruption trace (3-item group, remove middle item):**

| Step | In-memory `groupItems` | DB `seq` rows |
|---|---|---|
| After first save | `[A(seq='0'), B(seq='1'), C(seq='2')]` | `'0','1','2'` |
| After `removeGroupItem(1)` | `[A(seq='0'), C(seq='2')]` | `'0','1','2'` (unchanged) |
| `updateGroup` called | — | — |
| Delete loop: `fetchedItems.length(3) > groupItems.length(2)` → deletes `index=2` → `deleteGroupItem(id,'2')` | — | **`seq='2'` deleted** ← wrong item deleted |
| Update loop index=1: `getGroupItem(id,'1')` → finds old B's draft → overwrites it with C's bytes | — | **`seq='1'` now holds C's data** ← wrong draft overwritten |

**Final DB state:** `seq='0'`=A (correct), `seq='1'`=C's data (wrong), `seq='2'`=gone (C's slot deleted). The group is permanently corrupted in SQLite.

### Impact Explanation

When the corrupted group is reloaded and submitted to the Hedera network:
- The transaction that was supposed to be removed (B) is replaced with C's bytes and executed.
- C's original slot is gone, so C is silently dropped.
- For groups containing HBAR transfers, token transfers, or account operations, this means the wrong transactions are submitted — funds can be sent to wrong accounts or in wrong amounts with no warning to the user.
- The corruption is written to the local SQLite database and persists across sessions; there is no automatic recovery path.

### Likelihood Explanation

The trigger is a completely normal user workflow:
1. Create a transaction group with ≥ 2 items.
2. Save it (Personal Mode, local SQLite).
3. Reload the group.
4. Remove any item that is **not** the last one.
5. Save again.

No attacker is required. Any user of the Organization or Personal mode who edits a saved group will hit this path. The only condition that avoids corruption is removing only the last item (in which case `index` and `seq` still coincide).

### Recommendation

Replace the array-index-based DB lookup with the `seq` value stored on each in-memory `GroupItem`, which correctly tracks the DB key regardless of how the array has been mutated:

```typescript
// In the deletion loop — use item.seq, not index
for (const item of fetchedItems) {
  const stillPresent = groupItems.some(gi => gi.seq === item.seq);
  if (!stillPresent) {
    if (item.transaction_draft_id) await deleteDraft(item.transaction_draft_id);
    await ...deleteGroupItem(id, item.seq);
  }
}

// In the update loop — use item.seq, not index.toString()
for (const item of groupItems) {
  if (item.groupId) {
    const savedItem = await getGroupItem(id, item.seq);   // ← use item.seq
    await ...updateDraft(savedItem.transaction_draft_id!, transactionDraft);
  }
}
```

Additionally, `removeGroupItem` should update the `seq` fields of all surviving items to keep them consistent with their new array positions, mirroring the fix recommended in the external report (update the index mapping after the removal): [5](#0-4) 

```typescript
function removeGroupItem(index: number) {
  const next = [...groupItems.value.slice(0, index), ...groupItems.value.slice(index + 1)];
  // Re-number seq to match new array positions
  groupItems.value = next.map((item, i) => ({ ...item, seq: i.toString() }));
  setModified();
}
```

### Proof of Concept

**Preconditions:** Personal Mode, local SQLite database.

1. Create a transaction group with three HBAR-transfer transactions (A → X 10 ℏ, A → Y 20 ℏ, A → Z 30 ℏ). Save the group. Note DB state: `seq='0'`=10 ℏ, `seq='1'`=20 ℏ, `seq='2'`=30 ℏ.

2. Reload the group. Remove the middle item (20 ℏ transfer, index 1) via `handleDeleteGroupItem(1)` in `CreateTransactionGroup.vue`. [6](#0-5) 

3. Save the group. `updateGroup` is called with `groupItems = [A(seq='0'), C(seq='2')]` and `fetchedItems = [{seq:'0'},{seq:'1'},{seq:'2'}]`. [7](#0-6) 

   - Deletion loop: `fetchedItems.length(3) > groupItems.length(2)` → `deleteGroupItem(id, '2')` deletes the 30 ℏ transfer (wrong).
   - Update loop index=1: `getGroupItem(id, '1')` returns the 20 ℏ draft → overwrites it with 30 ℏ bytes.

4. Reload the group. Observe: two items remain — `seq='0'`=10 ℏ (correct) and `seq='1'`=30 ℏ (wrong; should be absent). The 30 ℏ transfer that was supposed to be kept is now at the wrong seq slot, and the 20 ℏ transfer that was supposed to be removed is gone but its slot now holds 30 ℏ data.

5. Submit the group. The 30 ℏ transfer executes instead of the intended 10 ℏ-only group, demonstrating direct financial impact.

### Citations

**File:** front-end/src/renderer/services/transactionGroupsService.ts (L71-76)
```typescript
      const groupItem: Prisma.GroupItemUncheckedCreateInput = {
        transaction_draft_id: draft.id,
        transaction_group_id: group.id,
        seq: index.toString(),
      };
      await window.electronAPI.local.transactionGroups.addGroupItem(groupItem);
```

**File:** front-end/src/renderer/services/transactionGroupsService.ts (L124-134)
```typescript
    const fetchedItems = await window.electronAPI.local.transactionGroups.getGroupItems(id);
    if (fetchedItems.length > groupItems.length) {
      for (const [index, item] of fetchedItems.entries()) {
        if (index < groupItems.length) {
          continue;
        }
        if (item.transaction_draft_id) {
          await deleteDraft(item.transaction_draft_id);
        }
        await window.electronAPI.local.transactionGroups.deleteGroupItem(id, index.toString());
      }
```

**File:** front-end/src/renderer/services/transactionGroupsService.ts (L136-149)
```typescript
    for (const [index, item] of groupItems.entries()) {
      const transactionDraft: Prisma.TransactionDraftUncheckedUpdateInput = {
        created_at: new Date(),
        updated_at: new Date(),
        user_id: userId,
        transactionBytes: item.transactionBytes.toString(),
        type: getTransactionType(item.transactionBytes),
      };
      if (item.groupId) {
        const savedItem = await getGroupItem(id, index.toString());
        await window.electronAPI.local.transactionDrafts.updateDraft(
          savedItem.transaction_draft_id!,
          transactionDraft,
        );
```

**File:** front-end/src/renderer/stores/storeTransactionGroup.ts (L142-145)
```typescript
  function removeGroupItem(index: number) {
    groupItems.value = [...groupItems.value.slice(0, index), ...groupItems.value.slice(index + 1)];
    setModified();
  }
```

**File:** front-end/src/renderer/stores/storeTransactionGroup.ts (L221-224)
```typescript
      for (const [index, groupItem] of groupItems.value.entries()) {
        groupItem.groupId = newGroupId;
        groupItem.seq = items[index].seq;
      }
```

**File:** front-end/src/renderer/pages/CreateTransactionGroup/CreateTransactionGroup.vue (L107-109)
```vue
function handleDeleteGroupItem(index: number) {
  transactionGroup.removeGroupItem(index);
}
```
