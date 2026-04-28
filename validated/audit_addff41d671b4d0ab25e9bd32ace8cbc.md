All code references check out. Here is the audit result:

---

Audit Report

## Title
`addClaim` Unconditionally Creates Duplicate Records When Claim Already Exists

## Summary
`addClaim` in `front-end/src/main/services/localUser/claim.ts` performs a count-check to detect an existing `(user_id, claim_key)` pair but then unconditionally calls `prisma.claim.create` regardless of the result. Because the `Claim` model in `front-end/prisma/schema.prisma` has no `@@unique([user_id, claim_key])` constraint, SQLite silently accepts the duplicate row. All subsequent reads return the original stale value because no `ORDER BY` is applied, making the intended overwrite permanently ineffective.

## Finding Description

**Root cause — check and mutation are decoupled:**

In `front-end/src/main/services/localUser/claim.ts` lines 18–33, the `if` block only logs; it does not branch away from the `create` call. The `create` is unconditionally executed after the `if`, regardless of whether `alreadyAddedCount > 0`:

```typescript
const alreadyAddedCount = await prisma.claim.count({
  where: { user_id: userId, claim_key: claimKey },
});
if (alreadyAddedCount > 0) logger.info('Claim already exists, claim will be overwritten');
return await prisma.claim.create({   // ← always executed
  data: { user_id: userId, claim_key: claimKey, claim_value: claimValue },
});
``` [1](#0-0) 

**No unique constraint in schema:**

The `Claim` model has no `@@unique([user_id, claim_key])` directive, so SQLite accepts duplicate rows without error: [2](#0-1) 

**Stale value always returned on read:**

`getStoredClaim` in `front-end/src/renderer/services/claimService.ts` destructures the first element with no `orderBy`, so the original (first-inserted) row is always returned: [3](#0-2) 

`getUseKeychainClaim` in `front-end/src/main/services/localUser/claim.ts` similarly reads `flags[0]` with no ordering: [4](#0-3) 

**Reachable call sites:**

`dataMigration.ts` calls `addClaim` for three security-relevant keys on every migration run: [5](#0-4) 

`addClaim` is also exposed as the `claim:add` IPC channel callable from the renderer process: [6](#0-5) 

## Impact Explanation

When `addClaim` is called for an already-existing `(userId, claimKey)` pair:

1. A duplicate row is silently inserted into the `Claim` table.
2. All subsequent reads return the **original stale value** — the intended new value is permanently shadowed.
3. For `SELECTED_NETWORK`, if migration runs more than once, the active Hedera network stored in the claim cannot be updated via `addClaim`, potentially causing transactions to be submitted to the wrong network.
4. For `DEFAULT_MAX_TRANSACTION_FEE_CLAIM_KEY`, the fee cap cannot be overwritten, causing the app to enforce a stale fee limit.
5. Duplicate rows accumulate indefinitely, growing the local SQLite database without bound.

Note: The renderer-side `setStoredClaim` helper does correctly call `updateClaim` (not `addClaim`) when a claim already exists, so normal UI update flows are not affected. The primary attack surface is `dataMigration.ts` being triggered more than once and direct `claim:add` IPC calls.

## Likelihood Explanation

The bug is triggered by any second call to `addClaim` with the same `(userId, claimKey)` pair. `dataMigration.ts` calls `addClaim` for three keys on every migration run. If migration is triggered more than once for the same user (e.g., re-import, re-login, or app reinstall without a DB wipe), all three claims are duplicated. The `claim:add` IPC channel is also directly callable from the renderer, making it reachable through normal application flows without any privileged access.

## Recommendation

Replace the `count` + `create` pattern with a Prisma `upsert`, which atomically handles both the create and update cases and eliminates the race condition:

```typescript
return await prisma.claim.upsert({
  where: { user_id_claim_key: { user_id: userId, claim_key: claimKey } },
  update: { claim_value: claimValue },
  create: { user_id: userId, claim_key: claimKey, claim_value: claimValue },
});
```

This also requires adding a `@@unique([user_id, claim_key])` constraint to the `Claim` model in `front-end/prisma/schema.prisma` so Prisma can use the compound field as the `upsert` target. Additionally, reads in `getStoredClaim` and `getUseKeychainClaim` should add `orderBy: { created_at: 'desc' }` as a defensive measure until any existing duplicate rows are cleaned up.

## Proof of Concept

1. Create a user and trigger `migrateUserData(userId)` once — this calls `addClaim(userId, SELECTED_NETWORK, 'mainnet')`, inserting one row.
2. Trigger `migrateUserData(userId)` a second time (e.g., by re-importing) — this calls `addClaim(userId, SELECTED_NETWORK, 'testnet')`, inserting a **second** row.
3. Call `getStoredClaim(userId, SELECTED_NETWORK)` — it returns `'mainnet'` (the first-inserted row), not `'testnet'`.
4. Query the SQLite DB directly: `SELECT * FROM Claim WHERE claim_key = 'SELECTED_NETWORK'` — two rows are present with different `claim_value`s, confirming the silent duplicate insertion.

### Citations

**File:** front-end/src/main/services/localUser/claim.ts (L18-33)
```typescript
  const alreadyAddedCount = await prisma.claim.count({
    where: {
      user_id: userId,
      claim_key: claimKey,
    },
  });

  if (alreadyAddedCount > 0) logger.info('Claim already exists, claim will be overwritten');

  return await prisma.claim.create({
    data: {
      user_id: userId,
      claim_key: claimKey,
      claim_value: claimValue,
    },
  });
```

**File:** front-end/src/main/services/localUser/claim.ts (L92-100)
```typescript
export const getUseKeychainClaim = async () => {
  const flags = await getClaims({
    where: {
      claim_key: USE_KEYCHAIN,
    },
  });
  if (flags.length === 0) throw new Error('Keychain mode not initialized');

  return flags[0].claim_value === 'true';
```

**File:** front-end/prisma/schema.prisma (L180-188)
```text
model Claim {
  id          String   @id @default(uuid())
  user_id     String
  claim_key   String
  claim_value String
  created_at  DateTime @default(now())
  updated_at  DateTime @updatedAt
  user        User     @relation(fields: [user_id], references: [id])
}
```

**File:** front-end/src/renderer/services/claimService.ts (L35-39)
```typescript
  const [claim] = await get({
    where,
  });

  return claim?.claim_value;
```

**File:** front-end/src/main/services/localUser/dataMigration.ts (L247-275)
```typescript
      const { error } = await safeAwait(
        addClaim(
          userId,
          DEFAULT_MAX_TRANSACTION_FEE_CLAIM_KEY,
          Hbar.fromTinybars(result.defaultMaxTransactionFee).toString(HbarUnit.Tinybar),
        ),
      );
      if (error) {
        logger.error('Failed to add default max transaction fee claim', { error });
      }
    }

    defaultNetwork = parseNetwork(
      parsedContent[USER_PROPERTIES_CURRENT_NETWORK_KEY],
      defaultNetwork,
    );
    result.currentNetwork = defaultNetwork;
    const { error } = await safeAwait(addClaim(userId, SELECTED_NETWORK, defaultNetwork));
    if (error) {
      logger.error('Failed to add network claim', { error });
    }

    const credentialsObj = parsedContent[CREDENTIALS_DIRECTORY];
    if (credentialsObj && typeof credentialsObj === 'object') {
      let updatesLocation = Object.keys(credentialsObj)[0];
      updatesLocation = updatesLocation.endsWith('/InputFiles')
        ? updatesLocation
        : updatesLocation + '/InputFiles';
      const { error } = await safeAwait(addClaim(userId, UPDATE_LOCATION, updatesLocation));
```

**File:** front-end/src/main/modules/ipcHandlers/localUser/claim.ts (L6-11)
```typescript
  createIPCChannel('claim', [
    renameFunc(addClaim, 'add'),
    renameFunc(getClaims, 'get'),
    renameFunc(updateClaim, 'update'),
    renameFunc(removeClaims, 'remove'),
  ]);
```
