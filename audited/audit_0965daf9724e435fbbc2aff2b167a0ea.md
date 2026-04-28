### Title
`updateOrganization` Lacks Duplicate `nickname`/`serverUrl` Enforcement, Allowing Silent Overwrite of Organization Identity After DB Unique Constraints Were Dropped

### Summary
The `updateOrganization` service function performs no uniqueness check on `nickname` or `serverUrl` before persisting changes. The database-level unique indexes that previously enforced this were explicitly dropped in a migration. The only guard is a renderer-side in-memory check that is trivially bypassed by calling the IPC handler directly. This allows two `Organization` records to share the same `serverUrl`, causing WebSocket connection and session-token state to be silently shared or corrupted between distinct organizations.

### Finding Description

**Root cause — dropped DB constraints, no service-layer guard on update:**

Migration `20240401140043_removed_unique_constraint_on_organizations` permanently dropped both unique indexes: [1](#0-0) 

The `Organization` model in `schema.prisma` has no `@unique` annotation on either field: [2](#0-1) 

`addOrganization` does perform application-level duplicate checks: [3](#0-2) 

`updateOrganization` performs **no such check** — it calls `updateMany` directly with whatever data is supplied: [4](#0-3) 

**Only guard is renderer-side and bypassable:**

`OrganizationsTab.vue` checks `user.organizations.some(org => org.nickname === nickname)` before calling `updateOrganization`: [5](#0-4) 

This check is:
1. Only in the renderer process, not in the main-process service.
2. Based on the in-memory `user.organizations` array, which can be stale.
3. Only covers `nickname`, not `serverUrl`.
4. Completely bypassed by calling the IPC handler directly from the renderer console or any renderer-side code path (e.g., `WorkGroupsTab.vue` calls `addOrganization` with no nickname uniqueness guard at all). [6](#0-5) 

**Exploit flow:**

1. User adds Organization A (`serverUrl: https://org-a.example.com`, `nickname: "Org A"`).
2. User adds Organization B (`serverUrl: https://org-b.example.com`, `nickname: "Org B"`).
3. From the renderer DevTools console (or any renderer-side script), the attacker calls:
   ```js
   window.electronAPI.local.organizations.updateOrganization(orgB.id, { serverUrl: 'https://org-a.example.com' });
   ```
4. No error is returned. Both records now share `serverUrl = https://org-a.example.com`.

### Impact Explanation

`serverUrl` is used as the key for WebSocket connections and session-storage tokens throughout the application: [7](#0-6) 

When two organizations share the same `serverUrl`:
- `ws.disconnect(serverUrl)` disconnects **both** organizations when the user deletes only one.
- `toggleAuthTokenInSessionStorage(serverUrl, '', true)` clears the JWT token for **both** when logging out of one.
- The wrong organization's authentication token is used for API calls, leading to cross-organization credential confusion.
- `getOrganization` uses `findFirst`, so lookups by `serverUrl` silently return whichever record was inserted first, making the second organization's record unreachable through normal application flows — an exact analog to the reference-overwrite described in the external report.

### Likelihood Explanation

The Electron preload script exposes `updateOrganization` directly to the renderer: [8](#0-7) 

Any renderer-side code — including a renderer DevTools console session, a compromised dependency, or a renderer-side XSS — can call this handler with arbitrary data. No privileged OS access is required. The attacker is a normal authenticated user of the desktop application.

### Recommendation

Add the same duplicate checks to `updateOrganization` that exist in `addOrganization`, excluding the record being updated from the count:

```ts
export const updateOrganization = async (id, data) => {
  const prisma = getPrismaClient();
  delete data.Contact; delete data.id; delete data.keyPairs;

  if (data.serverUrl) {
    const count = await prisma.organization.count({
      where: { serverUrl: data.serverUrl, NOT: { id } },
    });
    if (count > 0) throw new Error('Organization with this server URL already exists');
  }

  if (data.nickname) {
    const count = await prisma.organization.count({
      where: { nickname: data.nickname, NOT: { id } },
    });
    if (count > 0) throw new Error('Organization with this nickname already exists');
  }

  await prisma.organization.updateMany({ where: { id }, data });
  return true;
};
```

Additionally, restore the unique indexes at the database level so the constraint is enforced even if application-layer checks are bypassed.

### Proof of Concept

1. Launch the application and register a local user.
2. Add Organization A: `nickname="Org A"`, `serverUrl="https://org-a.example.com"`.
3. Add Organization B: `nickname="Org B"`, `serverUrl="https://org-b.example.com"`.
4. Open the Electron renderer DevTools console and run:
   ```js
   const orgs = await window.electronAPI.local.organizations.getOrganizations();
   const orgB = orgs.find(o => o.nickname === 'Org B');
   await window.electronAPI.local.organizations.updateOrganization(
     orgB.id,
     { serverUrl: 'https://org-a.example.com' }
   );
   ```
5. Call `getOrganizations()` again — both records now have `serverUrl = "https://org-a.example.com"` with no error raised.
6. Delete Organization A from the UI — the WebSocket for Organization B is also disconnected and its session token is cleared, because both share the same `serverUrl` key.

### Citations

**File:** front-end/prisma/migrations/20240401140043_removed_unique_constraint_on_organizations/migration.sql (L1-5)
```sql
-- DropIndex
DROP INDEX "Organization_serverUrl_key";

-- DropIndex
DROP INDEX "Organization_nickname_key";
```

**File:** front-end/prisma/schema.prisma (L50-59)
```text
model Organization {
  id        String @id @default(uuid())
  nickname  String
  serverUrl String
  key       String

  keyPairs                KeyPair[]
  OrganizationCredentials OrganizationCredentials[]
  Contact                 Contact[]
}
```

**File:** front-end/src/main/services/localUser/organizations.ts (L29-53)
```typescript
export const addOrganization = async (organization: Prisma.OrganizationCreateInput) => {
  const prisma = getPrismaClient();

  if (
    (await prisma.organization.count({
      where: {
        serverUrl: organization.serverUrl,
      },
    })) > 0
  ) {
    throw new Error('Organization with this server URL already exists');
  }

  if (
    (await prisma.organization.count({
      where: {
        nickname: organization.nickname,
      },
    })) > 0
  ) {
    throw new Error('Organization with this nickname already exists');
  }

  return await prisma.organization.create({ data: organization });
};
```

**File:** front-end/src/main/services/localUser/organizations.ts (L85-103)
```typescript
export const updateOrganization = async (
  id: string,
  data: Prisma.OrganizationUncheckedUpdateWithoutOrganizationCredentialsInput,
) => {
  const prisma = getPrismaClient();

  delete data.Contact;
  delete data.id;
  delete data.keyPairs;

  await prisma.organization.updateMany({
    where: {
      id,
    },
    data,
  });

  return true;
};
```

**File:** front-end/src/renderer/pages/Settings/components/OrganizationsTab.vue (L49-58)
```vue
const handleDeleteConnection = async (organizationId: string) => {
  assertUserLoggedIn(user.personal);

  const serverUrl = user.organizations.find(org => org.id === organizationId)?.serverUrl || '';
  ws.disconnect(serverUrl);
  toggleAuthTokenInSessionStorage(serverUrl, '', true);
  await user.selectOrganization(null);
  await user.deleteOrganization(organizationId);
  await setLast(null);
  toastManager.success('Connection deleted successfully');
```

**File:** front-end/src/renderer/pages/Settings/components/OrganizationsTab.vue (L77-92)
```vue
const handleChangeNickname = async (e: Event) => {
  assertUserLoggedIn(user.personal);

  const index = editedIndex.value;
  editedIndex.value = -1;

  const nickname = (e.target as HTMLInputElement)?.value?.trim() || '';

  if (nickname.length === 0) {
    toastManager.error('Nickname cannot be empty');
  } else if (user.organizations.some(org => org.nickname === nickname)) {
    toastManager.error('Nickname already exists');
  } else {
    await updateOrganization(user.organizations[index].id, { nickname });
    user.organizations[index].nickname = nickname;
  }
```

**File:** front-end/src/renderer/pages/Settings/components/WorkGroupsTab.vue (L25-39)
```vue
const handleAddOrganization = async () => {
  if (newOrganizationName.value !== '' && newOrganizationServerUrl.value !== '') {
    try {
      await addOrganization({
        nickname: newOrganizationName.value,
        serverUrl: newOrganizationServerUrl.value,
        key: newOrganizationServerPublicKey.value,
      });

      toastManager.success('Organization added successfully');
    } catch (error) {
      toastManager.error(getErrorMessage(error, 'Failed to add organization'));
    }
  }
};
```

**File:** front-end/src/renderer/services/organizationsService.ts (L20-26)
```typescript
export const updateOrganization = async (
  id: string,
  organization: Prisma.OrganizationUncheckedUpdateWithoutOrganizationCredentialsInput,
) =>
  commonIPCHandler(async () => {
    return await window.electronAPI.local.organizations.updateOrganization(id, organization);
  }, `Failed to update organization with id: ${id}`);
```
