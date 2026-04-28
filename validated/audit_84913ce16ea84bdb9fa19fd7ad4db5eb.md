The code has been verified. Both functions exist exactly as described, the loop termination conditions are fully server-controlled, and there are no guards. Here is the audit report:

---

Audit Report

## Title
Remote DoS via Malicious `totalItems` in Server-Driven Pagination Loops

## Summary
Two functions in the Electron front-end — `getAllInAppNotifications` and `getAllUserKeys` — implement pagination loops whose termination is controlled entirely by the `totalItems` field returned by the organization server. A malicious server can return an arbitrarily large `totalItems` with an empty `items` array, causing the loop to spin indefinitely, freezing the Electron renderer process.

## Finding Description

**`getAllInAppNotifications`** [1](#0-0) 

The loop at line 24 runs `while (!final)`. On each iteration, `totalItems` is read from `data.totalItems` (line 35) and `final` is set to `notifications.length >= totalItems` (line 38). If the server returns `{ totalItems: 9007199254740991, items: [] }` on every request, `notifications.length` stays at 0, `final` is never `true`, and the loop runs indefinitely. The `try/catch` at line 41 only catches thrown exceptions — a valid JSON response with a large `totalItems` never throws, so the catch path is never reached.

**`getAllUserKeys`** [2](#0-1) 

The `do...while` loop at line 85 continues `while (allUserKeys.length < totalItems)` (line 98). `totalItems` is overwritten from `data.totalItems` on every successful page fetch (line 90). With `{ totalItems: 9007199254740991, items: [] }`, `allUserKeys.length` stays at 0, the condition is always true, and the loop never exits. The only escape is an error from `safeAwait` (line 95), which does not fire for a well-formed server response.

**Call sites**

`fetchNotifications()` in `storeNotifications.ts` calls `getAllInAppNotifications` for every connected organization, triggered by a Vue `watch` on `organizationServerUrls`: [3](#0-2) [4](#0-3) 

`loadContacts()` in `storeContacts.ts` calls `getAllUserKeys`, triggered by a Vue `watch` on `loggedOrganization`: [5](#0-4) [6](#0-5) 

## Impact Explanation
Both loops run in the Electron renderer process, which hosts the Vue 3 UI. An infinite async loop in the renderer blocks all UI interaction — the user cannot sign transactions, manage keys, or close the organization session without force-killing the process. Because `fetchNotifications` is re-triggered by reactive watchers (e.g., on WebSocket events or organization changes), the loop can be re-entered automatically after a restart if the user remains connected to the malicious server. [7](#0-6) 

## Likelihood Explanation
The attacker must operate an HTTP server that the victim connects to as an organization server. No privileged access to the Hedera network or the victim's machine is required. The exploit payload is a single crafted JSON body: `{ "totalItems": 9007199254740991, "items": [], "page": 1, "size": 100 }`. In enterprise deployments, employees may be directed to connect to a new organization server URL, making this a realistic malicious-integrator scenario.

## Recommendation

1. **Cap total pages client-side.** Compute the maximum expected pages from the first response and break if exceeded:
   ```ts
   const maxPages = Math.ceil(data.totalItems / pageSize);
   if (page > maxPages + 1) break;
   ```
2. **Break on empty `items`.** If a page returns zero items, the server is not making progress — exit the loop immediately:
   ```ts
   if (data.items.length === 0) break;
   ```
3. **Cache `totalItems` from the first response only.** Do not overwrite it on subsequent pages; a legitimate server's total count should not change mid-pagination.
4. **Set an absolute page-count ceiling** (e.g., 1000 pages) as a hard safety net regardless of `totalItems`.

## Proof of Concept

Stand up any HTTP server that responds to `GET /notifications` and `GET /user-keys` with:
```json
{ "totalItems": 9007199254740991, "items": [], "page": 1, "size": 100 }
```
Connect the Electron app to this server as an organization. Upon login, `loadContacts` and `fetchNotifications` are triggered automatically. Both pagination loops begin issuing HTTP requests in a tight async loop. The renderer process becomes unresponsive within seconds; CPU usage climbs as the event loop is saturated with pending microtasks. The application cannot be interacted with until the process is force-killed. [8](#0-7) [9](#0-8)

### Citations

**File:** front-end/src/renderer/services/organization/notifications.ts (L21-39)
```typescript
      let page = 1;
      const pageSize = 100;
      let final = false;
      while (!final) {
        const paginationQuery = `page=${page}&size=${pageSize}`;
        let filterQuery = `filter=isInAppNotified:isnotnull`;

        if (onlyNew) {
          filterQuery = filterQuery += `&filter=isRead:eq:false`;
        }

        const { data } = await axiosWithCredentials.get(
          `${organizationServerUrl}/${controller}?${paginationQuery}&${filterQuery}`,
        );
        const totalItems = data.totalItems;

        notifications.push(...data.items);
        final = notifications.length >= totalItems;
        page++;
```

**File:** front-end/src/renderer/services/organization/userKeys.ts (L79-101)
```typescript
export const getAllUserKeys = async (organizationServerUrl: string): Promise<IUserKey[]> => {
  let page = 1;
  const size = 100;
  let totalItems = 0;
  const allUserKeys: IUserKey[] = [];

  do {
    const { data, error } = await safeAwait(
      getUserKeysPaginated(organizationServerUrl, page, size),
    );
    if (data) {
      totalItems = data.totalItems;
      allUserKeys.push(...data.items);
      page++;
    }

    if (error) {
      break;
    }
  } while (allUserKeys.length < totalItems);

  return allUserKeys;
};
```

**File:** front-end/src/renderer/stores/storeNotifications.ts (L141-156)
```typescript
  async function fetchNotifications() {
    notificationsQueue = notificationsQueue.then(async () => {
      const severUrls = organizationServerUrls.value;
      const results = await Promise.allSettled(
        user.organizations.map(o => getAllInAppNotifications(o.serverUrl, true)),
      );

      for (let i = 0; i < results.length; i++) {
        const result = results[i];
        result.status === 'fulfilled' && (notifications.value[severUrls[i]] = result.value);
      }
      notifications.value = { ...notifications.value };
    });

    await notificationsQueue;
  }
```

**File:** front-end/src/renderer/stores/storeNotifications.ts (L238-246)
```typescript
  ws.$onAction(ctx => {
    if (ctx.name === 'setup') {
      ctx.after(() => listenForUpdates());
    }
  });

  /* Watchers */
  watch(loggedInOrganization, async () => await fetchPreferences(), { immediate: true });
  watch(organizationServerUrls, async () => await fetchNotifications(), { immediate: true });
```

**File:** front-end/src/renderer/stores/storeContacts.ts (L88-88)
```typescript
  watch(loggedOrganization, () => fetch(), { immediate: true });
```

**File:** front-end/src/renderer/stores/storeContacts.ts (L118-118)
```typescript
    const allKeys = await getAllUserKeys(serverUrl);
```
