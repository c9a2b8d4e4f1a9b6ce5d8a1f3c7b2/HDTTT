### Title
Wrong Preference Field Checked in `filterReceiversByPreferenceForType` Causes Incorrect Email Notification Delivery

### Summary
In `back-end/apps/notifications/src/receiver/receiver.service.ts`, the `filterReceiversByPreferenceForType` function always evaluates `preference.inApp` regardless of whether it is being called to filter in-app or email recipients. Inside `handleUserRegisteredNotifications`, this function is called twice with identical arguments for both channels, meaning the email recipient list is computed using the in-app opt-in flag instead of the email opt-in flag. This is the direct analog of the external report: a wrong variable is used in a validation/filtering check.

### Finding Description

**Root cause — `filterReceiversByPreferenceForType` always reads `preference.inApp`:** [1](#0-0) 

```typescript
const preference = user.notificationPreferences?.find(
  p => p.type === notificationType
);

if (preference ? preference.inApp : true) {   // ← always inApp, never email
  result.push(id);
}
```

The function has no channel parameter; it unconditionally checks `preference.inApp`.

**Call site — `handleUserRegisteredNotifications` calls it twice with identical arguments:** [2](#0-1) 

```typescript
// Intended: in-app filter
const inAppReceiverUserIds = await this.filterReceiversByPreferenceForType(
  entityManager, NotificationType.USER_REGISTERED, adminUserIds, cache,
);

// Intended: email filter — but uses SAME arguments, so checks inApp again
const emailReceiverUserIds = await this.filterReceiversByPreferenceForType(
  entityManager, NotificationType.USER_REGISTERED, adminUserIds, cache,
);
```

`inAppReceiverUserIds` and `emailReceiverUserIds` are always identical sets.

**Downstream use of the wrong set:** [3](#0-2) 

```typescript
Array.from(allReceiverIds).map(adminUserId => ({
  ...
  isInAppNotified: inAppReceiverUserIds.includes(adminUserId) ? false : null,
  isEmailSent:     emailReceiverUserIds.includes(adminUserId) ? false : null, // ← wrong set
  ...
}))
```

Because `emailReceiverUserIds` was filtered by `preference.inApp` instead of `preference.email`, the `isEmailSent` flag is set based on the wrong preference field.

### Impact Explanation

| Admin preference state | Expected behaviour | Actual behaviour |
|---|---|---|
| `inApp: false`, `email: true` | No in-app; receives email | `isEmailSent: null` → **email silently dropped** |
| `inApp: true`, `email: false` | Receives in-app; no email | `isEmailSent: false` → **unwanted email sent** |
| `inApp: true`, `email: true` | Both channels | Both channels (correct by accident) |
| `inApp: false`, `email: false` | Neither channel | Neither channel (correct by accident) |

Admins who explicitly opted out of email notifications receive them anyway (privacy/spam violation). Admins who opted in to email but not in-app silently miss the `USER_REGISTERED` notification entirely.

### Likelihood Explanation

This triggers on every user registration event that reaches `processUserRegisteredNotifications`. Any admin with mismatched `inApp`/`email` preferences will be affected on every registration. No attacker action is required; the bug fires automatically through normal product use.

### Recommendation

`filterReceiversByPreferenceForType` must accept a channel parameter so it can check the correct preference field:

```typescript
private async filterReceiversByPreferenceForType(
  entityManager: EntityManager,
  notificationType: NotificationType,
  userIds: Set<number>,
  cache: Map<number, User>,
  channel: 'inApp' | 'email' = 'inApp',   // ← add channel
): Promise<number[]> {
  ...
  if (preference ? preference[channel] : true) {   // ← use channel
    result.push(id);
  }
  ...
}
```

Then in `handleUserRegisteredNotifications`:

```typescript
const inAppReceiverUserIds = await this.filterReceiversByPreferenceForType(
  entityManager, NotificationType.USER_REGISTERED, adminUserIds, cache, 'inApp',
);
const emailReceiverUserIds = await this.filterReceiversByPreferenceForType(
  entityManager, NotificationType.USER_REGISTERED, adminUserIds, cache, 'email', // ← correct field
);
```

### Proof of Concept

1. Create two admin accounts:
   - **Admin A**: `notificationPreferences` for `USER_REGISTERED` → `{ inApp: false, email: true }`
   - **Admin B**: `notificationPreferences` for `USER_REGISTERED` → `{ inApp: true, email: false }`
2. Trigger a new user registration so `processUserRegisteredNotifications` fires.
3. Observe the `NotificationReceiver` rows created:
   - **Admin A**: `isEmailSent = null` (email dropped — should be `false`/queued)
   - **Admin B**: `isEmailSent = false` (email queued — should be `null`/suppressed)
4. Root cause confirmed: both `inAppReceiverUserIds` and `emailReceiverUserIds` contain exactly the same user IDs because `filterReceiversByPreferenceForType` reads `preference.inApp` in both calls. [4](#0-3) [5](#0-4)

### Citations

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L271-296)
```typescript
  private async filterReceiversByPreferenceForType(
    entityManager: EntityManager,
    notificationType: NotificationType,
    userIds: Set<number>,
    cache: Map<number, User>, // User with preferences relation
  ): Promise<number[]> {
    // Load uncached users
    await this.loadUsersWithPreferences(entityManager, Array.from(userIds), cache);

    // Filter based on preferences
    const result: number[] = [];
    for (const id of userIds) {
      const user = cache.get(id);
      if (!user) continue; // Safety check

      const preference = user.notificationPreferences?.find(
        p => p.type === notificationType
      );

      if (preference ? preference.inApp : true) {
        result.push(id);
      }
    }

    return result;
  }
```

**File:** back-end/apps/notifications/src/receiver/receiver.service.ts (L892-971)
```typescript
  private async handleUserRegisteredNotifications(
    entityManager: EntityManager,
    userId: number,
    adminUserIds: Set<number>,
    additionalData: any,
    cache: Map<number, User>,
    inAppNotifications: { [userId: number]: NotificationReceiver[] },
    emailNotifications: { [email: string]: Notification[] },
    inAppReceiverIds: number[],
    emailReceiverIds: number[],
  ): Promise<void> {
    // Get admin users who want in-app notifications (filtered by preferences)
    const inAppReceiverUserIds = await this.filterReceiversByPreferenceForType(
      entityManager,
      NotificationType.USER_REGISTERED,
      adminUserIds,
      cache,
    );

    // Get admin users who want email notifications (filtered by preferences)
    const emailReceiverUserIds = await this.filterReceiversByPreferenceForType(
      entityManager,
      NotificationType.USER_REGISTERED,
      adminUserIds,
      cache,
    );

    // Combine all receivers (union of in-app and email preferences)
    const allReceiverIds = new Set([...inAppReceiverUserIds, ...emailReceiverUserIds]);

    if (allReceiverIds.size === 0) {
      // Nothing to do
      return;
    }

    // Create single notification for both in-app and email
    const notification = await entityManager.save(Notification, {
      type: NotificationType.USER_REGISTERED,
      entityId: userId,
      notificationReceivers: [],
      additionalData,
    });

    // Create receivers for all admins who want either notification type
    const receivers = await entityManager.save(
      NotificationReceiver,
      Array.from(allReceiverIds).map(adminUserId => ({
        notificationId: notification.id,
        userId: adminUserId,
        isRead: false,
        isInAppNotified: inAppReceiverUserIds.includes(adminUserId) ? false : null,
        isEmailSent: emailReceiverUserIds.includes(adminUserId) ? false : null,
        notification,
      })),
    );

    // Separate receivers for in-app vs email delivery
    const inAppReceiverIdSet = new Set(inAppReceiverUserIds);
    const emailReceiverIdSet = new Set(emailReceiverUserIds);

    const inAppReceivers = receivers.filter(r => inAppReceiverIdSet.has(r.userId));
    const emailReceivers = receivers.filter(r => emailReceiverIdSet.has(r.userId));

    // Collect in-app notifications
    this.collectInAppNotifications(
      inAppReceivers,
      [],
      inAppNotifications,
      inAppReceiverIds,
    );

    // Collect email notifications
    this.collectEmailNotifications(
      emailReceivers,
      [],
      emailNotifications,
      emailReceiverIds,
      cache,
    );
  }
```
