I've verified the code. Here is my assessment:

**Confirmed facts:**
- `NotificationPreferencesController` line 19: `@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard)` — `VerifiedUserGuard` is absent. [1](#0-0) 
- Every other controller in the same package applies all three guards. [2](#0-1) [3](#0-2) 
- `VerifiedUserGuard` allows bypass only when `@AllowNonVerifiedUser()` is present; no such decorator exists on either notification-preferences endpoint. [4](#0-3) 
- `@AllowNonVerifiedUser()` is used intentionally on specific endpoints (`GET /users/me`, `GET /users/public-owner/:publicKey`) in `UsersController`. [5](#0-4) 
- The two exposed endpoints are `PATCH /notification-preferences` and `GET /notification-preferences`. [6](#0-5) 

The structural finding is real and confirmed. However, the impact described in the report is significantly overstated. The endpoints only operate on the **authenticated user's own** preferences (via `@GetUser()`), so an unverified user can only read/mutate their own notification settings — not those of other users. The claim about "hiding activity from administrators" is inaccurate; notification preferences control what alerts the user themselves receives, not what is visible to admins or the audit trail.

---

Audit Report

## Title
`NotificationPreferencesController` Missing `VerifiedUserGuard` Allows Unverified Users to Access Notification Preferences

## Summary
`NotificationPreferencesController` omits `VerifiedUserGuard` from its class-level guard chain, while every other controller in the same application applies all three guards (`JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard`). No `@AllowNonVerifiedUser()` decorator is present to indicate this is intentional, making it a structural oversight.

## Finding Description
All controllers under `back-end/apps/api/src/` use:
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
```
`NotificationPreferencesController` uses only:
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard)
``` [7](#0-6) 

`VerifiedUserGuard.canActivate` returns `true` only when `user.status === UserStatus.NONE` (verified) or when `@AllowNonVerifiedUser()` is set on the handler. Neither condition is satisfied here for unverified users, yet the guard is never invoked. [4](#0-3) 

The two affected endpoints are:
- `PATCH /notification-preferences` (`updatePreferences`) [8](#0-7) 
- `GET /notification-preferences` (`getPreferencesOrCreate`) [9](#0-8) 

## Impact Explanation
An authenticated but unverified user (one who has not completed email verification) can read and mutate their **own** notification preferences. The impact is limited to the user's own data — no cross-user data access or privilege escalation is possible. The claim that this allows hiding activity from administrators is inaccurate; notification preferences only govern what alerts the user themselves receives, not the audit trail or admin visibility.

## Likelihood Explanation
Account creation is admin-gated (`/auth/signup`), which significantly limits who can be in an unverified state. An unverified user who possesses a valid JWT (e.g., obtained immediately after admin-created account registration, before email verification) can reach these endpoints directly via HTTP. No race condition or special privilege is required beyond a valid JWT.

## Recommendation
Add `VerifiedUserGuard` to the controller's guard chain to match the pattern used by all sibling controllers:
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
```
If access by unverified users is intentionally desired (e.g., for onboarding flows), explicitly annotate both handlers with `@AllowNonVerifiedUser()` to document the intent. [10](#0-9) 

## Proof of Concept
1. Admin creates a new user account via the admin-gated signup endpoint.
2. The new user logs in and obtains a valid JWT before completing email verification.
3. With that JWT, the user sends:
   ```
   GET /notification-preferences
   Authorization: Bearer <unverified-user-jwt>
   ```
   Response: `200 OK` with the user's notification preferences — `VerifiedUserGuard` is never evaluated.
4. Similarly, `PATCH /notification-preferences` with a body such as `{"type": "TRANSACTION_CREATED", "value": false}` succeeds, mutating the user's own preferences without email verification.

### Citations

**File:** back-end/apps/api/src/notification-preferences/notification-preferences.controller.ts (L17-21)
```typescript
@ApiTags('Notification Preferences')
@Controller('notification-preferences')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard)
@Serialize(NotificationPreferencesDto)
export class NotificationPreferencesController {
```

**File:** back-end/apps/api/src/notification-preferences/notification-preferences.controller.ts (L33-63)
```typescript
  @Patch()
  @HttpCode(200)
  updatePreferences(
    @GetUser() user: User,
    @Body() body: UpdateNotificationPreferencesDto,
  ): Promise<NotificationPreferences> {
    return this.notificationPreferencesService.updatePreferences(user, body);
  }

  @ApiOperation({
    summary: "Get user's notification preferences",
    description:
      'Get notification preferences for the provided user id. If the preferences do not exist, they will be created and be all true by default.',
  })
  @ApiResponse({
    status: 200,
    type: [NotificationPreferencesDto],
  })
  @Get()
  @HttpCode(200)
  async getPreferencesOrCreate(
    @GetUser() user: User,
    @Query('type', new EnumValidationPipe<NotificationType>(NotificationType, true))
    type?: NotificationType,
  ): Promise<NotificationPreferences[]> {
    if (type) {
      return [await this.notificationPreferencesService.getPreferenceOrCreate(user, type)];
    } else {
      return this.notificationPreferencesService.getPreferencesOrCreate(user);
    }
  }
```

**File:** back-end/apps/api/src/users/users.controller.ts (L34-35)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class UsersController {
```

**File:** back-end/apps/api/src/users/users.controller.ts (L60-65)
```typescript
  @AllowNonVerifiedUser()
  @Get('/me')
  @Serialize(UserDto)
  getMe(@GetUser() user: User): User {
    return user;
  }
```

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L54-57)
```typescript
@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
```

**File:** back-end/apps/api/src/guards/verified-user.guard.ts (L12-22)
```typescript
  canActivate(context: ExecutionContext) {
    const { user } = context.switchToHttp().getRequest();

    const allowNonVerifiedUser = this.reflector.get<boolean>(
      ALLOW_NON_VERIFIED_USER,
      context.getHandler(),
    );
    if (allowNonVerifiedUser) return true;

    return user.status === UserStatus.NONE;
  }
```

**File:** back-end/apps/api/src/decorators/allow-non-verified-user.decorator.ts (L1-4)
```typescript
import { SetMetadata } from '@nestjs/common';

export const ALLOW_NON_VERIFIED_USER = 'ALLOW_NON_VERIFIED_USER';
export const AllowNonVerifiedUser = () => SetMetadata(ALLOW_NON_VERIFIED_USER, true);
```
