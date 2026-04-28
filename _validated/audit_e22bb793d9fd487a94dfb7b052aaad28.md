Audit Report

## Title
JWT Token Not Revoked on Password Change — Stolen Session Persists After Credential Rotation

## Summary
`PATCH /auth/change-password` successfully updates the user's password but never blacklists the caller's current JWT. An attacker holding a stolen bearer token retains full API access for up to 365 days even after the victim rotates their credentials. The JWT blacklist mechanism exists and is correctly applied on logout and OTP-based password reset, but the password-change path is silently omitted.

## Finding Description

**Root cause — inconsistent blacklist application**

The `changePassword` controller in `auth.controller.ts` delegates entirely to `authService.changePassword()` and returns, with no call to `blacklistService.blacklistToken()`: [1](#0-0) 

Compare this to the `logout` handler, which correctly blacklists the token: [2](#0-1) 

And `setPassword`, which also correctly blacklists after an OTP-based reset: [3](#0-2) 

The `authService.changePassword()` implementation confirms no blacklisting occurs there either — it only validates the old password and calls `usersService.setPassword()`: [4](#0-3) 

**Why the JWT cannot be invalidated by any other means**

The JWT payload contains only `userId` and `email` — no password hash, no credential version, no session ID: [5](#0-4) 

The `JwtStrategy.validate()` only checks whether the user record still exists in the database: [6](#0-5) 

Changing the password does not delete the user record, so the stolen token passes validation indefinitely until it naturally expires.

**Token lifetime**

`JWT_EXPIRATION` defaults to 365 days across all deployment configurations: [7](#0-6) [8](#0-7) [9](#0-8) 

The `BlacklistService` correctly stores revoked tokens in Redis with a TTL equal to `JWT_EXPIRATION` days, but it is never called from the password-change path: [10](#0-9) 

## Impact Explanation

An attacker who obtains a user's bearer token (via XSS, network interception, compromised device, log leakage, etc.) retains complete API access — read all transactions, sign on behalf of the user, view all organization data — for up to **365 days** after the victim changes their password. The victim has no mechanism to revoke the stolen session short of contacting an administrator to delete their account. The existing blacklist infrastructure is fully capable of solving this but is simply not invoked on this code path.

## Likelihood Explanation

The attacker precondition is possession of a valid JWT, which is a realistic outcome of XSS, token leakage in logs, or a compromised client device. No privileged access is required. The victim's natural response to a suspected compromise — changing their password — is entirely ineffective, making the window of exploitation the full remaining token lifetime (up to 365 days). The attack path requires no special tooling: a single HTTP request with the stolen `Authorization: Bearer <token>` header suffices.

## Recommendation

In `AuthController.changePassword()`, add a call to `blacklistService.blacklistToken(extractJwtAuth(req))` after the password is successfully changed, mirroring the pattern already used in `logout()`. The `@Req() req: Request` parameter must also be added to the method signature. This ensures the caller's current session token is immediately invalidated upon credential rotation, consistent with the behavior of the other security-sensitive endpoints.

## Proof of Concept

```
# Step 1: Attacker obtains victim's JWT (e.g., from a compromised device)
STOLEN_TOKEN="<victim_bearer_token>"

# Step 2: Victim changes their password
curl -X PATCH https://<host>/auth/change-password \
  -H "Authorization: Bearer $STOLEN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"oldPassword":"OldPass1!","newPassword":"NewPass2!"}'
# => 200 OK — password changed

# Step 3: Attacker continues using the stolen token — still valid
curl -X GET https://<host>/transactions/history?page=1&size=10 \
  -H "Authorization: Bearer $STOLEN_TOKEN"
# => 200 OK — full access retained, up to 365 days after the password change
```

The stolen token passes `JwtBlackListAuthGuard` (not blacklisted) and `JwtStrategy.validate()` (user still exists), granting uninterrupted access despite the credential rotation.

### Citations

**File:** back-end/apps/api/src/auth/auth.controller.ts (L99-104)
```typescript
  @Post('/logout')
  @HttpCode(200)
  @UseGuards(JwtBlackListAuthGuard, JwtAuthGuard)
  async logout(@Req() req: Request) {
    await this.blacklistService.blacklistToken(extractJwtAuth(req));
  }
```

**File:** back-end/apps/api/src/auth/auth.controller.ts (L115-119)
```typescript
  @Patch('/change-password')
  @UseGuards(JwtBlackListAuthGuard, JwtAuthGuard)
  async changePassword(@GetUser() user: User, @Body() dto: ChangePasswordDto): Promise<void> {
    return this.authService.changePassword(user, dto);
  }
```

**File:** back-end/apps/api/src/auth/auth.controller.ts (L170-175)
```typescript
  @UseGuards(JwtBlackListOtpGuard, OtpVerifiedAuthGuard)
  @Patch('/set-password')
  async setPassword(@GetUser() user: User, @Body() dto: NewPasswordDto, @Req() req): Promise<void> {
    await this.authService.setPassword(user, dto.password);
    await this.blacklistService.blacklistToken(extractJwtOtp(req));
  }
```

**File:** back-end/apps/api/src/auth/auth.service.ts (L72-80)
```typescript
  async login(user: User) {
    const payload: JwtPayload = { userId: user.id, email: user.email };
    const expiresIn = `${this.configService.get('JWT_EXPIRATION')}d`;

    const accessToken: string = this.jwtService.sign(payload, {
      expiresIn,
    });

    return accessToken;
```

**File:** back-end/apps/api/src/auth/auth.service.ts (L83-95)
```typescript
  /* Change the password for the given user */
  async changePassword(user: User, { oldPassword, newPassword }: ChangePasswordDto): Promise<void> {
    if (oldPassword === newPassword) throw new BadRequestException(ErrorCodes.NPMOP);

    const { correct } = await this.dualCompareHash(oldPassword, user.password);
    if (!correct) throw new BadRequestException(ErrorCodes.INOP);

    if (user.status === UserStatus.NEW && user.keys.length === 0) {
      emitUserStatusUpdateNotifications(this.notificationsPublisher, { entityId: user.id, additionalData: { username: user.email } });
    }

    await this.usersService.setPassword(user, newPassword);
  }
```

**File:** back-end/apps/api/src/auth/strategies/jwt.strategy.ts (L26-32)
```typescript
  async validate({ userId }: JwtPayload): Promise<User> {
    const user = await this.usersService.getUser({ id: userId });

    if (!user) throw new UnauthorizedException();

    return user;
  }
```

**File:** back-end/apps/api/.env.test (L13-13)
```text
JWT_EXPIRATION=365
```

**File:** back-end/apps/api/example.env (L13-13)
```text
JWT_EXPIRATION=365
```

**File:** back-end/k8s/back-end/api-deployment.yaml (L63-64)
```yaml
            - name: JWT_EXPIRATION
              value: '365'
```

**File:** back-end/libs/common/src/blacklist/blacklist.service.ts (L17-22)
```typescript
  async blacklistToken(jwt: string) {
    const expirationDays = this.configService.get<number>('JWT_EXPIRATION');
    const expirationSeconds = Number(expirationDays) * 24 * 60 * 60;

    await this.client.set(jwt, this.BLACKLISTED, 'EX', expirationSeconds);
  }
```
