All code references check out. Let me verify one more detail about the OTP JWT blacklisting behavior on failed attempts.

Audit Report

## Title
Global IP Rate Limiter Bypass via Attacker-Controlled `X-Forwarded-For` Header Enables OTP Brute Force on `/auth/verify-reset`

## Summary
`IpThrottlerGuard` — the sole globally-applied rate limiter — derives its tracker key from the raw `req.headers['x-forwarded-for']` value, which is fully attacker-controlled. By rotating arbitrary strings in this header, any unauthenticated client can bypass the throttler entirely. The `/auth/verify-reset` endpoint carries no secondary throttler, leaving OTP brute force completely unmitigated. Combined with a TOTP configuration of `window: 20` and `step: 60` (41 valid codes at any moment), and the fact that the OTP JWT is only blacklisted on *successful* verification (not on failed attempts), an attacker can enumerate OTP values against a victim's reset token without restriction.

## Finding Description

**Root cause — `IpThrottlerGuard.getTracker` trusts a client-supplied header:**

`getTracker` reads `req.headers['x-forwarded-for']` directly before falling back to `req.ip`. This header is set by the HTTP client, not by a trusted proxy. Any string sent in this header becomes the throttler's tracking key. [1](#0-0) 

**Production amplifier — `trust proxy` is unconditionally enabled:**

In production, `app.enable('trust proxy')` is called with no hop count or allowlist. This does not fix the guard — the guard reads `req.headers['x-forwarded-for']` directly (the raw header string), bypassing Express's own proxy-trust resolution of `req.ip`. [2](#0-1) 

**Global guard registration — bypass affects every route:**

`IpThrottlerGuard` is the only rate limiter registered as a global `APP_GUARD`. No other IP-level throttler exists. [3](#0-2) 

**Unprotected OTP endpoint — `/auth/verify-reset` has no secondary throttler:**

`EmailThrottlerGuard` is applied to `/auth/signup`, `/auth/login`, and `/auth/reset-password`, but not to `/auth/verify-reset`. The only guards on this endpoint are `JwtBlackListOtpGuard` and `OtpJwtAuthGuard`. [4](#0-3) 

**OTP JWT is only blacklisted on success, not on failed attempts:**

`blacklistService.blacklistToken` is called only after `authService.verifyOtp` returns successfully. When the OTP is wrong, `verifyOtp` throws `UnauthorizedException` and the JWT is never blacklisted, so the attacker can reuse the same JWT for unlimited brute-force attempts. [5](#0-4) [6](#0-5) 

**Wide TOTP acceptance window:**

`window: 20` with `step: 60` means the library accepts codes from −20 to +20 steps, yielding 41 simultaneously valid 8-digit codes out of a 10^8 search space. [7](#0-6) 

## Impact Explanation

An attacker who calls `/auth/reset-password` with a victim's email receives an OTP JWT directly in the response body. The actual OTP code is emailed to the victim, but the attacker holds the JWT needed to call `/auth/verify-reset`. With the IP throttler bypassed by rotating `X-Forwarded-For` values, the attacker can submit unlimited OTP guesses using the same JWT (which is never blacklisted on failure). With 41 valid codes out of 10^8 and no rate limit, the attacker can enumerate the full space. A successful guess returns a `verified: true` OTP JWT, which is then used to call `/auth/set-password` — resulting in full account takeover with no privileged access required. [8](#0-7) 

## Likelihood Explanation

Setting an arbitrary `X-Forwarded-For` header requires only a standard HTTP client (`curl`, Python `requests`, etc.). No authentication, no leaked secrets, and no internal network access is needed. The attacker only needs to know a target's email address to initiate the OTP flow. The attack is fully scriptable. The only practical constraint is the OTP JWT expiration (`OTP_EXPIRATION` minutes), but with no per-request throttling, an attacker can submit thousands of requests per second within that window. [9](#0-8) 

## Recommendation

1. **Fix `getTracker` to use a trusted IP source.** Replace `req.headers['x-forwarded-for']` with `req.ip`. When `trust proxy` is correctly configured, Express resolves `req.ip` to the first untrusted IP in the chain, which cannot be spoofed by the client.

```typescript
// back-end/apps/api/src/guards/ip-throttler.guard.ts
protected getTracker(req: Record<string, any>): Promise<string> {
  const clientIp = req.ip; // rely on Express trust-proxy resolution only
  if (!clientIp) {
    throw new HttpException('Unable to determine client IP', HttpStatus.INTERNAL_SERVER_ERROR);
  }
  return Promise.resolve(clientIp);
}
```

2. **Scope `trust proxy` to a specific hop count or CIDR.** Replace `app.enable('trust proxy')` with `app.set('trust proxy', 1)` (or the actual number of trusted proxy hops) to prevent the entire `X-Forwarded-For` chain from being trusted.

3. **Add an `EmailThrottlerGuard` (or a dedicated OTP attempt counter) to `/auth/verify-reset`.** Rate-limit by the OTP JWT's subject/email so that even with IP bypass, per-account brute force is capped.

4. **Blacklist the OTP JWT on repeated failed attempts** (e.g., after N failures), not only on success.

5. **Reduce the TOTP `window`** from 20 to 1 or 2 to shrink the valid code space from 41 to 3–5 codes.

## Proof of Concept

```bash
# Step 1: Trigger OTP flow for victim — attacker receives the OTP JWT
OTP_JWT=$(curl -s -X POST https://target/auth/reset-password \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com"}' | jq -r .token)

# Step 2: Brute-force /auth/verify-reset with rotating X-Forwarded-For
#         The same OTP_JWT is reused on every request (never blacklisted on failure)
for i in $(seq 0 99999999); do
  CODE=$(printf "%08d" $i)
  FAKE_IP="10.0.$((RANDOM % 256)).$((RANDOM % 256))"
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target/auth/verify-reset \
    -H "Content-Type: application/json" \
    -H "otp: $OTP_JWT" \
    -H "X-Forwarded-For: $FAKE_IP" \
    -d "{\"token\":\"$CODE\"}")
  if [ "$RESPONSE" = "200" ]; then
    echo "OTP found: $CODE — account takeover possible"
    break
  fi
done
```

Each iteration uses a different `X-Forwarded-For` value, so the throttler never accumulates hits against a single key. The same `$OTP_JWT` remains valid for all failed attempts because it is only blacklisted upon success. [1](#0-0) [4](#0-3)

### Citations

**File:** back-end/apps/api/src/guards/ip-throttler.guard.ts (L7-13)
```typescript
  protected getTracker(req: Record<string, any>): Promise<string> {
    const clientIp = req.headers['x-forwarded-for'] || req.ip;
    if (!clientIp) {
      throw new HttpException('Unable to determine client IP', HttpStatus.INTERNAL_SERVER_ERROR);
    }
    // console.log('client IP', clientIp.replace(/^.*:/, ''));
    return clientIp;
```

**File:** back-end/apps/api/src/main.ts (L32-37)
```typescript
async function createAppForDeployment(): Promise<NestExpressApplication> {
  const app = (await NestFactory.create(ApiModule)) as NestExpressApplication;
  app.enable('trust proxy');

  return app;
}
```

**File:** back-end/apps/api/src/api.module.ts (L73-78)
```typescript
  providers: [
    {
      provide: APP_GUARD,
      useClass: IpThrottlerGuard,
    },
    {
```

**File:** back-end/apps/api/src/auth/auth.controller.ts (L152-158)
```typescript
  @Post('/verify-reset')
  @HttpCode(200)
  @UseGuards(JwtBlackListOtpGuard, OtpJwtAuthGuard)
  async verifyOtp(@GetUser() user: User, @Body() dto: OtpDto, @Req() req) {
    const result = await this.authService.verifyOtp(user, dto);
    await this.blacklistService.blacklistToken(extractJwtOtp(req));
    return result;
```

**File:** back-end/apps/api/src/auth/auth.service.ts (L30-34)
```typescript
totp.options = {
  digits: 8,
  step: 60,
  window: 20,
};
```

**File:** back-end/apps/api/src/auth/auth.service.ts (L98-109)
```typescript
  async createOtp(email: string): Promise<{ token: string }> {
    const user = await this.usersService.getUser({ email });

    if (!user) return;

    const secret = this.getOtpSecret(user.email);
    const otp = totp.generate(secret);

    emitUserPasswordResetEmail(this.notificationsPublisher, [{ email: user.email, additionalData: { otp } }]);

    const token = this.getOtpToken({ email: user.email, verified: false });
    return { token };
```

**File:** back-end/apps/api/src/auth/auth.service.ts (L112-115)
```typescript
  async verifyOtp(user: User, { token }: OtpDto): Promise<{ token: string }> {
    const secret = this.getOtpSecret(user.email);

    if (!totp.check(token, secret)) throw new UnauthorizedException('Incorrect token');
```

**File:** back-end/apps/api/src/throttlers/ip-throttler.module.ts (L13-27)
```typescript
        throttlers: [
          {
            name: 'global-minute',
            ttl: seconds(60),
            limit: configService.getOrThrow<number>('GLOBAL_MINUTE_LIMIT'),
          },
          {
            name: 'global-second',
            ttl: seconds(1),
            limit: configService.getOrThrow<number>('GLOBAL_SECOND_LIMIT'),
          },
        ],
      }),
    }),
  ],
```
