All claims are verified against the actual code. The vulnerability is real and confirmed.

---

Audit Report

## Title
Global IP Rate Limiter Bypassed via Attacker-Controlled `X-Forwarded-For` Header, Enabling Unlimited API Requests

## Summary
`IpThrottlerGuard`, registered as the global `APP_GUARD` for all API endpoints, derives its throttle tracking key from the raw, unvalidated `req.headers['x-forwarded-for']` header before falling back to `req.ip`. Because this header is fully attacker-controlled, any external client can rotate through arbitrary spoofed IP values on every request, rendering the global rate limiter completely ineffective.

## Finding Description

**Root cause — raw header used as throttle key:**

`IpThrottlerGuard.getTracker()` reads:

```ts
const clientIp = req.headers['x-forwarded-for'] || req.ip;
``` [1](#0-0) 

`req.headers['x-forwarded-for']` is the raw, unparsed HTTP header sent by the client. It is evaluated first, before `req.ip`, and is never validated or sanitized. An attacker can set it to any arbitrary string (e.g., `1.2.3.4`, then `1.2.3.5`, etc.) and each request will be counted against a different throttle bucket, effectively resetting the rate limit on every request.

**Why `req.ip` does not save this:**

Express's `trust proxy` setting causes `req.ip` to be derived from the proxy chain correctly — but only when `trust proxy` is enabled. In this codebase, `trust proxy` is only enabled in the production code path:

```ts
async function createAppForDeployment(): Promise<NestExpressApplication> {
  const app = (await NestFactory.create(ApiModule)) as NestExpressApplication;
  app.enable('trust proxy');
  return app;
}
``` [2](#0-1) 

Even in production with `trust proxy` enabled, the guard still reads `req.headers['x-forwarded-for']` first. Express's `req.ip` correctly resolves the real client IP from the trusted proxy chain, but the guard bypasses this entirely by reading the raw header directly.

**Global scope — all endpoints affected:**

`IpThrottlerGuard` is registered as a global `APP_GUARD`, meaning it is the primary rate-limiting defense for every HTTP endpoint in the API: [3](#0-2) 

The throttler configuration enforces limits per IP per minute and per second via `GLOBAL_MINUTE_LIMIT` and `GLOBAL_SECOND_LIMIT` environment variables: [4](#0-3) 

All of these limits are bypassed when the attacker rotates the `X-Forwarded-For` header.

**High-value targets reachable without authentication:**

- `POST /auth/reset-password` — triggers OTP email generation (email quota depletion); protected only by `EmailThrottlerGuard` (tracks by `req.body.email`, not IP)
- `POST /auth/login` — credential brute-force; protected only by `EmailThrottlerGuard`
- `POST /auth/verify-reset` — OTP brute-force; protected only by JWT guard, no email throttler [5](#0-4) [6](#0-5) [7](#0-6) 

The `EmailThrottlerGuard` tracks by `req.body.email`: [8](#0-7) 

This means an attacker rotating both `X-Forwarded-For` and target email addresses bypasses both throttlers simultaneously.

**Test suite confirms the behavior:**

The unit test explicitly confirms the guard accepts a spoofed `x-forwarded-for` header as the tracker key: [9](#0-8) 

## Impact Explanation

An unauthenticated external attacker can send unlimited requests to any API endpoint by rotating the `X-Forwarded-For` header on each request. Concrete impacts:

1. **Email quota depletion:** Repeated calls to `POST /auth/reset-password` with rotating valid email addresses trigger OTP emails, depleting the transactional email provider's quota and blocking legitimate password resets. The `EmailThrottlerGuard` is per-email, so rotating email addresses bypasses it.
2. **Brute-force enablement:** The rate limiter on `POST /auth/login` is rendered ineffective for credential stuffing across multiple accounts simultaneously.
3. **Service unavailability (DoS):** The API, PostgreSQL, and Redis are flooded with unbounded requests, exhausting CPU, memory, and connection pool resources.
4. **Hedera network API depletion:** Authenticated endpoints that trigger Hedera network operations can be abused by authenticated users who bypass per-IP limits.

**Impact: 3/5** — Service degradation, third-party resource depletion, and brute-force enablement; no direct asset theft.

## Likelihood Explanation

**Likelihood: 4/5** — No privileges required. The attacker only needs to send HTTP requests with a rotating `X-Forwarded-For` header, which is trivially achievable with any HTTP client or load-testing tool (e.g., `curl -H "X-Forwarded-For: <rotating_ip>" ...`). The attack is fully automated and requires no knowledge of the application beyond the public API surface.

## Recommendation

Replace the raw header read with Express's `req.ip`, which correctly resolves the real client IP when `trust proxy` is properly configured:

```ts
protected getTracker(req: Record<string, any>): Promise<string> {
  const clientIp = req.ip;
  if (!clientIp) {
    throw new HttpException('Unable to determine client IP', HttpStatus.INTERNAL_SERVER_ERROR);
  }
  return Promise.resolve(clientIp);
}
```

Additionally, ensure `trust proxy` is configured correctly for the deployment environment so `req.ip` reflects the real client IP behind a reverse proxy. Do not read `req.headers['x-forwarded-for']` directly in security-sensitive contexts.

## Proof of Concept

```bash
# Send unlimited requests by rotating X-Forwarded-For on each request
for i in $(seq 1 10000); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://target/auth/reset-password \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.0.$((i % 255))" \
    -d '{"email": "victim@example.com"}'
done
```

Each request is counted against a different throttle bucket (`10.0.0.1`, `10.0.0.2`, ..., `10.0.0.254`, cycling), so the global rate limit is never reached. The `EmailThrottlerGuard` on `reset-password` is bypassed by rotating the `email` field across valid addresses. The attack requires no authentication and no prior knowledge beyond the public API surface.

### Citations

**File:** back-end/apps/api/src/guards/ip-throttler.guard.ts (L7-14)
```typescript
  protected getTracker(req: Record<string, any>): Promise<string> {
    const clientIp = req.headers['x-forwarded-for'] || req.ip;
    if (!clientIp) {
      throw new HttpException('Unable to determine client IP', HttpStatus.INTERNAL_SERVER_ERROR);
    }
    // console.log('client IP', clientIp.replace(/^.*:/, ''));
    return clientIp;
  }
```

**File:** back-end/apps/api/src/main.ts (L32-37)
```typescript
async function createAppForDeployment(): Promise<NestExpressApplication> {
  const app = (await NestFactory.create(ApiModule)) as NestExpressApplication;
  app.enable('trust proxy');

  return app;
}
```

**File:** back-end/apps/api/src/api.module.ts (L73-77)
```typescript
  providers: [
    {
      provide: APP_GUARD,
      useClass: IpThrottlerGuard,
    },
```

**File:** back-end/apps/api/src/throttlers/ip-throttler.module.ts (L13-24)
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
```

**File:** back-end/apps/api/src/auth/auth.controller.ts (L81-88)
```typescript
  @Post('/login')
  @HttpCode(200)
  @UseGuards(LocalAuthGuard, EmailThrottlerGuard)
  @Serialize(LoginResponseDto)
  async login(@GetUser() user: User) {
    const accessToken = await this.authService.login(user);
    return { user, accessToken };
  }
```

**File:** back-end/apps/api/src/auth/auth.controller.ts (L134-139)
```typescript
  @Post('/reset-password')
  @HttpCode(200)
  @UseGuards(EmailThrottlerGuard)
  async createOtp(@Body() { email }: OtpLocalDto) {
    return this.authService.createOtp(email);
  }
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

**File:** back-end/apps/api/src/guards/email-throttler.guard.ts (L7-13)
```typescript
  protected getTracker(req: Record<string, any>): Promise<string> {
    const email = req.body.email;
    if (!email) {
      throw new HttpException('No email specified.', HttpStatus.BAD_REQUEST);
    }
    return email;
  }
```

**File:** back-end/apps/api/src/guards/ip-throttler.guard.spec.ts (L42-47)
```typescript
  it('returns the ip from x-forwarded-for header when present', async () => {
    const req = { headers: { 'x-forwarded-for': '203.0.113.5' }, ip: undefined };

    const result = await (guard as any).getTracker(req);
    expect(result).toBe('203.0.113.5');
  });
```
