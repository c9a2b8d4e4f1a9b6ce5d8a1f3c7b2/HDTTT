### Title
Global IP Rate Limiter Bypassed via Attacker-Controlled `X-Forwarded-For` Header, Enabling Unlimited API Requests

### Summary
The `IpThrottlerGuard`, registered as the sole global rate-limiting guard for all API endpoints, derives its throttle tracking key from the raw `req.headers['x-forwarded-for']` header before falling back to `req.ip`. Because this header is fully attacker-controlled, any external client can rotate through arbitrary spoofed IP values on every request, rendering the global rate limiter completely ineffective. This allows an attacker to flood all API endpoints without restriction, causing service unavailability and depleting third-party resources such as email and Hedera network API quotas.

### Finding Description

**Root cause — raw header used as throttle key:**

`IpThrottlerGuard.getTracker()` reads the tracker key as:

```ts
const clientIp = req.headers['x-forwarded-for'] || req.ip;
``` [1](#0-0) 

`req.headers['x-forwarded-for']` is the raw, unparsed HTTP header sent by the client. It is evaluated first, before `req.ip`. Because it is never validated or sanitized, an attacker can set it to any arbitrary string (e.g., `1.2.3.4`, then `1.2.3.5`, etc.) and each request will be counted against a different throttle bucket, effectively resetting the rate limit on every request.

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

`IpThrottlerGuard` is registered as a global `APP_GUARD`, meaning it is the primary rate-limiting defense for every HTTP endpoint in the API:

```ts
providers: [
  {
    provide: APP_GUARD,
    useClass: IpThrottlerGuard,
  },
``` [3](#0-2) 

The throttler configuration enforces limits per IP per minute and per second: [4](#0-3) 

All of these limits are bypassed when the attacker rotates the `X-Forwarded-For` header.

**High-value targets reachable without authentication:**

- `POST /auth/reset-password` — triggers OTP email generation (email quota depletion)
- `POST /auth/login` — credential brute-force
- `POST /auth/verify-reset` — OTP brute-force [5](#0-4) 

The `EmailThrottlerGuard` on some of these endpoints tracks by `req.body.email`, which is not spoofable in the same way, but it is only applied to a subset of endpoints and does not protect against general API flooding.

### Impact Explanation

An unauthenticated external attacker can send unlimited requests to any API endpoint by rotating the `X-Forwarded-For` header on each request. Concrete impacts:

1. **Service unavailability (DoS):** The API, PostgreSQL, and Redis are flooded with unbounded requests, exhausting CPU, memory, and connection pool resources.
2. **Email quota depletion:** Repeated calls to `POST /auth/reset-password` with valid email addresses trigger OTP emails, depleting the transactional email provider's quota and blocking legitimate password resets.
3. **Hedera network API depletion:** Authenticated endpoints that trigger Hedera network operations (transaction submission, polling) can be abused by authenticated users who bypass per-IP limits.
4. **Brute-force enablement:** The rate limiter on `POST /auth/login` is rendered ineffective, enabling credential stuffing at full network speed.

**Impact: 3/5** — Service degradation and third-party resource depletion; no direct asset theft.

### Likelihood Explanation

**Likelihood: 4/5** — No privileges required. The attacker only needs to send HTTP requests with a rotating `X-Forwarded-For` header, which is trivially achievable with any HTTP client or load-testing tool. The attack is fully automated and requires no knowledge of the application beyond the public API surface. The test suite itself confirms the guard accepts the spoofed header as the tracker key: [6](#0-5) 

### Recommendation

Replace the raw header read with Express's normalized `req.ip`, which correctly applies the `trust proxy` chain:

```ts
protected getTracker(req: Record<string, any>): Promise<string> {
  const clientIp = req.ip; // Use Express-normalized IP only
  if (!clientIp) {
    throw new HttpException('Unable to determine client IP', HttpStatus.INTERNAL_SERVER_ERROR);
  }
  return Promise.resolve(clientIp);
}
```

Additionally, ensure `trust proxy` is configured to the exact number of trusted proxy hops (e.g., `app.set('trust proxy', 1)`) rather than the blanket `true`/`'trust proxy'` setting, to prevent `req.ip` itself from being influenced by attacker-injected headers beyond the trusted proxy layer.

### Proof of Concept

```bash
# Bypass rate limit by rotating X-Forwarded-For on every request
for i in $(seq 1 1000); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://<api-host>/auth/reset-password \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -H "x-frontend-version: <valid-version>" \
    -d '{"email": "victim@example.com"}'
done
```

**Expected result:** All 1000 requests return `200 OK` (or `400`/`404` based on email validity), none return `429 Too Many Requests`. Each request is counted against a distinct throttle bucket (`10.0.0.1`, `10.0.0.2`, …, `10.0.0.1000`), so the per-IP limit is never reached. With a valid victim email, this triggers up to 1000 OTP emails in seconds.

### Citations

**File:** back-end/apps/api/src/guards/ip-throttler.guard.ts (L7-9)
```typescript
  protected getTracker(req: Record<string, any>): Promise<string> {
    const clientIp = req.headers['x-forwarded-for'] || req.ip;
    if (!clientIp) {
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

**File:** back-end/apps/api/src/auth/auth.controller.ts (L134-139)
```typescript
  @Post('/reset-password')
  @HttpCode(200)
  @UseGuards(EmailThrottlerGuard)
  async createOtp(@Body() { email }: OtpLocalDto) {
    return this.authService.createOtp(email);
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
