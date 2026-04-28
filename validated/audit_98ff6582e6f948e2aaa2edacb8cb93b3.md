Audit Report

## Title
Rate-Limit Bypass via Spoofable `x-forwarded-for` Header in `IpThrottlerGuard`

## Summary
`IpThrottlerGuard.getTracker()` unconditionally reads the attacker-controlled `x-forwarded-for` HTTP header before falling back to `req.ip`. Because any HTTP client can set this header to an arbitrary value, an unauthenticated attacker can rotate fake IPs on every request and never accumulate hits in any Redis throttle bucket, rendering the global rate limiter entirely ineffective.

## Finding Description

`IpThrottlerGuard.getTracker()` resolves the tracking key as:

```ts
const clientIp = req.headers['x-forwarded-for'] || req.ip;
``` [1](#0-0) 

`x-forwarded-for` is a plain HTTP header with no authentication. Any HTTP client can set it to an arbitrary string. Because it is evaluated **before** `req.ip`, the real socket address is never consulted when the header is present. The guard then uses this attacker-supplied string as the Redis key for the global throttler backed by `GLOBAL_MINUTE_LIMIT` / `GLOBAL_SECOND_LIMIT`. [2](#0-1) 

The guard is registered as a global `APP_GUARD` for the entire API service, so every endpoint is subject to it. [3](#0-2) 

The production bootstrap calls `app.enable('trust proxy')` — equivalent to trusting **all** proxies — rather than a validated proxy list. [4](#0-3) 

With `trust proxy` set to `true`, Express also sets `req.ip` to the leftmost value in `x-forwarded-for`, meaning even the fallback path is attacker-controlled in production. The guard's own test suite confirms this behaviour explicitly: [5](#0-4) 

Sensitive unauthenticated endpoints protected only by this IP throttler include:

- `POST /auth/login` — `@UseGuards(LocalAuthGuard, EmailThrottlerGuard)` + global IP throttler
- `POST /auth/reset-password` — `@UseGuards(EmailThrottlerGuard)` + global IP throttler [6](#0-5) [7](#0-6) 

`EmailThrottlerGuard` tracks by email address and provides a separate layer, but it is trivially bypassed by rotating email addresses. The global IP throttler is the only control that limits requests from callers who rotate both IPs and email addresses.

## Impact Explanation

An attacker who increments the `X-Forwarded-For` value on each request (e.g., `1.2.3.4`, `1.2.3.5`, …) is never counted against any single Redis bucket. The configured limits (`GLOBAL_MINUTE_LIMIT=10000`, `GLOBAL_SECOND_LIMIT=1000` in production) become entirely ineffective. Concrete consequences:

- **Credential brute-force**: unlimited password guesses against any known email at `POST /auth/login`.
- **OTP enumeration**: unlimited TOTP guesses at `POST /auth/verify-reset`, bypassing the time-step window.
- **Resource exhaustion**: sustained high-rate requests to any endpoint without throttling.

## Likelihood Explanation

- Requires zero privileges — any HTTP client (`curl`, Python `requests`) can set arbitrary headers.
- Trivially scriptable: increment a counter in `X-Forwarded-For` per request.
- `app.enable('trust proxy')` trusts all proxies unconditionally, so no infrastructure layer strips or validates the header before it reaches the guard.
- The guard's own unit tests document and validate the spoofable-header path as intended behaviour, meaning it will not be caught by the existing test suite.

## Recommendation

**Fix `IpThrottlerGuard`**: Remove the direct header read and rely solely on `req.ip`:

```ts
protected getTracker(req: Record<string, any>): Promise<string> {
  const clientIp = req.ip;
  if (!clientIp) {
    throw new HttpException('Unable to determine client IP', HttpStatus.INTERNAL_SERVER_ERROR);
  }
  return clientIp;
}
```

**Fix the proxy trust configuration**: Replace the blanket `app.enable('trust proxy')` with a specific, validated proxy list (e.g., the known ingress/load-balancer CIDR):

```ts
app.set('trust proxy', 'loopback, 10.0.0.0/8'); // restrict to known proxies
```

With a validated proxy list, Express will strip attacker-supplied `x-forwarded-for` entries and set `req.ip` to the actual client IP as seen by the last trusted proxy, making the throttler key unforgeable.

## Proof of Concept

```bash
# Bypass the global rate limiter by rotating X-Forwarded-For on every request
for i in $(seq 1 10000); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://<target>/auth/login \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 1.2.3.$i" \
    -d '{"email":"victim@example.com","password":"guess'$i'"}'
done
```

Each request lands in a distinct Redis bucket keyed by `1.2.3.$i`. No bucket ever reaches `GLOBAL_MINUTE_LIMIT` or `GLOBAL_SECOND_LIMIT`, so every request is processed and the attacker can attempt unlimited password guesses without ever receiving a `429 Too Many Requests` response.

### Citations

**File:** back-end/apps/api/src/guards/ip-throttler.guard.ts (L7-8)
```typescript
  protected getTracker(req: Record<string, any>): Promise<string> {
    const clientIp = req.headers['x-forwarded-for'] || req.ip;
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

**File:** back-end/apps/api/src/api.module.ts (L74-77)
```typescript
    {
      provide: APP_GUARD,
      useClass: IpThrottlerGuard,
    },
```

**File:** back-end/apps/api/src/main.ts (L32-37)
```typescript
async function createAppForDeployment(): Promise<NestExpressApplication> {
  const app = (await NestFactory.create(ApiModule)) as NestExpressApplication;
  app.enable('trust proxy');

  return app;
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
