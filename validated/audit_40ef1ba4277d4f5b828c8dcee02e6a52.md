### Title
Rate Limit Bypass via Unvalidated `X-Forwarded-For` Header Enables DoS Against All API Users

### Summary
The `IpThrottlerGuard`, applied globally to every API route, derives the rate-limit key from the attacker-controlled `X-Forwarded-For` header without any trusted-proxy validation. An unauthenticated attacker can rotate arbitrary fake IPs in that header to bypass the per-IP throttle entirely, flooding the API with unlimited requests and exhausting backend resources (DB connection pool, CPU, memory) for all legitimate users.

### Finding Description

`IpThrottlerGuard.getTracker()` unconditionally prefers the `X-Forwarded-For` header over the real socket IP:

```typescript
// back-end/apps/api/src/guards/ip-throttler.guard.ts
protected getTracker(req: Record<string, any>): Promise<string> {
    const clientIp = req.headers['x-forwarded-for'] || req.ip;
    ...
    return clientIp;   // returns a plain string, not a Promise
}
``` [1](#0-0) 

This guard is registered as a global `APP_GUARD`, meaning it is the sole rate-limiting layer protecting every HTTP route in the API service:

```typescript
// back-end/apps/api/src/api.module.ts
providers: [
  { provide: APP_GUARD, useClass: IpThrottlerGuard },
  ...
]
``` [2](#0-1) 

The throttler it enforces is configured with `GLOBAL_MINUTE_LIMIT=10000` and `GLOBAL_SECOND_LIMIT=1000` keyed per-IP: [3](#0-2) 

Because `X-Forwarded-For` is a plain HTTP request header, any client can set it to any value. The guard performs no trusted-proxy check, no IP allowlist, and no format validation before using it as the Redis throttle key. An attacker who rotates this header through a sequence of unique fake IPs (`1.1.1.1`, `1.1.1.2`, …) gets a fresh rate-limit bucket on every request, effectively making the limit infinite.

The `EmailThrottlerGuard` (used on `/reset-password`) is a separate guard keyed on the request body's `email` field and is not affected by this bypass, but the global `IpThrottlerGuard` covers all other routes including unauthenticated ones (`/auth/login`, `/auth/signup`, `/auth/verify-reset`, etc.). [4](#0-3) 

### Impact Explanation

With the rate limit nullified, an attacker can:

1. **Exhaust the PostgreSQL connection pool** (`POSTGRES_MAX_POOL_SIZE=2` in test, `3` in production) by issuing concurrent authenticated or unauthenticated requests that hit the database, causing `connection pool exhausted` errors for all legitimate users.
2. **Saturate CPU/memory** of the NestJS API process through unbounded concurrent request processing.
3. **Deny service to all users** of the organization backend for as long as the flood continues — no time-window reset is needed because the attacker never hits a limit. [5](#0-4) 

### Likelihood Explanation

- **No authentication required** — the bypass works on every route, including public ones.
- **Zero cost** — rotating `X-Forwarded-For` values requires only a trivial HTTP header change; no tokens, funds, or special access are needed.
- **Widely known technique** — header-spoofing to bypass IP rate limits is a standard attacker playbook entry.
- **No existing mitigation** — the codebase contains no trusted-proxy configuration, no `X-Forwarded-For` allowlist, and no secondary rate-limiting layer that would catch this.

### Recommendation

1. **Short term**: Only trust `X-Forwarded-For` when the request originates from a known, trusted reverse proxy. Replace the unconditional header preference with a check against a configured trusted-proxy CIDR list, or simply use `req.ip` (which Express already resolves correctly when `app.set('trust proxy', ...)` is configured):

```typescript
protected getTracker(req: Record<string, any>): Promise<string> {
    // req.ip is already the real IP when Express trust proxy is set correctly
    const clientIp = req.ip;
    if (!clientIp) {
        throw new HttpException('Unable to determine client IP', HttpStatus.INTERNAL_SERVER_ERROR);
    }
    return Promise.resolve(clientIp);
}
```

2. **Long term**: Configure Express `trust proxy` to the exact number of trusted proxy hops (e.g., `app.set('trust proxy', 1)`) so that `req.ip` is correctly populated from the last trusted `X-Forwarded-For` entry rather than the raw socket address.

### Proof of Concept

```bash
# Flood the login endpoint, rotating X-Forwarded-For on every request.
# Each request gets a fresh rate-limit bucket, so no 429 is ever returned.
for i in $(seq 1 50000); do
  curl -s -o /dev/null \
    -H "X-Forwarded-For: 10.0.$((i/256)).$((i%256))" \
    -H "Content-Type: application/json" \
    -d '{"email":"a@b.com","password":"x"}' \
    http://<api-host>:3000/auth/login &
done
wait
```

Expected result: all 50,000 requests reach the NestJS process and hit the database. No `429 Too Many Requests` is returned. The PostgreSQL connection pool is exhausted within seconds, and subsequent legitimate requests receive `500 Internal Server Error` or hang indefinitely. [6](#0-5) [2](#0-1)

### Citations

**File:** back-end/apps/api/src/guards/ip-throttler.guard.ts (L1-14)
```typescript
/* eslint-disable @typescript-eslint/no-explicit-any */
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

@Injectable()
export class IpThrottlerGuard extends ThrottlerGuard {
  protected getTracker(req: Record<string, any>): Promise<string> {
    const clientIp = req.headers['x-forwarded-for'] || req.ip;
    if (!clientIp) {
      throw new HttpException('Unable to determine client IP', HttpStatus.INTERNAL_SERVER_ERROR);
    }
    // console.log('client IP', clientIp.replace(/^.*:/, ''));
    return clientIp;
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

**File:** back-end/apps/api/src/guards/email-throttler.guard.spec.ts (L35-40)
```typescript
  it('returns the email string when provided in request body', async () => {
    const req = { body: { email: 'user@example.com' } };

    const result = await (guard as any).getTracker(req);
    expect(result).toBe('user@example.com');
  });
```

**File:** back-end/apps/api/example.env (L26-29)
```text
ANONYMOUS_MINUTE_LIMIT=3
ANONYMOUS_FIVE_SECOND_LIMIT=1
GLOBAL_MINUTE_LIMIT=10000
GLOBAL_SECOND_LIMIT=1000
```
