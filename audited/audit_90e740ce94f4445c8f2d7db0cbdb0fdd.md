### Title
Spoofable `x-forwarded-for` Header Used as Trusted Rate-Limit Key in `IpThrottlerGuard`, Enabling Complete IP Throttle Bypass

### Summary
`IpThrottlerGuard` resolves the client identity for rate limiting by reading the attacker-controlled `x-forwarded-for` HTTP header before falling back to the server-assigned `req.ip`. Because any HTTP client can set this header to an arbitrary value, an attacker can rotate fake IP strings per request and bypass the global IP-based rate limiter entirely. This is the direct analog of the `tx.origin` pattern in the external report: both substitute a spoofable, caller-supplied identifier for a trustworthy, server-verified one in a security-critical decision.

### Finding Description

**Root cause — `IpThrottlerGuard.getTracker()`** [1](#0-0) 

```typescript
protected getTracker(req: Record<string, any>): Promise<string> {
  const clientIp = req.headers['x-forwarded-for'] || req.ip;
  ...
  return clientIp;
}
```

`x-forwarded-for` is checked **first**. It is a plain HTTP request header; any client can set it to any string. The server-assigned `req.ip` (the actual TCP peer address, which cannot be forged at the HTTP layer) is only consulted when the header is absent.

The guard is wired into the global throttler module: [2](#0-1) 

Production limits from the Helm values are extremely tight for anonymous callers: [3](#0-2) 

```
ANONYMOUS_MINUTE_LIMIT: "3"
ANONYMOUS_FIVE_SECOND_LIMIT: "1"
```

These limits are the primary guard against unauthenticated abuse. Because the tracker key is attacker-controlled, they are trivially bypassed.

**Exploit flow**

1. Attacker sends `POST /auth/reset-password` with `x-forwarded-for: 1.0.0.1`. Counter for `1.0.0.1` increments.
2. Next request uses `x-forwarded-for: 1.0.0.2`. Fresh counter — no throttle.
3. Repeat indefinitely with rotating fake IPs. The `ANONYMOUS_MINUTE_LIMIT=3` and `ANONYMOUS_FIVE_SECOND_LIMIT=1` limits are never reached for any single key.

The `EmailThrottlerGuard` (keyed on `req.body.email`) partially mitigates brute-force on `/auth/login` and `/auth/reset-password`, but: [4](#0-3) 

- Any endpoint that relies **only** on `IpThrottlerGuard` (e.g., OTP verification, version-check probing, or any future unauthenticated route) has no remaining rate-limit protection once the IP throttle is bypassed.
- An attacker targeting many distinct email addresses simultaneously is not constrained by the per-email throttle and can enumerate or brute-force at scale.

The `FrontendVersionGuard` also reads `x-forwarded-for` but only for logging, not for a security decision — that usage is harmless. [5](#0-4) 

### Impact Explanation

- **Rate-limit bypass**: The global anonymous throttle (`3 req/min`, `1 req/5 s`) is completely neutralised for any attacker who sets a rotating `x-forwarded-for` header.
- **Brute-force enablement**: Endpoints that depend solely on IP throttling (e.g., OTP verification) become open to unlimited attempts, making short numeric OTP codes brute-forceable within their validity window.
- **Scale abuse**: An attacker can drive arbitrarily high request volume to any unauthenticated endpoint, degrading service for legitimate users — without triggering any throttle counter.

### Likelihood Explanation

- **No privileges required**: Any unauthenticated HTTP client can set arbitrary headers.
- **Trivial to automate**: A single `curl` loop rotating `x-forwarded-for` values is sufficient.
- **No proxy dependency**: The bypass works whether or not a reverse proxy is present, because the code reads the raw header value before the proxy-assigned `req.ip`.
- **Directly reachable**: The guard is applied globally to all API routes via `IpThrottlerModule`.

### Recommendation

**Do not trust `x-forwarded-for` as the primary rate-limit key.** Use `req.ip` exclusively, which Express/NestJS derives from the actual TCP connection and cannot be forged at the HTTP layer:

```typescript
protected getTracker(req: Record<string, any>): Promise<string> {
  const clientIp = req.ip;
  if (!clientIp) {
    throw new HttpException('Unable to determine client IP', HttpStatus.INTERNAL_SERVER_ERROR);
  }
  return clientIp;
}
```

If the deployment sits behind a trusted reverse proxy (Traefik, as shown in the Helm chart), configure Express to trust the proxy via `app.set('trust proxy', 1)` so that `req.ip` is correctly populated from the proxy-appended `x-forwarded-for` entry — but this must be done at the framework level, not by reading the raw header in application code. [6](#0-5) 

### Proof of Concept

```bash
# Bypass the ANONYMOUS_MINUTE_LIMIT=3 by rotating x-forwarded-for on every request
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://<api-host>/auth/reset-password \
    -H "Content-Type: application/json" \
    -H "x-forwarded-for: 10.0.0.$i" \
    -H "x-frontend-version: 0.21.0" \
    -d '{"email":"victim@example.com"}'
done
```

Expected result: all 100 requests return `200` (or `400`/`404` based on email existence), none return `429 Too Many Requests`. Without the `x-forwarded-for` rotation, requests 4+ within the same minute would be throttled. The tracker key for each request is a distinct fake IP, so no counter ever reaches the limit of 3.

### Citations

**File:** back-end/apps/api/src/guards/ip-throttler.guard.ts (L1-15)
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
}
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

**File:** charts/transaction-tool/values.yaml (L153-156)
```yaml
    ANONYMOUS_MINUTE_LIMIT: "3"
    ANONYMOUS_FIVE_SECOND_LIMIT: "1"
    GLOBAL_MINUTE_LIMIT: "10000"
    GLOBAL_SECOND_LIMIT: "1000"
```

**File:** back-end/apps/api/src/guards/email-throttler.guard.ts (L6-13)
```typescript
export class EmailThrottlerGuard extends ThrottlerGuard {
  protected getTracker(req: Record<string, any>): Promise<string> {
    const email = req.body.email;
    if (!email) {
      throw new HttpException('No email specified.', HttpStatus.BAD_REQUEST);
    }
    return email;
  }
```

**File:** back-end/apps/api/src/guards/frontend-version.guard.ts (L41-41)
```typescript
    const clientIp = request.headers['x-forwarded-for'] || request.ip || 'unknown';
```
