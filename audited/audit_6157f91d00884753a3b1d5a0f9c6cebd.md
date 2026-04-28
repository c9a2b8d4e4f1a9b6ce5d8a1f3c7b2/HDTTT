### Title
IP Rate-Limit Bypass via Attacker-Controlled `X-Forwarded-For` Header in `IpThrottlerGuard`

### Summary
The global `IpThrottlerGuard` derives its throttle key directly from the attacker-controlled `x-forwarded-for` request header without sanitization or proxy-chain validation. An unauthenticated attacker can rotate arbitrary fake IPs in that header to make unlimited requests to every API endpoint, completely nullifying the IP-based rate-limiting layer that is the system's primary DoS and brute-force defense.

### Finding Description

**Root cause — `getTracker` reads a raw, attacker-controlled header:**

In `back-end/apps/api/src/guards/ip-throttler.guard.ts`, the throttle key is resolved as:

```typescript
const clientIp = req.headers['x-forwarded-for'] || req.ip;
``` [1](#0-0) 

`req.headers['x-forwarded-for']` is the raw HTTP header string. It is never validated, never parsed for the trusted segment, and never compared against a known-good proxy list. Any HTTP client can set it to any value.

**Production deployment enables full proxy trust:**

```typescript
app.enable('trust proxy');   // trusts ALL proxies — no IP pinning
``` [2](#0-1) 

`trust proxy = true` (the boolean form) tells Express to trust every hop in the forwarding chain. It does not strip or overwrite the header before the guard reads it. The guard reads `req.headers['x-forwarded-for']` directly — bypassing even the partial protection Express's `req.ip` would provide under a stricter trust-proxy numeric setting.

**The guard is applied globally to every endpoint:**

```typescript
{ provide: APP_GUARD, useClass: IpThrottlerGuard }
``` [3](#0-2) 

This means the bypass is not limited to one route — it covers the entire API surface.

**Exploit flow:**

1. Attacker sends `POST /auth/login` with header `X-Forwarded-For: 1.1.1.1`.
2. `getTracker` returns `"1.1.1.1"` as the throttle key.
3. After `GLOBAL_MINUTE_LIMIT` requests, the attacker increments the last octet: `X-Forwarded-For: 1.1.1.2`.
4. A fresh counter starts. The attacker repeats indefinitely with no real rate limit applied.

The `EmailThrottlerGuard` on `POST /auth/login` keys on `req.body.email`, not IP, so it is a separate control that does not compensate for this bypass. [4](#0-3) 

### Impact Explanation

- **Authentication brute force:** `POST /auth/login` is protected only by `LocalAuthGuard` + `EmailThrottlerGuard` (email-keyed) and the global IP throttler. With the IP throttler bypassed, an attacker can attempt unlimited passwords against any known email address.
- **OTP brute force:** `POST /auth/reset-password` triggers OTP generation. Unlimited calls exhaust email-sending resources and allow OTP enumeration.
- **General DoS:** Every endpoint becomes unthrottled, enabling resource exhaustion of the API service, PostgreSQL connection pool, and Redis. [5](#0-4) 

### Likelihood Explanation

- **No privilege required.** Any unauthenticated HTTP client can set arbitrary headers.
- **Trivially scriptable.** A single `curl` loop incrementing the spoofed IP is sufficient.
- **No detection barrier.** The real source IP never appears in the throttle key, so the attacker's actual IP is never rate-limited.
- **Deployment-confirmed.** The `trust proxy` flag is only set in `createAppForDeployment`, confirming this path is active in production. [6](#0-5) 

### Recommendation

1. **Never read `x-forwarded-for` directly for security decisions.** Replace `req.headers['x-forwarded-for']` with `req.ip`, which Express resolves correctly when `trust proxy` is configured to a specific numeric hop count or CIDR list of trusted proxies.

2. **Restrict `trust proxy` to the actual proxy tier.** Change `app.enable('trust proxy')` to `app.set('trust proxy', 1)` (or the exact CIDR of the load balancer) so Express only trusts the last known-good hop and `req.ip` reflects the real client IP.

3. **Corrected `getTracker`:**
   ```typescript
   protected getTracker(req: Record<string, any>): Promise<string> {
     const clientIp = req.ip;  // Express-resolved, proxy-aware
     if (!clientIp) {
       throw new HttpException('Unable to determine client IP', HttpStatus.INTERNAL_SERVER_ERROR);
     }
     return Promise.resolve(clientIp);
   }
   ```

### Proof of Concept

```bash
# Bypass global IP rate limit by rotating the spoofed header value
for i in $(seq 1 1000); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://<api-host>/auth/login \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.0.${i}" \
    -H "X-Frontend-Version: <valid-version>" \
    -d '{"email":"victim@example.com","password":"guess'$i'"}'
done
```

Each iteration presents a fresh throttle key (`10.0.0.1`, `10.0.0.2`, …). The server never accumulates enough hits against any single key to trigger a 429, so all 1 000 login attempts succeed at the transport layer. The attacker can enumerate passwords against `victim@example.com` without any IP-level rate-limit enforcement. [7](#0-6) [6](#0-5)

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
