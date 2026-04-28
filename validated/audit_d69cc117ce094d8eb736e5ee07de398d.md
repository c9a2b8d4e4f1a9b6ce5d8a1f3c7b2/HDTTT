### Title
IP Rate-Limit Bypass via Attacker-Controlled `X-Forwarded-For` Header Enables Brute Force on `/auth/login`

### Summary

The global `IpThrottlerGuard`, registered as an `APP_GUARD` for the entire API, derives its rate-limit tracker key from the raw `X-Forwarded-For` HTTP header before falling back to `req.ip`. Because `X-Forwarded-For` is an attacker-controlled header, an adversary can rotate its value on every request to appear as a new IP, completely nullifying the IP-based rate limit. On the `/auth/login` endpoint this leaves only the per-email `EmailThrottlerGuard` as a brake, which is bypassable across accounts and allows sustained credential brute force.

### Finding Description

**Root cause — `IpThrottlerGuard.getTracker()`** [1](#0-0) 

```typescript
const clientIp = req.headers['x-forwarded-for'] || req.ip;
```

`req.headers['x-forwarded-for']` is the raw, unvalidated HTTP header sent by the client. The guard uses it as the throttle-bucket key **before** `req.ip`. An attacker sets a unique value (e.g., `X-Forwarded-For: <random>`) on every request; each request lands in its own bucket and the counter never reaches the limit.

**Global registration — every route is affected** [2](#0-1) 

`IpThrottlerGuard` is the sole `APP_GUARD` providing IP-level protection across all routes.

**Attack surface — `/auth/login`** [3](#0-2) 

`/auth/login` is guarded by `LocalAuthGuard` (credential check) and `EmailThrottlerGuard` (per-email bucket). With the IP guard bypassed, only the email throttle remains.

**`EmailThrottlerGuard` throttles per email, not per attacker** [4](#0-3) 

The tracker key is `req.body.email`. An attacker targeting *N* accounts gets `ANONYMOUS_MINUTE_LIMIT` attempts per minute **per account**, with no cross-account ceiling.

**Throttle configuration (configurable, no hard floor)** [5](#0-4) 

`ANONYMOUS_MINUTE_LIMIT` and `ANONYMOUS_FIVE_SECOND_LIMIT` are environment variables with no enforced minimum in code.

**Unauthenticated OTP endpoint also exposed** [6](#0-5) 

`/auth/reset-password` is unauthenticated and carries only `EmailThrottlerGuard`. With the IP guard bypassed and a list of known user emails, an attacker can trigger OTP emails to arbitrary users at the per-email rate limit, causing email flooding.

### Impact Explanation

With the IP throttle nullified, an attacker can attempt `ANONYMOUS_MINUTE_LIMIT` passwords per minute against every known account in parallel. There is no cross-account rate ceiling and no CAPTCHA. Weak or reused passwords are recoverable through sustained credential stuffing. A compromised account gives the attacker access to the organization's Hedera transaction signing workflow, including the ability to approve or submit transactions on behalf of the victim.

### Likelihood Explanation

The bypass requires only a standard HTTP client capable of setting custom headers — no special tooling, no privileged access, no cryptographic break. The `X-Forwarded-For` header is universally supported. The attacker needs a list of registered email addresses (obtainable via the `/auth/reset-password` oracle, which returns a JWT only for existing users, or via other enumeration). Likelihood is high.

### Recommendation

1. **Do not trust `X-Forwarded-For` directly.** Configure Express `trust proxy` correctly and use `req.ip`, which Express resolves to the real client IP after accounting for the trusted proxy chain.
2. **Replace the guard logic:**
   ```typescript
   // ip-throttler.guard.ts
   protected getTracker(req: Record<string, any>): Promise<string> {
     const clientIp = req.ip; // Express resolves this via trust proxy
     if (!clientIp) throw new HttpException('Unable to determine client IP', HttpStatus.INTERNAL_SERVER_ERROR);
     return Promise.resolve(clientIp);
   }
   ```
3. **Add a hard per-IP limit on auth endpoints** independent of the `X-Forwarded-For` header, or enforce a minimum value for `ANONYMOUS_MINUTE_LIMIT` in the config validation schema.

### Proof of Concept

```python
import requests, random, string

TARGET = "https://<api-host>/auth/login"

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

# Brute-force a single account; each request appears from a new IP
for password in ["password1", "password2", "Summer2024!", ...]:
    r = requests.post(
        TARGET,
        json={"email": "victim@org.example", "password": password},
        headers={
            "X-Forwarded-For": random_ip(),   # bypasses IpThrottlerGuard
            "Content-Type": "application/json",
        },
    )
    print(r.status_code, r.text)
    # 200 → credentials found; 401 → wrong password; 429 only after
    # ANONYMOUS_MINUTE_LIMIT hits on the same email bucket
```

Each iteration presents a fresh IP to `IpThrottlerGuard`. The email bucket fills at `ANONYMOUS_MINUTE_LIMIT` per 60 s, but resets after the TTL, allowing indefinite iteration across the password space.

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

**File:** back-end/apps/api/src/api.module.ts (L73-77)
```typescript
  providers: [
    {
      provide: APP_GUARD,
      useClass: IpThrottlerGuard,
    },
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

**File:** back-end/apps/api/src/throttlers/email-throttler.module.ts (L13-23)
```typescript
          {
            name: 'anonymous-minute',
            ttl: seconds(60),
            limit: configService.getOrThrow<number>('ANONYMOUS_MINUTE_LIMIT'),
          },
          {
            name: 'anonymous-five-second',
            ttl: seconds(5),
            limit: configService.getOrThrow<number>('ANONYMOUS_FIVE_SECOND_LIMIT'),
          },
        ],
```
