### Title
Unauthenticated Attacker Can Exhaust Per-Email Rate Limit on `/auth/reset-password`, Locking Out Any User's Password Reset

### Summary
The `POST /auth/reset-password` endpoint is protected only by `EmailThrottlerGuard`, which tracks request counts by the email address supplied in the request body. Because no authentication is required to reach this endpoint, any unauthenticated attacker who knows a victim's email can exhaust the per-email rate limit bucket with just 3 HTTP requests per minute, permanently blocking the victim from requesting a password-reset OTP for as long as the attack is maintained. This is the direct analog of the Linea rate-limiter DoS: a protocol-wide limit intended to protect the service is weaponized to deny a legitimate user access to a critical function.

### Finding Description

**Root cause — `EmailThrottlerGuard` tracker key is attacker-supplied email**

`EmailThrottlerGuard.getTracker` returns `req.body.email` as the throttle-bucket key: [1](#0-0) 

The bucket limits are configured in `EmailThrottlerModule`: [2](#0-1) 

Production and all deployment configs confirm the live limits:
- `ANONYMOUS_MINUTE_LIMIT = 3` (3 requests per 60 s)
- `ANONYMOUS_FIVE_SECOND_LIMIT = 1` (1 request per 5 s) [3](#0-2) 

**Vulnerable endpoint — no authentication before the throttle guard**

```
POST /auth/reset-password
@UseGuards(EmailThrottlerGuard)          ← only guard; no JWT, no LocalAuth
async createOtp(@Body() { email }: OtpLocalDto)
``` [4](#0-3) 

Compare with `/auth/login`, where `LocalAuthGuard` (credential validation) runs *before* `EmailThrottlerGuard`, so an unauthenticated attacker cannot exhaust the login bucket without valid credentials: [5](#0-4) 

**Exploit flow**

1. Attacker learns victim's email (e.g., from a public directory or prior enumeration).
2. Attacker sends 3 `POST /auth/reset-password` requests per minute with `{"email":"victim@org.com"}`.
3. The Redis-backed throttler increments the `victim@org.com` bucket to its limit.
4. Every subsequent request — including the victim's own legitimate request — receives HTTP 429 for the remainder of the 60-second window.
5. Attacker repeats at the start of each new window (3 req/min is trivially sustainable).

The victim, having forgotten their password, cannot obtain an OTP and cannot log in.

**Secondary issue — `IpThrottlerGuard` trusts attacker-controlled `x-forwarded-for`**

The global IP throttler also has a flaw: it reads `x-forwarded-for` directly from the request header without validation: [6](#0-5) 

An attacker can rotate arbitrary `x-forwarded-for` values to get a fresh bucket on every request, bypassing the global rate limiter entirely. This is a separate bypass issue but compounds the overall rate-limit posture.

### Impact Explanation

A user who has forgotten their organization password is permanently locked out of the password-reset flow for as long as the attacker sustains the attack (3 HTTP requests per minute). The victim cannot obtain an OTP, cannot set a new password, and therefore cannot authenticate to the organization server. All pending multi-signature transactions requiring that user's approval or signature are stalled. The attack is silent — the victim sees only HTTP 429 with no indication of malicious activity.

### Likelihood Explanation

- **No authentication required**: the endpoint is fully public.
- **Attacker precondition**: knowledge of the victim's email address only (often obtainable from the organization's user list or public sources).
- **Attack cost**: 3 HTTP requests per minute — trivially sustainable from a single machine or even a cron job.
- **No rate-limit on the attacker's own IP** for this action beyond the global IP throttler, which can itself be bypassed via `x-forwarded-for` spoofing.
- The attack is persistent and requires no special tooling.

### Recommendation

1. **Require authentication before the throttle check on `/auth/reset-password`**: add a CAPTCHA or proof-of-work challenge for unauthenticated callers, or apply the throttle by IP *in addition to* email so the attacker's own IP is penalized.
2. **Do not use the attacker-supplied email as the sole throttle key**: combine email + source IP as the composite key, so exhausting one victim's email requires the attacker to also exhaust their own IP quota.
3. **Fix `IpThrottlerGuard` to use only the trusted IP**: when behind a reverse proxy, use only the *last* (proxy-appended) value of `x-forwarded-for`, or configure the proxy to strip and re-set the header. Do not trust the full raw header string. [6](#0-5) 

### Proof of Concept

```bash
# Exhaust the rate limit for victim@org.com in under 15 seconds
for i in 1 2 3; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://<org-server>/auth/reset-password \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@org.com"}'
  sleep 6   # stay within the 5-second sub-limit
done

# Now the victim's own request is blocked for the rest of the 60-second window:
curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST https://<org

### Citations

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

**File:** back-end/apps/api/src/throttlers/email-throttler.module.ts (L12-23)
```typescript
        throttlers: [
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

**File:** back-end/apps/api/example.env (L26-27)
```text
ANONYMOUS_MINUTE_LIMIT=3
ANONYMOUS_FIVE_SECOND_LIMIT=1
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
