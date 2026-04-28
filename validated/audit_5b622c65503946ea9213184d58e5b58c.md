All key facts are now verified. Here is the audit report:

---

Audit Report

## Title
Spoofable `x-forwarded-for` Header Used as Trusted Rate-Limit Key in `IpThrottlerGuard`, Enabling IP Throttle Bypass

## Summary
`IpThrottlerGuard.getTracker()` resolves the client identity for rate limiting by reading the attacker-controlled `x-forwarded-for` HTTP header before falling back to `req.ip`. Because any HTTP client can set this header to an arbitrary value, an attacker can rotate fake IP strings per request and bypass the global IP-based rate limiter entirely. This is compounded by the production configuration enabling `trust proxy` unconditionally, which makes even `req.ip` derive from the same attacker-controlled header.

## Finding Description

**Root cause — `IpThrottlerGuard.getTracker()`**

`back-end/apps/api/src/guards/ip-throttler.guard.ts`, line 8:
```typescript
protected getTracker(req: Record<string, any>): Promise<string> {
  const clientIp = req.headers['x-forwarded-for'] || req.ip;
  ...
  return clientIp;
}
``` [1](#0-0) 

`x-forwarded-for` is checked **first**. It is a plain HTTP request header; any client can set it to any string.

**Compounding factor — unconditional `trust proxy` in production**

`back-end/apps/api/src/main.ts`, lines 32–37:
```typescript
async function createAppForDeployment(): Promise<NestExpressApplication> {
  const app = (await NestFactory.create(ApiModule)) as NestExpressApplication;
  app.enable('trust proxy');
  return app;
}
``` [2](#0-1) 

`app.enable('trust proxy')` is equivalent to `trust proxy = true`, which instructs Express to trust **all** proxies. As a result, `req.ip` is set to the leftmost IP in `x-forwarded-for` — which is also attacker-controlled. The fallback to `req.ip` therefore provides no protection: both the primary and fallback values are derived from the same spoofable header.

**Guard is wired globally**

`back-end/apps/api/src/api.module.ts`, lines 73–78:
```typescript
providers: [
  {
    provide: APP_GUARD,
    useClass: IpThrottlerGuard,
  },
``` [3](#0-2) 

**Actual limits being bypassed**

The `IpThrottlerModule` (which backs `IpThrottlerGuard`) uses `GLOBAL_MINUTE_LIMIT` and `GLOBAL_SECOND_LIMIT`: [4](#0-3) 

Production values from Helm charts and k8s manifests: `GLOBAL_MINUTE_LIMIT=10000`, `GLOBAL_SECOND_LIMIT=1000`. [5](#0-4) 

**Correction to the submitted report**: The submitted report incorrectly attributes `ANONYMOUS_MINUTE_LIMIT=3` and `ANONYMOUS_FIVE_SECOND_LIMIT=1` to `IpThrottlerGuard`. Those limits are consumed by `EmailThrottlerModule`, which backs `EmailThrottlerGuard` (keyed on `req.body.email`), not `IpThrottlerGuard`. [6](#0-5) 

The actual limits bypassed via IP spoofing are the global ones (`10000/min`, `1000/sec`). The tight anonymous limits (`3/min`, `1/5s`) apply to the email-keyed throttler, which is not affected by IP header spoofing.

**Exploit flow**

1. Attacker sends `POST /auth/login` with `x-forwarded-for: 1.0.0.1`. Counter for key `1.0.0.1` increments.
2. Next request uses `x-forwarded-for: 1.0.0.2`. Fresh counter — no throttle.
3. Repeat indefinitely with rotating fake IPs. The `GLOBAL_MINUTE_LIMIT=10000` and `GLOBAL_SECOND_LIMIT=1000` limits are never reached for any single key.

## Impact Explanation

- **Rate-limit bypass**: The global IP throttle (`10000 req/min`, `1000 req/sec`) is completely neutralised for any attacker who sets a rotating `x-forwarded-for` header.
- **Brute-force enablement**: Endpoints that depend solely on IP throttling (e.g., OTP verification) become open to unlimited attempts, making short numeric OTP codes brute-forceable within their validity window.
- **Scale abuse**: An attacker can drive arbitrarily high request volume to any unauthenticated endpoint without triggering any throttle counter, degrading service for legitimate users.
- **Multi-email enumeration**: An attacker targeting many distinct email addresses simultaneously is not constrained by the per-email throttle and can enumerate or brute-force at scale.

## Likelihood Explanation

- **No privileges required**: Any unauthenticated HTTP client can set arbitrary headers.
- **Trivial to automate**: A single `curl` loop rotating `x-forwarded-for` values is sufficient.
- **Worsened by `trust proxy = true`**: Even the fallback `req.ip` is attacker-controlled in production, so there is no server-side path to a trustworthy IP.
- **Directly reachable**: The guard is applied globally to all API routes via `IpThrottlerModule`.

## Recommendation

1. **Fix `getTracker`**: Remove the `x-forwarded-for` header read entirely. Rely solely on `req.ip`:
   ```typescript
   protected getTracker(req: Record<string, any>): Promise<string> {
     const clientIp = req.ip;
     if (!clientIp) {
       throw new HttpException('Unable to determine client IP', HttpStatus.INTERNAL_SERVER_ERROR);
     }
     return clientIp;
   }
   ```
2. **Fix `trust proxy` configuration**: Change `app.enable('trust proxy')` to `app.set('trust proxy', 1)` (or the exact number of trusted proxy hops in the infrastructure). With `trust proxy = true`, Express trusts all proxies and `req.ip` is still the leftmost (attacker-controlled) IP. Setting it to `1` causes Express to strip the attacker-supplied leftmost entry and use the proxy-appended real client IP.
3. **Apply the same fix to `FrontendVersionGuard`**: It reads `x-forwarded-for` for logging only, which is harmless for security but should be consistent.

## Proof of Concept

```bash
# Bypass the global IP rate limiter by rotating x-forwarded-for values
for i in $(seq 1 50000); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "x-forwarded-for: 10.0.$((i/256)).$((i%256))" \
    -H "x-frontend-version: 0.24.0" \
    -X POST https://target/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@example.com","password":"guess'"$i"'"}'
done
# Each request uses a fresh throttle key; no 429 is ever returned.
```

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

**File:** back-end/k8s/back-end/api-deployment.yaml (L78-81)
```yaml
            - name: GLOBAL_MINUTE_LIMIT
              value: '10000'
            - name: GLOBAL_SECOND_LIMIT
              value: '1000'
```

**File:** back-end/apps/api/src/throttlers/email-throttler.module.ts (L14-22)
```typescript
            name: 'anonymous-minute',
            ttl: seconds(60),
            limit: configService.getOrThrow<number>('ANONYMOUS_MINUTE_LIMIT'),
          },
          {
            name: 'anonymous-five-second',
            ttl: seconds(5),
            limit: configService.getOrThrow<number>('ANONYMOUS_FIVE_SECOND_LIMIT'),
          },
```
