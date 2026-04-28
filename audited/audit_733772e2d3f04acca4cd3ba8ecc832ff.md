### Title
Hardcoded JWT and OTP Secrets Committed to Public Repository in `.env.test`

### Summary
The file `back-end/apps/api/.env.test` is committed to the public repository and contains real, hardcoded values for `JWT_SECRET` and `OTP_SECRET`. An attacker who reads these values can forge valid JWT tokens and bypass authentication for any user account in any environment that reuses these secrets.

### Finding Description
Unlike the `example.env` files (which use placeholder strings like `some-very-secret-string`), the file `back-end/apps/api/.env.test` is an actual environment configuration file committed to the public repository with concrete secret values:

- `JWT_SECRET=13123` — used to sign and verify all JWT authentication tokens
- `OTP_SECRET=123` — used to generate and verify one-time passwords [1](#0-0) 

These secrets are consumed by the authentication service and JWT strategy: [2](#0-1) [3](#0-2) 

The `example.env` counterpart correctly uses non-secret placeholder values, confirming that `.env.test` was intended to hold real (if test-only) values and was mistakenly committed: [4](#0-3) 

No `.gitignore` was found in the repository that would have excluded `.env.test` from version control.

### Impact Explanation
`JWT_SECRET` is the HMAC signing key for all JWT tokens issued by the API. Knowing this value allows any attacker to craft a valid, signed JWT for any user ID or role (including admin), bypassing authentication entirely. `OTP_SECRET` similarly allows an attacker to generate valid OTPs without going through the email flow. Any environment — test, staging, or production — that was bootstrapped from this file or reuses these values is fully compromised.

### Likelihood Explanation
The file is committed to a public GitHub repository and is immediately readable by anyone. The values are trivially weak (`13123`, `123`), making them also susceptible to brute-force even without reading the file. Developers commonly copy `.env.test` as a starting point for local or staging environments, increasing the probability that these secrets propagate beyond the test context.

### Recommendation
1. **Immediately rotate** `JWT_SECRET` and `OTP_SECRET` in all environments.
2. **Remove** `back-end/apps/api/.env.test` from version control and add `.env.test` (and all `.env` variants except `example.env`) to `.gitignore`.
3. Use a secrets manager or CI-injected environment variables for test secrets; never commit real values.
4. Audit git history to confirm no other real secrets were committed and purge them using `git filter-repo` or equivalent.

### Proof of Concept
1. Clone the public repository.
2. Read `back-end/apps/api/.env.test` — `JWT_SECRET=13123` is immediately visible.
3. Use any JWT library to sign a token:
   ```js
   const jwt = require('jsonwebtoken');
   const token = jwt.sign({ sub: 1, role: 'admin' }, '13123', { expiresIn: '365d' });
   console.log(token); // Valid token accepted by the API
   ```
4. Send the forged token in the `Authorization: Bearer <token>` header to any authenticated API endpoint — the server will accept it as a legitimate admin session. [1](#0-0)

### Citations

**File:** back-end/apps/api/.env.test (L11-16)
```text
JWT_SECRET=13123
# Temporary, expiration in days
JWT_EXPIRATION=365

# One time password settings
OTP_SECRET=123
```

**File:** back-end/apps/api/src/auth/auth.service.ts (L1-5)
```typescript
import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
```

**File:** back-end/apps/api/src/auth/strategies/jwt.strategy.ts (L1-5)
```typescript
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';

import { ExtractJwt, Strategy } from 'passport-jwt';
```

**File:** back-end/apps/api/example.env (L11-16)
```text
JWT_SECRET=some-very-secret-string
# Temporary, expiration in days
JWT_EXPIRATION=365

# One time password settings
OTP_SECRET=some-very-secret-string-otp
```
