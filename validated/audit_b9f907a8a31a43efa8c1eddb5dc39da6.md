### Title
JWT Bearer Token Stored in Plaintext in Local SQLite Database While Organization Password Is Encrypted

### Summary
The `jwtToken` (JWT bearer token) used for organization server authentication is persisted in plaintext in the local Prisma/SQLite database, while the organization password in the same table is properly encrypted via AES-256-GCM or OS keychain. Any process or backup with read access to the database file can extract a live bearer token and authenticate to the organization server as the victim user without knowing their password.

### Finding Description

The `OrganizationCredentials` table stores two sensitive fields: `password` (encrypted) and `jwtToken` (plaintext). The asymmetry is clear in `organizationCredentials.ts`:

**Password is encrypted before write:** [1](#0-0) 

The `encryptData()` helper either uses Electron `safeStorage.encryptString()` (keychain mode) or AES-256-GCM with PBKDF2: [2](#0-1) 

**JWT token is written directly, without any encryption, in three separate code paths:**

1. `addOrganizationCredentials` — initial credential creation: [3](#0-2) 

2. `updateOrganizationCredentials` — credential update: [4](#0-3) 

3. `tryAutoSignIn` — token refresh after re-login: [5](#0-4) 

The token is also read back from the database in plaintext and placed directly into session storage and HTTP `Authorization` headers: [6](#0-5) [7](#0-6) 

The schema migration confirms `jwtToken` is a plain `TEXT` column with no encryption layer: [8](#0-7) 

### Impact Explanation

The JWT token is a bearer credential accepted by the organization back-end's `JwtStrategy`: [9](#0-8) 

Possession of the token is sufficient to authenticate as the victim user for the token's full lifetime (`JWT_EXPIRATION` days). An attacker who extracts the token can:
- Submit or approve Hedera transactions on behalf of the victim.
- Access all organization-scoped API endpoints.
- Maintain access until the token expires, even if the victim changes their application password (because the password change does not invalidate existing JWTs — the blacklist only covers explicit logout). [10](#0-9) 

### Likelihood Explanation

The SQLite database is stored in the Electron app's `userData` directory on disk. Any process running under the same OS user account (e.g., malware, a compromised dependency, another application) can read the file without any additional privilege escalation. The database is also included in standard OS-level backups (Time Machine, Windows Backup, cloud sync folders), giving an attacker who accesses a backup the same token. This does not require physical access to the device — it requires only the ability to read a file owned by the victim user, which is the baseline capability of any malware running in user space.

### Recommendation

Apply the same `encryptData()` / `decryptData()` pattern already used for the `password` field to the `jwtToken` field before persisting it. On write, call `encryptData(jwtToken, encryptPassword)`. On read in `getAccessToken` / `getOrganizationTokens`, call `decryptData(credentials.jwtToken, decryptPassword)` before returning the value. This ensures that even if the database file is exfiltrated, the token cannot be used without the user's encryption password or OS keychain access.

### Proof of Concept

1. Locate the Electron app's SQLite database (e.g., `~/Library/Application Support/hedera-transaction-tool/prisma/db.sqlite` on macOS).
2. Open it with any SQLite client: `sqlite3 db.sqlite "SELECT email, jwtToken FROM OrganizationCredentials;"`
3. The `jwtToken` column contains a live, unencrypted JWT string.
4. Use it directly: `curl -H "Authorization: bearer <token>" https://<org-server>/api/transactions`
5. The server accepts the request and returns data scoped to the victim's organization account, confirming full authentication bypass without knowledge of the user's password.

### Citations

**File:** front-end/src/main/services/localUser/organizationCredentials.ts (L179-190)
```typescript
  try {
    password = await encryptData(password, encryptPassword);

    await prisma.organizationCredentials.create({
      data: {
        email,
        password,
        jwtToken,
        organization_id,
        user_id,
      },
    });
```

**File:** front-end/src/main/services/localUser/organizationCredentials.ts (L224-231)
```typescript
    await prisma.organizationCredentials.update({
      where: { id: credentials.id },
      data: {
        email: email || credentials.email,
        password: password !== undefined ? password : credentials.password,
        jwtToken: jwtToken !== undefined ? jwtToken : credentials.jwtToken,
      },
    });
```

**File:** front-end/src/main/services/localUser/organizationCredentials.ts (L281-284)
```typescript
      await prisma.organizationCredentials.update({
        where: { id: invalidCredential.id },
        data: { jwtToken: accessToken },
      });
```

**File:** front-end/src/main/services/localUser/organizationCredentials.ts (L293-305)
```typescript
/* Encrypt data */
async function encryptData(data: string, encryptPassword?: string | null) {
  const useKeychain = await getUseKeychainClaim();

  if (useKeychain) {
    const passwordBuffer = safeStorage.encryptString(data);
    return passwordBuffer.toString('base64');
  } else if (encryptPassword) {
    return encrypt(data, encryptPassword);
  } else {
    throw new Error('Password is required to store sensitive data');
  }
}
```

**File:** front-end/src/renderer/utils/userStoreHelpers.ts (L459-470)
```typescript
export const getOrganizationJwtTokens = async (
  user: PersonalUser | null,
): Promise<OrganizationTokens> => {
  if (isUserLoggedIn(user)) {
    const organizationTokens = await getOrganizationTokens(user.id);
    return organizationTokens.reduce<OrganizationTokens>((acc, token) => {
      acc[token.organization_id] = token.jwtToken;
      return acc;
    }, {});
  }
  return {};
};
```

**File:** front-end/src/renderer/utils/userStoreHelpers.ts (L499-514)
```typescript
export const toggleAuthTokenInSessionStorage = (
  serverUrl: string,
  token: string,
  remove: boolean = false,
) => {
  const origin = new URL(serverUrl).origin;
  if (remove) {
    sessionStorage.removeItem(`${SESSION_STORAGE_AUTH_TOKEN_PREFIX}${origin}`);
    return;
  }
  sessionStorage.setItem(`${SESSION_STORAGE_AUTH_TOKEN_PREFIX}${origin}`, token);
};

export const getAuthTokenFromSessionStorage = (serverUrl: string): string | null => {
  const origin = new URL(serverUrl).origin;
  return sessionStorage.getItem(`${SESSION_STORAGE_AUTH_TOKEN_PREFIX}${origin}`);
```

**File:** front-end/prisma/migrations/20240322100208_jwt_added_in_credentials/migration.sql (L1-2)
```sql
-- AlterTable
ALTER TABLE "OrganizationCredentials" ADD COLUMN "jwtToken" TEXT;
```

**File:** back-end/apps/api/src/auth/strategies/jwt.strategy.ts (L19-32)
```typescript
    super({
      secretOrKey: configService.get('JWT_SECRET'),
      ignoreExpiration: false,
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    });
  }

  async validate({ userId }: JwtPayload): Promise<User> {
    const user = await this.usersService.getUser({ id: userId });

    if (!user) throw new UnauthorizedException();

    return user;
  }
```

**File:** back-end/libs/common/src/blacklist/blacklist.service.ts (L17-27)
```typescript
  async blacklistToken(jwt: string) {
    const expirationDays = this.configService.get<number>('JWT_EXPIRATION');
    const expirationSeconds = Number(expirationDays) * 24 * 60 * 60;

    await this.client.set(jwt, this.BLACKLISTED, 'EX', expirationSeconds);
  }

  async isTokenBlacklisted(jwt: string) {
    const data = await this.client.get(jwt);
    return data === this.BLACKLISTED;
  }
```
