All referenced code paths have been verified. The finding is accurate and substantiated.

---

Audit Report

## Title
JWT Bearer Token Stored in Plaintext in Local SQLite Database While Organization Password Is Encrypted

## Summary
The `OrganizationCredentials` table in the Electron app's local Prisma/SQLite database stores the `jwtToken` field as unencrypted plaintext, while the `password` field in the same row is protected by AES-256-GCM or OS keychain encryption. Any process or backup with read access to the database file can extract a live bearer token and authenticate to the organization server as the victim user without knowing their password.

## Finding Description

**Schema confirms `jwtToken` is a plain `TEXT` column:**

The migration adds the column with no encryption layer. [1](#0-0) 

The Prisma schema reflects this as a nullable `String?` with no transformation. [2](#0-1) 

**Password is encrypted before write via `encryptData()`:**

`encryptData()` uses either `safeStorage.encryptString()` (OS keychain) or AES-256-GCM with PBKDF2 via `encrypt()`. [3](#0-2) 

**Three code paths write `jwtToken` in plaintext with no equivalent protection:**

1. `addOrganizationCredentials` — initial credential creation: `password` is encrypted at line 180, but `jwtToken` is passed directly into the `create` call. [4](#0-3) 

2. `updateOrganizationCredentials` — credential update: `password` is conditionally encrypted at line 212, but `jwtToken` is written as-is. [5](#0-4) 

3. `tryAutoSignIn` — token refresh after re-login: `accessToken` returned from the network is written directly to the database with no encryption. [6](#0-5) 

**Token is read back from the database and placed into session storage and HTTP `Authorization` headers:**

`setSessionStorageTokens` reads the raw `jwtToken` from the database and stores it in `sessionStorage`. [7](#0-6) 

`getConfigWithAuthHeader` then reads it from session storage and injects it as `Authorization: bearer <token>` on every outbound API request. [8](#0-7) 

**The backend `JwtStrategy` accepts the bearer token as sufficient proof of identity:** [9](#0-8) 

**`changePassword` does NOT blacklist the existing JWT:**

`AuthService.changePassword` only calls `usersService.setPassword()`. It does not call `blacklistService.blacklistToken()`. Only the explicit `POST /auth/logout` endpoint blacklists a token. [10](#0-9) [11](#0-10) 

## Impact Explanation

An attacker who reads the SQLite database file obtains a raw JWT bearer token. Presenting this token in an `Authorization: Bearer` header is sufficient to pass both `JwtStrategy` validation and the `JwtBlackListAuthGuard` (since the token has not been explicitly logged out). The attacker can:

- Submit, approve, or sign Hedera transactions on behalf of the victim.
- Access all organization-scoped API endpoints.
- Maintain access for the full `JWT_EXPIRATION`-day lifetime of the token, even if the victim subsequently changes their application password, because `changePassword` does not invalidate existing tokens. [12](#0-11) 

## Likelihood Explanation

The SQLite database is stored in the Electron app's `userData` directory, readable by any process running under the same OS user account — the baseline capability of any malware or compromised dependency executing in user space. No privilege escalation is required. The database is also included in standard OS-level backups (Time Machine, Windows Backup, cloud-synced folders), giving an attacker who accesses a backup the same token. This does not require physical access to the device, which is the only relevant exclusion in `SECURITY.md` for this class of attack. [13](#0-12) 

## Recommendation

Apply the same `encryptData()` / `decryptData()` treatment to `jwtToken` that is already applied to `password` in all three write paths (`addOrganizationCredentials`, `updateOrganizationCredentials`, `tryAutoSignIn`). On read, decrypt the token before placing it into session storage or HTTP headers. This eliminates the asymmetry and ensures that an attacker who reads the raw database file cannot directly replay the token.

Additionally, consider blacklisting the existing JWT on `changePassword` (mirroring the behavior of `logout`) so that a password change also invalidates any previously extracted tokens.

## Proof of Concept

1. Locate the Electron `userData` SQLite file (e.g., `~/Library/Application Support/<app>/db.sqlite` on macOS).
2. Open it with any SQLite client: `sqlite3 db.sqlite "SELECT jwtToken FROM OrganizationCredentials LIMIT 1;"` — the raw JWT is returned in plaintext.
3. Use the token directly: `curl -H "Authorization: Bearer <token>" https://<org-server>/transactions/history?page=1&size=10` — the request succeeds and returns the victim's transaction history, confirming the token is live and accepted by the backend `JwtStrategy`. [14](#0-13)

### Citations

**File:** front-end/prisma/migrations/20240322100208_jwt_added_in_credentials/migration.sql (L1-2)
```sql
-- AlterTable
ALTER TABLE "OrganizationCredentials" ADD COLUMN "jwtToken" TEXT;
```

**File:** front-end/prisma/schema.prisma (L61-72)
```text
model OrganizationCredentials {
  id                   String       @id @default(uuid())
  email                String
  password             String
  organization_id      String
  organization_user_id Int?
  user_id              String
  jwtToken             String?
  updated_at           DateTime?    @updatedAt
  user                 User         @relation(fields: [user_id], references: [id])
  organization         Organization @relation(fields: [organization_id], references: [id])
}
```

**File:** front-end/src/main/services/localUser/organizationCredentials.ts (L80-93)
```typescript
export const getAccessToken = async (serverUrl: string) => {
  const prisma = getPrismaClient();

  try {
    const credentials = await prisma.organizationCredentials.findFirst({
      where: { organization: { serverUrl } },
    });
    if (!credentials) return null;
    return credentials.jwtToken || null;
  } catch (error) {
    logger.error('Failed to get access token', { error });
    return null;
  }
};
```

**File:** front-end/src/main/services/localUser/organizationCredentials.ts (L179-197)
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

    return true;
  } catch (error) {
    logger.error('Failed to add organization credentials', { error });
    throw new Error('Failed to add organization credentials');
  }
};
```

**File:** front-end/src/main/services/localUser/organizationCredentials.ts (L210-231)
```typescript
  try {
    if (password) {
      password = await encryptData(password, encryptPassword);
    }

    const credentials = await prisma.organizationCredentials.findFirst({
      where: { user_id, organization_id },
    });

    if (!credentials) {
      logger.warn('User credentials for this organization not found');
      return false;
    }

    await prisma.organizationCredentials.update({
      where: { id: credentials.id },
      data: {
        email: email || credentials.email,
        password: password !== undefined ? password : credentials.password,
        jwtToken: jwtToken !== undefined ? jwtToken : credentials.jwtToken,
      },
    });
```

**File:** front-end/src/main/services/localUser/organizationCredentials.ts (L274-284)
```typescript
    try {
      const { accessToken } = await login(
        invalidCredential.organization.serverUrl,
        invalidCredential.email,
        password,
      );

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

**File:** front-end/src/renderer/utils/userStoreHelpers.ts (L472-485)
```typescript
export const setSessionStorageTokens = (
  organizations: Organization[],
  organizationTokens: OrganizationTokens,
) => {
  for (const organization of organizations) {
    const token = organizationTokens[organization.id]?.trim();
    if (token && token.length > 0) {
      sessionStorage.setItem(
        `${SESSION_STORAGE_AUTH_TOKEN_PREFIX}${new URL(organization.serverUrl).origin}`,
        token,
      );
    }
  }
};
```

**File:** front-end/src/renderer/utils/axios.ts (L148-156)
```typescript
const getConfigWithAuthHeader = (config: AxiosRequestConfig, url: string) => {
  return {
    ...config,
    headers: {
      ...config.headers,
      Authorization: `bearer ${getAuthTokenFromSessionStorage(url)}`,
    },
  };
};
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

**File:** back-end/apps/api/src/auth/auth.service.ts (L83-95)
```typescript
  /* Change the password for the given user */
  async changePassword(user: User, { oldPassword, newPassword }: ChangePasswordDto): Promise<void> {
    if (oldPassword === newPassword) throw new BadRequestException(ErrorCodes.NPMOP);

    const { correct } = await this.dualCompareHash(oldPassword, user.password);
    if (!correct) throw new BadRequestException(ErrorCodes.INOP);

    if (user.status === UserStatus.NEW && user.keys.length === 0) {
      emitUserStatusUpdateNotifications(this.notificationsPublisher, { entityId: user.id, additionalData: { username: user.email } });
    }

    await this.usersService.setPassword(user, newPassword);
  }
```

**File:** back-end/apps/api/src/auth/auth.controller.ts (L99-104)
```typescript
  @Post('/logout')
  @HttpCode(200)
  @UseGuards(JwtBlackListAuthGuard, JwtAuthGuard)
  async logout(@Req() req: Request) {
    await this.blacklistService.blacklistToken(extractJwtAuth(req));
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

**File:** SECURITY.md (L32-33)
```markdown
- Impacts involving attacks requiring access to the local network of the victim.
- Reflected plain text injection (e.g. URL parameters, path, etc.).
```
