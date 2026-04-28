### Title
`mnemonicHash` and `index` of All Users' Keys Exposed to Any Authenticated User via `GET /user-keys` Endpoint

### Summary
The backend API exposes the `mnemonicHash` (a fingerprint of a user's 24-word recovery phrase) and `index` (key derivation index) for every user's keys to any authenticated, verified user through the `GET /user-keys` endpoint. The codebase explicitly treats these fields as private to the key owner in the `getUserKeysRestricted` path, but the `getUserKeys` path used by `UserKeysAllController` applies no such field-level restriction, creating a bypass.

### Finding Description

**Root Cause:**

The `UserKeysService` has two distinct methods for fetching keys:

1. `getUserKeysRestricted` — used by `UserKeysController` at `GET /user/:userId/keys`. It explicitly hides `mnemonicHash` and `index` when the requesting user is not the key owner: [1](#0-0) 

2. `getUserKeys` — used by `UserKeysAllController` at `GET /user-keys`. It performs an unrestricted `findAndCount` with no field-level filtering: [2](#0-1) 

The `UserKeyDto` serializer unconditionally exposes `mnemonicHash` and `index` via `@Expose()`: [3](#0-2) 

The `UserKeysAllController` is guarded only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — no admin guard — meaning any verified user can call it: [4](#0-3) 

**Exploit Flow:**

1. Attacker registers and becomes a verified user (standard product flow).
2. Attacker calls `GET /user-keys` with their JWT.
3. The response contains every user's `id`, `userId`, `publicKey`, `mnemonicHash`, and `index` — paginated across all users in the system.

The e2e test for the *restricted* path explicitly asserts that `mnemonicHash` must not appear for other users' keys, confirming the developers' intent that this field is private: [5](#0-4) 

The `GET /user-keys` path has no equivalent test asserting this protection, and the service code confirms it is absent.

### Impact Explanation

`mnemonicHash` is the argon2 hash of a user's 24-word BIP39 recovery phrase, stored in the `user_key` table: [6](#0-5) 

Exposure of `mnemonicHash` to other users allows:
- **Recovery phrase verification**: An attacker who obtains a candidate recovery phrase (e.g., via phishing or social engineering) can confirm whether it belongs to a specific user by computing its argon2 hash and comparing it to the leaked value — without ever touching the backend's authentication flow.
- **Key correlation**: An attacker can determine which keys across the system share the same recovery phrase (same `mnemonicHash`), revealing the full key derivation structure of every user.
- **Index disclosure**: The `index` field reveals the exact BIP32 derivation index used, reducing the search space in any offline attack against the recovery phrase.

The `mnemonicHash` is generated with a pseudo-salt (data-derived, not random) in some code paths, making it deterministic and directly comparable: [7](#0-6) 

### Likelihood Explanation

- **Attacker precondition**: Only a valid, verified account is required — a standard product registration flow.
- **No privilege required**: The endpoint has no admin guard.
- **Trivially reachable**: A single authenticated HTTP GET request to `/user-keys` is sufficient.
- **No rate-limit or anomaly detection** is visible on this endpoint.

### Recommendation

Apply the same field-level access control used in `getUserKeysRestricted` to `getUserKeys`. Since `getUserKeys` returns keys for all users, `mnemonicHash` and `index` must be excluded from the response entirely (they are per-owner secrets with no legitimate cross-user use case). Either:

1. Remove `@Expose()` from `mnemonicHash` and `index` in `UserKeyDto` and create a separate owner-only DTO, or
2. Add a `select` clause to `getUserKeys` that omits `mnemonicHash` and `index`, mirroring the pattern in `getUserKeysRestricted`.

Additionally, restrict `GET /user-keys` to admin users if its purpose is administrative enumeration.

### Proof of Concept

```
POST /auth/login
Body: { "email": "attacker@example.com", "password": "..." }
→ Receive JWT

GET /user-keys?page=1&limit=50
Authorization: Bearer <JWT>

Response:
{
  "totalItems": N,
  "items": [
    {
      "id": 1,
      "userId": 2,
      "publicKey": "e0c8ec...",
      "mnemonicHash": "7a40e67733edaec462d6b4a31f026cc37f96f767d6a581e41f71785516d42929",
      "index": 0,
      "deletedAt": null
    },
    ...
  ]
}
```

The attacker now holds the `mnemonicHash` for every user in the system. To verify a candidate recovery phrase for victim user ID 2, the attacker computes `argon2(candidatePhrase)` locally and compares it to the leaked hash — confirming or denying the phrase without any server interaction.

### Citations

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L68-81)
```typescript
  // Get the list of user keys for the provided userId
  async getUserKeysRestricted(user: User, userId: number): Promise<UserKey[]> {
    if (!userId) return [];
    return this.repo.find({
      where: { userId },
      select: {
        id: true,
        userId: true,
        mnemonicHash: user.id === userId,
        index: user.id === userId,
        publicKey: true,
      },
    });
  }
```

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L139-156)
```typescript
  async getUserKeys({
    page,
    limit,
    size,
    offset,
  }: Pagination): Promise<PaginatedResourceDto<UserKey>> {
    const [items, total] = await this.repo.findAndCount({
      take: limit,
      skip: offset,
    });

    return {
      totalItems: total,
      items,
      page,
      size,
    };
  }
```

**File:** back-end/apps/api/src/user-keys/dtos/user-key.dto.ts (L1-21)
```typescript
import { Expose } from 'class-transformer';

export class UserKeyDto {
  @Expose()
  id: number;

  @Expose()
  userId: number;

  @Expose()
  mnemonicHash?: string;

  @Expose()
  index?: number;

  @Expose()
  publicKey: string;

  @Expose()
  deletedAt?: Date;
}
```

**File:** back-end/apps/api/src/user-keys/user-keys-all.controller.ts (L18-38)
```typescript
@ApiTags('User Keys All')
@Controller('user-keys')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class UserKeysAllController {
  constructor(private userKeysService: UserKeysService) {}

  @ApiOperation({
    summary: 'Get all user keys for user',
    description: 'Get all the user keys for the provided user id.',
  })
  @ApiResponse({
    status: 200,
    type: PaginatedResourceDto<UserKeyDto>,
  })
  @Get()
  @Serialize(withPaginatedResponse(UserKeyDto))
  getUserKeys(
    @PaginationParams() paginationParams: Pagination,
  ): Promise<PaginatedResourceDto<UserKey>> {
    return this.userKeysService.getUserKeys(paginationParams);
  }
```

**File:** back-end/apps/api/test/spec/user-keys.e2e-spec.ts (L46-56)
```typescript
    it('(GET) should get keys of other user if verified', async () => {
      const res = await endpoint.get(`/${admin.id}/keys`, userAuthToken).expect(200);

      const actualUserKeys = await getUserKeys(1);

      expect(res.body).toHaveLength(actualUserKeys.length);
      res.body.forEach(key => {
        expect(key).not.toHaveProperty('mnemonicHash');
        expect(key).not.toHaveProperty('index');
      });
    });
```

**File:** docs/database/tables/user_key.md (L1-36)
```markdown
# user_key

**Description**: A table that contains information about user's keys.

## Columns

| Column Name      | Type    | Description                                                    |
| ---------------- | ------- | -------------------------------------------------------------- |
| **id**           | Integer | The primary key for the table. Unique identifier for each key. |
| **mnemonicHash** | String  | The mneumonic (24 word recovery phrase) hash.                  |
| **index**        | String  | The index at which the private key was created.                |
| **publicKey**    | Text    | Public key associated with the key.                            |
| **deletedAt**    | String  | Timestamp of when the key was removed                          |
| **userId**       | String  | The ID of the related user. ( Foreign key to user)             |

### Example Query

```sql
SELECT * FROM "user_key" WHERE "id" = '1';
```

### Example Response

```
id: 1

mnemonicHash: 7a40e67733edaec462d6b4a31f026cc37f96f767d6a581e41f71785516d42929

index: 0

publicKey: 5a7245ff4fbbc301ec0a4b4c9d04117d7527759431d8fab1729a7dbfb715094f

deletedAt:

userId: 1
```
```

**File:** front-end/src/main/utils/crypto.ts (L45-53)
```typescript
export async function hash(data: string, usePseudoSalt = false): Promise<string> {
  let pseudoSalt: Buffer | undefined;
  if (usePseudoSalt) {
    const paddedData = data.padEnd(16, 'x');
    pseudoSalt = Buffer.from(paddedData.slice(0, 16));
  }
  return await argon2.hash(data, {
    salt: pseudoSalt,
  });
```
