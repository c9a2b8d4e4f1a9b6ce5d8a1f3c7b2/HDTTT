All code references check out. The vulnerability is confirmed. Here is the audit report:

---

Audit Report

## Title
Unfiltered `GET /user-keys` Endpoint Exposes All Users' `mnemonicHash` and `index` to Any Verified Organization Member

## Summary
`UserKeysAllController` at `GET /user-keys` calls `UserKeysService.getUserKeys()`, which performs an unfiltered `findAndCount` with no `userId` constraint and no field-level restriction. This returns every row in the `user_key` table — including the sensitive `mnemonicHash` and `index` fields — to any verified organization member. The sibling method `getUserKeysRestricted()` was explicitly designed to suppress these fields for non-owners, but `UserKeysAllController` bypasses that protection entirely.

## Finding Description

**Root cause — `getUserKeys()` has no `where` clause and no `select` restriction:**

`UserKeysService.getUserKeys()` issues a bare `findAndCount` with only pagination parameters: [1](#0-0) 

No `where: { userId }` filter, no `select` clause. TypeORM returns all columns for all rows.

**Contrast with the restricted path:**

`getUserKeysRestricted()` — used by `UserKeysController` at `GET /user/:userId/keys` — explicitly scopes by `userId` and conditionally suppresses `mnemonicHash` and `index` for non-owners: [2](#0-1) 

**The unprotected controller:**

`UserKeysAllController` at `GET /user-keys` passes no user identity to the service and applies only `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`: [3](#0-2) 

**`VerifiedUserGuard` only checks `user.status === UserStatus.NONE`:** [4](#0-3) 

No admin check, no ownership check, no scoping to the caller's own keys.

**What `UserKeyDto` serializes:**

`UserKeyDto` exposes `id`, `userId`, `mnemonicHash`, `index`, `publicKey`, and `deletedAt` — all fields, for all users: [5](#0-4) 

**`mnemonicHash` and `index` are sensitive fields per the entity and documentation:** [6](#0-5) [7](#0-6) 

## Impact Explanation

1. **Cross-user `mnemonicHash` leakage**: The hash of each user's 24-word BIP-39 mnemonic recovery phrase is exposed to every verified member. This reveals which keys share the same seed wallet, enabling correlation of a user's full key portfolio. It also provides a preimage target for offline dictionary or brute-force attacks against the mnemonic.
2. **`index` leakage**: The HD derivation index is exposed, revealing the key derivation structure of other users' wallets.
3. **Complete key infrastructure enumeration**: Any verified member can map every public key to its owning `userId`, building a full picture of the organization's key infrastructure.

The `getUserKeysRestricted()` method was explicitly designed to prevent exactly this — hiding `mnemonicHash` and `index` from non-owners — but `UserKeysAllController` bypasses that protection entirely.

## Likelihood Explanation

- **Attacker precondition**: Valid JWT for any verified organization member (`status = NONE`). No admin role required.
- **Exploitation**: Single HTTP GET request — `GET /user-keys?page=1&size=100`.
- **Discoverability**: The endpoint is registered in `UserKeysModule`, documented via Swagger (`@ApiTags('User Keys All')`), and actively called by the front-end client via `getAllUserKeys()` in `storeContacts.ts`: [8](#0-7) [9](#0-8) 

Any member who inspects network traffic or the Swagger API docs will find it immediately.

## Recommendation

Apply a field-level `select` restriction inside `getUserKeys()` to suppress `mnemonicHash` and `index` unconditionally (since this endpoint is not scoped to a single owner), mirroring the pattern used in `getUserKeysRestricted()`:

```typescript
async getUserKeys({ page, limit, size, offset }: Pagination): Promise<PaginatedResourceDto<UserKey>> {
  const [items, total] = await this.repo.findAndCount({
    take: limit,
    skip: offset,
    select: {
      id: true,
      userId: true,
      publicKey: true,
      deletedAt: true,
      // mnemonicHash and index intentionally omitted
    },
  });
  return { totalItems: total, items, page, size };
}
```

Alternatively, restrict the endpoint to admin-only access using `AdminGuard` if full field exposure is required for administrative purposes.

## Proof of Concept

```
# Attacker: any verified organization member
GET /user-keys?page=1&size=100
Authorization: Bearer <valid_jwt_for_any_verified_member>

# Response (200 OK):
{
  "totalItems": N,
  "items": [
    {
      "id": 1,
      "userId": 2,
      "publicKey": "...",
      "mnemonicHash": "7a40e67733edaec462d6b4a31f026cc37f96f767d6a581e41f71785516d42929",
      "index": 0,
      "deletedAt": null
    },
    ...  // all rows for all users
  ]
}
```

The front-end already exercises this exact flow via `getAllUserKeys()` → `getUserKeysPaginated()` → `GET /user-keys?page=X&size=100`. [10](#0-9)

### Citations

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L69-81)
```typescript
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

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L139-148)
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

**File:** back-end/apps/api/src/guards/verified-user.guard.ts (L12-22)
```typescript
  canActivate(context: ExecutionContext) {
    const { user } = context.switchToHttp().getRequest();

    const allowNonVerifiedUser = this.reflector.get<boolean>(
      ALLOW_NON_VERIFIED_USER,
      context.getHandler(),
    );
    if (allowNonVerifiedUser) return true;

    return user.status === UserStatus.NONE;
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

**File:** back-end/libs/common/src/database/entities/user-key.entity.ts (L28-32)
```typescript
  @Column({ nullable: true })
  mnemonicHash: string;

  @Column({ nullable: true })
  index: number;
```

**File:** docs/database/tables/user_key.md (L10-11)
```markdown
| **mnemonicHash** | String  | The mneumonic (24 word recovery phrase) hash.                  |
| **index**        | String  | The index at which the private key was created.                |
```

**File:** front-end/src/renderer/stores/storeContacts.ts (L118-123)
```typescript
    const allKeys = await getAllUserKeys(serverUrl);
    const userToKeys = new Map<number, IUserKey[]>();
    allKeys.forEach(k => {
      if (!userToKeys.has(k.userId)) userToKeys.set(k.userId, []);
      userToKeys.get(k.userId)?.push(k);
    });
```

**File:** front-end/src/renderer/services/organization/userKeys.ts (L66-77)
```typescript
export const getUserKeysPaginated = async (
  organizationServerUrl: string,
  page: number,
  size: number,
): Promise<PaginatedResourceDto<IUserKey>> =>
  commonRequestHandler(async () => {
    const response = await axiosWithCredentials.get(
      `${organizationServerUrl}/user-keys?page=${page}&size=${size}`,
    );

    return response.data;
  }, 'Failed to get user keys');
```

**File:** front-end/src/renderer/services/organization/userKeys.ts (L79-101)
```typescript
export const getAllUserKeys = async (organizationServerUrl: string): Promise<IUserKey[]> => {
  let page = 1;
  const size = 100;
  let totalItems = 0;
  const allUserKeys: IUserKey[] = [];

  do {
    const { data, error } = await safeAwait(
      getUserKeysPaginated(organizationServerUrl, page, size),
    );
    if (data) {
      totalItems = data.totalItems;
      allUserKeys.push(...data.items);
      page++;
    }

    if (error) {
      break;
    }
  } while (allUserKeys.length < totalItems);

  return allUserKeys;
};
```
