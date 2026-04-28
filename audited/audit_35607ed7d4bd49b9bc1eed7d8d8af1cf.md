### Title
`GET /user-keys` Description Claims User-Scoped Access But Implementation Returns All Users' Keys Without Filtering

### Summary
`UserKeysAllController.getUserKeys` at `GET /user-keys` is documented as "Get all the user keys for the provided user id," but the implementation accepts no `userId` parameter and performs an unrestricted database query returning every key for every user in the organization. This is the same vulnerability class as the external report: the stated access restriction (per-user scoping) does not exist in the actual code.

### Finding Description
In `back-end/apps/api/src/user-keys/user-keys-all.controller.ts`, the endpoint is described as scoped to a specific user:

```
summary: 'Get all user keys for user',
description: 'Get all the user keys for the provided user id.',
```

But the handler signature accepts no `userId` and no `@GetUser()` decorator: [1](#0-0) 

It delegates directly to `UserKeysService.getUserKeys`, which issues a completely unfiltered `findAndCount`: [2](#0-1) 

No `where` clause, no user identity check — every row in the `user_key` table is returned.

Contrast this with the correctly-scoped sibling endpoint `UserKeysController.getUserKeys` at `GET /user/:userId/keys`, which calls `getUserKeysRestricted` and explicitly restricts sensitive fields (`mnemonicHash`, `index`) to the key owner: [3](#0-2) 

The `GET /user-keys` path has no equivalent restriction. The `getUserKeys` service method fetches all columns with no `select` clause, so whatever `UserKeyDto` serializes is returned for every user's keys.

The guards on the controller are only `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — no `AdminGuard`, no ownership check: [4](#0-3) 

### Impact Explanation
Any verified (non-new) organization user can call `GET /user-keys` and receive the full paginated list of every user key registered in the organization. Because `getUserKeys` performs no `select` projection, all database columns — including `mnemonicHash` and `index` — are fetched and passed to the serializer. If `UserKeyDto` exposes those fields (as it does for the key owner in the restricted endpoint), every verified user can read the mnemonic hashes and derivation indices of all other users' keys. Even if `UserKeyDto` strips those fields, the public keys of all organization members are enumerated without restriction, enabling targeted key-mapping attacks.

### Likelihood Explanation
The endpoint is reachable by any authenticated, verified user — no elevated role is required. The front-end already calls it unconditionally via `getAllUserKeys` to populate the contact list: [5](#0-4) 

Any verified user, including a newly elevated or compromised account, can exploit this immediately.

### Recommendation
1. Either add `AdminGuard` to `UserKeysAllController` if the intent is admin-only access, or remove the endpoint and replace it with a properly scoped query.
2. If the endpoint must remain for contact-list use, add a `select` projection identical to `getUserKeysRestricted` that omits `mnemonicHash` and `index` for non-owners, and update the `@ApiOperation` description to accurately reflect that it returns all users' public keys (not a single user's keys).
3. Align the description with the implementation in all cases to prevent future confusion about the access model.

### Proof of Concept
```
# As any verified user (not admin):
GET /user-keys?page=1&size=100
Authorization: Bearer <verified_user_jwt>

# Response: paginated list of ALL UserKey records across ALL users,
# fetched via repo.findAndCount({ take: 100, skip: 0 }) with no WHERE clause.
# Fields returned depend on UserKeyDto but the DB query fetches every column.
```

The mismatch is rooted at:
- **Description** (`user-keys-all.controller.ts:26`): "Get all the user keys for the **provided user id**" — implies per-user scoping. [6](#0-5) 
- **Implementation** (`user-keys.service.ts:145`): `this.repo.findAndCount({ take: limit, skip: offset })` — no user id, no filter. [7](#0-6)

### Citations

**File:** back-end/apps/api/src/user-keys/user-keys-all.controller.ts (L18-21)
```typescript
@ApiTags('User Keys All')
@Controller('user-keys')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class UserKeysAllController {
```

**File:** back-end/apps/api/src/user-keys/user-keys-all.controller.ts (L24-27)
```typescript
  @ApiOperation({
    summary: 'Get all user keys for user',
    description: 'Get all the user keys for the provided user id.',
  })
```

**File:** back-end/apps/api/src/user-keys/user-keys-all.controller.ts (L32-38)
```typescript
  @Get()
  @Serialize(withPaginatedResponse(UserKeyDto))
  getUserKeys(
    @PaginationParams() paginationParams: Pagination,
  ): Promise<PaginatedResourceDto<UserKey>> {
    return this.userKeysService.getUserKeys(paginationParams);
  }
```

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

**File:** front-end/src/renderer/services/organization/userKeys.ts (L65-77)
```typescript
/* Get all users keys from organization */
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
