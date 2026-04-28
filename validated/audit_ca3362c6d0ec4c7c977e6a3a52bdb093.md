### Title
Missing Access Control on `GET /user-keys` Endpoint Exposes All Organization User Keys

### Summary

The `GET /user-keys` endpoint in `UserKeysAllController` is accessible to any authenticated, verified user. It invokes `UserKeysService.getUserKeys()`, which performs an unrestricted database query returning **all** `UserKey` records for **all** users in the organization — including sensitive fields such as `mnemonicHash` and `index` — with no ownership check, no user-scoping, and no `AdminGuard`.

### Finding Description

`UserKeysAllController` at `back-end/apps/api/src/user-keys/user-keys-all.controller.ts` applies only `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` at the class level. No `AdminGuard` is present. [1](#0-0) 

The handler calls `userKeysService.getUserKeys()`: [2](#0-1) 

That service method issues a completely unfiltered `findAndCount` with no `where` clause and no `select` field restriction: [3](#0-2) 

Contrast this with `getUserKeysRestricted`, the method used by the user-scoped `GET /user/:userId/keys` endpoint, which explicitly restricts `mnemonicHash` and `index` to the key owner: [4](#0-3) 

The `getUserKeys` path applies no equivalent field-level restriction. Because TypeORM returns all columns when no `select` is specified, the raw entity — including `mnemonicHash` and `index` — is passed to the serializer. Any field that `UserKeyDto` does not explicitly exclude will be returned to the caller.

For comparison, admin-only mutations on users (`PATCH /users/:id`, `DELETE /users/:id`) correctly apply `AdminGuard`: [5](#0-4) 

No such guard exists on `GET /user-keys`.

### Impact Explanation

Any authenticated organization member can call `GET /user-keys` and receive the full list of every user's key records, including:

- **`publicKey`** — enables mapping keys to identities across the organization.
- **`mnemonicHash`** — a hash of the BIP-39 mnemonic used to derive the key. Exposure enables offline dictionary/rainbow-table attacks against weak mnemonics and correlation of key usage across sessions.
- **`index`** — the HD derivation index, which combined with `mnemonicHash` narrows the key-derivation search space.

In a multi-user organization, this constitutes a full enumeration of the cryptographic identity material of every participant.

### Likelihood Explanation

The endpoint is reachable by any user who has completed registration and email verification — the lowest privilege tier in the system. No special role, no admin status, and no knowledge of another user's ID is required. A single authenticated HTTP `GET` request to `/user-keys` is sufficient.

### Recommendation

Apply `AdminGuard` to the `GET /user-keys` endpoint, consistent with how other organization-wide administrative operations are protected:

```typescript
@UseGuards(AdminGuard)
@Get()
@Serialize(withPaginatedResponse(UserKeyDto))
getUserKeys(...) { ... }
```

Alternatively, if this endpoint is intended for non-admin use, the service method must be rewritten to scope results to the requesting user and apply the same field-level restrictions as `getUserKeysRestricted`.

### Proof of Concept

1. Register and verify two accounts: `alice@org.com` (attacker) and `bob@org.com` (victim).
2. Bob uploads a key via `POST /user/:bobId/keys`.
3. Alice authenticates and obtains a JWT.
4. Alice sends:
   ```
   GET /user-keys
   Authorization: Bearer <alice_jwt>
   ```
5. The response includes Bob's `UserKey` record with `publicKey`, `mnemonicHash`, and `index` — fields that `GET /user/:bobId/keys` would hide from Alice when called with Alice's identity.

### Citations

**File:** back-end/apps/api/src/user-keys/user-keys-all.controller.ts (L19-38)
```typescript
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

**File:** back-end/apps/api/src/users/users.controller.ts (L103-108)
```typescript
  @UseGuards(AdminGuard)
  @Patch('/:id')
  @Serialize(UserDto)
  updateUser(@Param('id', ParseIntPipe) userId: number, @Body() dto: UpdateUserDto): Promise<User> {
    return this.usersService.updateUserById(userId, dto);
  }
```
