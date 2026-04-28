All code references check out. The vulnerability is confirmed across every cited file.

---

Audit Report

## Title
Missing Access Control on `GET /user-keys` Exposes All Organization User Keys Including `mnemonicHash` and `index`

## Summary
The `GET /user-keys` endpoint in `UserKeysAllController` is guarded only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. It calls `UserKeysService.getUserKeys()`, which issues a completely unfiltered `findAndCount` with no `where` clause and no `select` restriction, returning every `UserKey` record in the database. The serializer DTO (`UserKeyDto`) explicitly exposes `mnemonicHash` and `index` via `@Expose()`, so both sensitive fields are returned to any authenticated, verified caller.

## Finding Description

**Controller — no `AdminGuard`:**

`back-end/apps/api/src/user-keys/user-keys-all.controller.ts` [1](#0-0) 

The class-level guard list is `JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard` — no `AdminGuard` is present.

**Service — unfiltered query:**

`back-end/apps/api/src/user-keys/user-keys.service.ts` [2](#0-1) 

`findAndCount` has no `where` clause and no `select` restriction. TypeORM returns all columns for all rows.

**DTO — sensitive fields explicitly exposed:**

`back-end/apps/api/src/user-keys/dtos/user-key.dto.ts` [3](#0-2) 

Both `mnemonicHash` and `index` carry `@Expose()`, so the `@Serialize(withPaginatedResponse(UserKeyDto))` interceptor will include them in the HTTP response.

**Contrast with the correctly scoped method:**

`getUserKeysRestricted` (used by `GET /user/:userId/keys`) restricts `mnemonicHash` and `index` to the key owner via a `select` clause: [4](#0-3) 

No equivalent restriction exists in `getUserKeys`.

**Comparison with admin-gated mutations:**

`PATCH /users/:id` and `DELETE /users/:id` correctly apply `AdminGuard`: [5](#0-4) 

`GET /user-keys` has no such guard.

## Impact Explanation
Any verified organization member can issue a single `GET /user-keys` request and receive a paginated dump of every user's key records, including:

- `publicKey` — maps keys to identities across the organization.
- `mnemonicHash` — a hash of the BIP-39 mnemonic used to derive the key. Enables offline dictionary/rainbow-table attacks against weak mnemonics and cross-session key correlation.
- `index` — the HD derivation index; combined with `mnemonicHash`, it narrows the key-derivation search space for an attacker.

This constitutes a full enumeration of the cryptographic identity material of every participant in the organization.

## Likelihood Explanation
The endpoint is reachable by any user who has completed registration and email verification — the lowest privilege tier in the system. No admin role, no knowledge of another user's ID, and no special tooling are required. A single authenticated HTTP `GET /user-keys` request is sufficient.

## Recommendation
Apply one or more of the following mitigations:

1. **Add `AdminGuard`** at the class or handler level of `UserKeysAllController` to restrict the endpoint to administrators only.
2. **Scope the query** in `getUserKeys()` to the requesting user's own records by adding a `where: { userId: requestingUser.id }` clause, consistent with `getUserKeysRestricted`.
3. **Restrict sensitive fields** in `getUserKeys()` by adding a `select` clause that excludes `mnemonicHash` and `index`, or remove those fields from `UserKeyDto` for this endpoint.

## Proof of Concept
```
# 1. Authenticate as any verified user and obtain a JWT token.
POST /auth/login  { "email": "user@org.com", "password": "..." }
# → { "accessToken": "<JWT>" }

# 2. Call the unprotected endpoint.
GET /user-keys?page=1&limit=50
Authorization: Bearer <JWT>

# 3. Response includes mnemonicHash and index for ALL users:
{
  "totalItems": N,
  "items": [
    {
      "id": 1,
      "userId": 2,
      "publicKey": "302a...",
      "mnemonicHash": "e3b0c44298fc...",
      "index": 0
    },
    ...
  ]
}
```

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

**File:** back-end/apps/api/src/users/users.controller.ts (L103-123)
```typescript
  @UseGuards(AdminGuard)
  @Patch('/:id')
  @Serialize(UserDto)
  updateUser(@Param('id', ParseIntPipe) userId: number, @Body() dto: UpdateUserDto): Promise<User> {
    return this.usersService.updateUserById(userId, dto);
  }

  @ApiOperation({
    summary: 'Remove a user',
    description: 'Remove a user from the organization for the given id.',
  })
  @ApiResponse({
    status: 200,
    type: Boolean,
  })
  @UseGuards(AdminGuard)
  @Delete('/:id')
  removeUser(@GetUser() user: User, @Param('id', ParseIntPipe) id: number): Promise<boolean> {
    if (user.id === id) throw new BadRequestException(ErrorCodes.CRYFO);
    return this.usersService.removeUser(id);
  }
```
