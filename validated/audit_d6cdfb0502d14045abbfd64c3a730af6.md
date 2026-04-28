### Title
Any Verified User Can Enumerate All Organization User Keys via Unguarded `GET /user-keys` Endpoint

### Summary
`UserKeysAllController` exposes a `GET /user-keys` endpoint that returns all user keys across the entire organization. The controller applies only `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — but not `AdminGuard`. Any authenticated, verified organization member can paginate through every user's key records, including fields that the ownership-aware sibling endpoint (`getUserKeysRestricted`) deliberately hides from non-owners.

### Finding Description

**Root cause — missing `AdminGuard` on `UserKeysAllController`:**

`UserKeysAllController` at `back-end/apps/api/src/user-keys/user-keys-all.controller.ts` is decorated with only three guards:

```
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
``` [1](#0-0) 

The single route handler calls `getUserKeys(paginationParams)`: [2](#0-1) 

**Service layer — no user filter, no field restriction:**

`UserKeysService.getUserKeys` issues an unrestricted `findAndCount` with no `where` clause and no `select` projection:

```ts
const [items, total] = await this.repo.findAndCount({
  take: limit,
  skip: offset,
});
``` [3](#0-2) 

**Contrast with the ownership-aware path:**

The sibling method `getUserKeysRestricted`, used by `UserKeysController`, explicitly restricts `mnemonicHash` and `index` to the key's owner:

```ts
mnemonicHash: user.id === userId,
index: user.id === userId,
``` [4](#0-3) 

**Exploit path:**

1. Attacker registers as a normal organization user (requires admin to invite, but once registered they are a valid verified user).
2. Attacker calls `GET /user-keys?page=1&size=100` with their JWT.
3. The request passes `JwtBlackListAuthGuard → JwtAuthGuard → VerifiedUserGuard` — no `AdminGuard` check.
4. The service returns all `UserKey` rows from the database with no per-user filtering.
5. Attacker iterates pages to collect every user's key records organization-wide.

**Analog to external report:**

The external report describes `addStrategy()` missing `onlyOwner`, allowing anyone to control privileged state. Here, `getUserKeys()` on `UserKeysAllController` is missing `AdminGuard`, allowing any verified user to access privileged cross-user data that should be admin-only.

### Impact Explanation

- **Cross-user data exposure**: Any verified user can enumerate all public keys registered by all organization members. Public keys are used to identify signers in Hedera multi-sig workflows; leaking the full set reveals the organization's key infrastructure.
- **Sensitive field exposure**: Because `getUserKeys` applies no `select` restriction (unlike `getUserKeysRestricted`), the raw database rows — potentially including `mnemonicHash` and `index` — are returned before the `UserKeyDto` serializer runs. If `UserKeyDto` does not explicitly exclude these fields, HD wallet derivation metadata for every user is exposed to any verified attacker.
- **Privilege escalation of information**: A normal user gains visibility equivalent to an admin over the entire key registry.

### Likelihood Explanation

- Attacker precondition: must be a verified organization member (requires an admin to have invited them). This is a realistic role — any malicious insider or compromised regular account qualifies.
- Attack is a single unauthenticated HTTP GET with a valid JWT. No special tooling required.
- The endpoint is documented in Swagger (`@ApiTags('User Keys All')`), making it discoverable.

### Recommendation

Add `AdminGuard` to `UserKeysAllController`, consistent with how other admin-only operations are protected:

```ts
// back-end/apps/api/src/user-keys/user-keys-all.controller.ts
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard, AdminGuard)
export class UserKeysAllController { ... }
``` [5](#0-4) 

Reference the pattern already used for `updateUser` and `removeUser` in `UsersController`: [6](#0-5) 

Additionally, `getUserKeys` in the service should apply a `select` projection matching `getUserKeysRestricted` to enforce field-level access control as a defense-in-depth measure.

### Proof of Concept

```
# Step 1: Login as a normal (non-admin) verified user
POST /auth/login
{ "email": "user@org.com", "password": "..." }
→ { "accessToken": "<JWT>" }

# Step 2: Call the unguarded endpoint
GET /user-keys?page=1&size=100
Authorization: Bearer <JWT>

# Expected (correct) behavior: 403 Forbidden
# Actual behavior: 200 OK — returns all UserKey records for all users
# in the organization, with no ownership filtering
``` [7](#0-6) [3](#0-2)

### Citations

**File:** back-end/apps/api/src/user-keys/user-keys-all.controller.ts (L1-39)
```typescript
import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

import {
  PaginatedResourceDto,
  Pagination,
  PaginationParams,
  Serialize,
  withPaginatedResponse,
} from '@app/common';
import { UserKey } from '@entities';

import { JwtAuthGuard, JwtBlackListAuthGuard, VerifiedUserGuard } from '../guards';

import { UserKeyDto } from './dtos';
import { UserKeysService } from './user-keys.service';

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
}
```

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

**File:** back-end/apps/api/src/users/users.controller.ts (L103-108)
```typescript
  @UseGuards(AdminGuard)
  @Patch('/:id')
  @Serialize(UserDto)
  updateUser(@Param('id', ParseIntPipe) userId: number, @Body() dto: UpdateUserDto): Promise<User> {
    return this.usersService.updateUserById(userId, dto);
  }
```
