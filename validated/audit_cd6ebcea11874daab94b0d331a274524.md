### Title
Any Verified User Can Enumerate All Organization User Keys via Unguarded `/user-keys` Endpoint

### Summary
The `UserKeysAllController` exposes a `GET /user-keys` endpoint that returns all cryptographic public keys for every user in the organization. Unlike the parallel `UserKeysController` which enforces per-user restriction via `getUserKeysRestricted`, this endpoint applies only `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard` — the `AdminGuard` is absent. Any verified (non-admin) organization member can call this endpoint and retrieve the full key inventory of all users.

### Finding Description
The vulnerability is a missing authorization guard on a sensitive data endpoint — the direct analog of `EmergencyWithdraw` lacking `onlyOwner`.

**Root cause:**

`UserKeysAllController` at [1](#0-0) 

The controller-level guard chain is:
```
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
```
`AdminGuard` is never applied — neither at the controller level nor on the individual `GET` handler.

The service call passes **no user parameter**:
```typescript
return this.userKeysService.getUserKeys(paginationParams);
```
This is in direct contrast to the scoped sibling controller `UserKeysController`, which calls `getUserKeysRestricted(user, userId)` and enforces per-user ownership: [2](#0-1) 

The `AdminGuard` is already implemented and used elsewhere in the codebase for privileged operations (user deletion, admin elevation, user update): [3](#0-2) 

Its absence here is an omission, not a design choice, as evidenced by the existence of `getUserKeysRestricted`.

**Exploit path:**
1. Attacker registers or is added as a regular (non-admin) organization member.
2. Attacker authenticates via `POST /auth/login` and obtains a JWT.
3. Attacker sends `GET /user-keys` with the JWT in the `Authorization` header.
4. The server returns a paginated list of **all** `UserKey` records for all users in the organization — no admin privilege required.

### Impact Explanation
A non-admin attacker gains full visibility into the cryptographic key inventory of every user in the organization. This includes:
- All public keys registered by all users (enabling account mapping on the Hedera network)
- Key metadata (mnemonic hash indices, key IDs) that can be used to correlate keys to accounts
- Identification of high-value accounts (e.g., treasury signers) for targeted follow-on attacks

This is a **cross-user data exposure** and **unauthorized privilege escalation** (a regular user obtains data that only admins should see). The `AdminGuard` is the intended control, as proven by its use on `PATCH /users/:id`, `DELETE /users/:id`, and `PATCH /auth/elevate-admin`. [4](#0-3) 

### Likelihood Explanation
Likelihood is **high**:
- The attacker only needs a valid verified-user JWT — no admin credentials, no leaked secrets, no special network access.
- The endpoint is a standard REST `GET` with no additional parameters required.
- Any organization member (including newly onboarded users) satisfies the only enforced guard (`VerifiedUserGuard`).
- The attack is passive (read-only) and leaves no obvious audit trail distinguishing it from legitimate key lookups.

### Recommendation
Add `AdminGuard` to the `UserKeysAllController` at the controller level, consistent with how other admin-only data operations are protected:

```typescript
// back-end/apps/api/src/user-keys/user-keys-all.controller.ts
@Controller('user-keys')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard, AdminGuard)
export class UserKeysAllController { ... }
```

If the endpoint is intended to be accessible to non-admins for a specific use case (e.g., multi-sig key discovery), it must be scoped to return only the requesting user's own keys, mirroring `getUserKeysRestricted`. [1](#0-0) 

### Proof of Concept

```bash
# Step 1: Login as a regular (non-admin) verified user
TOKEN=$(curl -s -X POST http://<server>/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"regularuser@org.com","password":"<password>"}' \
  | jq -r '.accessToken')

# Step 2: Call the unguarded endpoint — no AdminGuard blocks this
curl -s -X GET "http://<server>/user-keys?page=1&limit=50" \
  -H "Authorization: Bearer $TOKEN"

# Expected (vulnerable) response: HTTP 200 with ALL users' keys
# {
#   "data": [
#     { "id": 1, "userId": 1, "publicKey": "302a...", "mnemonicHash": "...", ... },
#     { "id": 2, "userId": 2, "publicKey": "302a...", "mnemonicHash": "...", ... },
#     ...
#   ],
#   "total": N
# }
```

The response will contain `UserKey` records belonging to **all** users, not just the authenticated caller, confirming the missing authorization boundary. [5](#0-4)

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

**File:** back-end/apps/api/src/user-keys/user-keys.controller.ts (L52-57)
```typescript
  getUserKeys(
    @GetUser() user: User,
    @Param('userId', ParseIntPipe) userId: number,
  ): Promise<UserKey[]> {
    return this.userKeysService.getUserKeysRestricted(user, userId);
  }
```

**File:** back-end/apps/api/src/guards/admin.guard.ts (L1-9)
```typescript
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';

@Injectable()
export class AdminGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    const { user } = context.switchToHttp().getRequest();
    return user && user.admin;
  }
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
