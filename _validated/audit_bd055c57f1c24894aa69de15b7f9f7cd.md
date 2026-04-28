I was unable to read `SECURITY.md` in the final iteration, but all code claims are fully verified. The vulnerability is real and well-supported.

---

Audit Report

## Title
Any Verified User Can Enumerate All Organization User Keys via Unguarded `GET /user-keys` Endpoint

## Summary
`UserKeysAllController` exposes `GET /user-keys` protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. The missing `AdminGuard` allows any authenticated, verified organization member to paginate all `UserKey` rows organization-wide, including sensitive `mnemonicHash` and `index` fields that the ownership-aware sibling endpoint deliberately hides from non-owners.

## Finding Description

**Missing `AdminGuard` on `UserKeysAllController`:**

The controller is decorated with only three guards, with no admin restriction: [1](#0-0) 

The single route handler delegates directly to `getUserKeys(paginationParams)` with no user context passed: [2](#0-1) 

**Service layer — no user filter, no field restriction:**

`UserKeysService.getUserKeys` issues a `findAndCount` with no `where` clause and no `select` projection, returning every row in the `user_key` table: [3](#0-2) 

**Contrast with the ownership-aware path:**

The sibling method `getUserKeysRestricted`, used by `UserKeysController`, explicitly restricts `mnemonicHash` and `index` to the key's owner: [4](#0-3) 

**`UserKeyDto` exposes sensitive fields:**

`UserKeyDto` marks both `mnemonicHash` and `index` with `@Expose()`, meaning the serializer will include them in every response from the unguarded endpoint: [5](#0-4) 

These fields are real database columns on the `UserKey` entity: [6](#0-5) 

## Impact Explanation

- **Cross-user data exposure**: Any verified user can paginate all `UserKey` rows for every organization member. Public keys identify signers in Hedera multi-sig workflows; leaking the full set reveals the organization's entire key infrastructure.
- **Sensitive field exposure**: Because `getUserKeys` applies no `select` restriction and `UserKeyDto` exposes `mnemonicHash` and `index` via `@Expose()`, HD wallet derivation metadata (mnemonic hash and key derivation index) for every user is returned to any verified requester — data that `getUserKeysRestricted` explicitly withholds from non-owners.
- **Privilege escalation of information**: A normal verified user gains visibility equivalent to an admin over the entire key registry.

## Likelihood Explanation

- **Precondition**: Attacker must be a verified organization member (requires an admin invite). This is a realistic insider-threat or compromised-account scenario.
- **Attack complexity**: A single HTTP GET with a valid JWT. No special tooling required.
- **Discoverability**: The endpoint is documented in Swagger via `@ApiTags('User Keys All')`, making it trivially discoverable. [7](#0-6) 

## Recommendation

1. **Add `AdminGuard`** to `UserKeysAllController`:
   ```ts
   @UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard, AdminGuard)
   ```
   `AdminGuard` checks `user.admin` on the request object and is already implemented at `back-end/apps/api/src/guards/admin.guard.ts`. [8](#0-7) 

2. **Add a `select` projection** to `getUserKeys` in `UserKeysService` to exclude `mnemonicHash` and `index` (or explicitly include only the fields appropriate for admin-level listing), consistent with the principle of least privilege.

3. **Audit `UserKeyDto`**: Consider whether `mnemonicHash` and `index` should ever be returned in a bulk listing response, even for admins.

## Proof of Concept

```
# Step 1: Authenticate as any verified organization user
POST /auth/login
→ { "accessToken": "<jwt>" }

# Step 2: Enumerate all user keys organization-wide
GET /user-keys?page=1&size=100
Authorization: Bearer <jwt>

# Response: all UserKey rows including mnemonicHash and index for every user
{
  "totalItems": N,
  "items": [
    { "id": 1, "userId": 2, "publicKey": "...", "mnemonicHash": "...", "index": 0 },
    { "id": 2, "userId": 3, "publicKey": "...", "mnemonicHash": "...", "index": 1 },
    ...
  ]
}

# Step 3: Iterate pages to collect the full key registry
GET /user-keys?page=2&size=100
...
```

The request passes all three guards (`JwtBlackListAuthGuard → JwtAuthGuard → VerifiedUserGuard`) with no `AdminGuard` check, and the service returns unfiltered rows with all fields serialized by `UserKeyDto`.

### Citations

**File:** back-end/apps/api/src/user-keys/user-keys-all.controller.ts (L18-21)
```typescript
@ApiTags('User Keys All')
@Controller('user-keys')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class UserKeysAllController {
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

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L71-80)
```typescript
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
```

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L145-148)
```typescript
    const [items, total] = await this.repo.findAndCount({
      take: limit,
      skip: offset,
    });
```

**File:** back-end/apps/api/src/user-keys/dtos/user-key.dto.ts (L10-14)
```typescript
  @Expose()
  mnemonicHash?: string;

  @Expose()
  index?: number;
```

**File:** back-end/libs/common/src/database/entities/user-key.entity.ts (L28-32)
```typescript
  @Column({ nullable: true })
  mnemonicHash: string;

  @Column({ nullable: true })
  index: number;
```

**File:** back-end/apps/api/src/guards/admin.guard.ts (L1-8)
```typescript
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';

@Injectable()
export class AdminGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    const { user } = context.switchToHttp().getRequest();
    return user && user.admin;
  }
```
