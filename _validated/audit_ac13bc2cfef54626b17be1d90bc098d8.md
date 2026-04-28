All code claims have been verified against the actual repository. Every referenced file, line, and behavior matches exactly.

---

Audit Report

## Title
Missing `AdminGuard` on `GET /user-keys` Allows Any Authenticated User to Enumerate All Users' Cryptographic Key Metadata

## Summary
`UserKeysAllController` exposes a paginated `GET /user-keys` endpoint that returns every `UserKey` row in the database — including `mnemonicHash` and `index` — to any verified, authenticated user. The `AdminGuard` is absent, and the underlying service method performs a completely unfiltered query with no ownership or role scoping.

## Finding Description

**Missing `AdminGuard` on the controller:**

`UserKeysAllController` applies only `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. `AdminGuard` is not present. [1](#0-0) 

**Handler passes no user context to the service:**

The `getUserKeys` handler injects only `@PaginationParams()`. No `@GetUser()` decorator is used, so the caller's identity is never forwarded to the service layer. [2](#0-1) 

**Service performs a completely unfiltered query:**

`getUserKeys` calls `findAndCount` with only `take`/`skip` — no `where` clause, no user filter, no ownership check. [3](#0-2) 

**Response DTO exposes sensitive fields for all users:**

`UserKeyDto` serializes `mnemonicHash` and `index` with `@Expose()`, meaning both fields are included in every response item for every user in the organization. [4](#0-3) 

**Contrast with the correctly scoped sibling endpoint:**

`getUserKeysRestricted` in the same service filters by `userId` and conditionally suppresses `mnemonicHash`/`index` unless the requester is the owner. The `GET /user-keys` endpoint bypasses this entirely. [5](#0-4) 

**`AdminGuard` exists and is used elsewhere:**

`AdminGuard` is a working, deployed guard used in `auth.controller.ts` and `users.controller.ts`, confirming its omission from `UserKeysAllController` is an oversight, not an intentional design choice. [6](#0-5) 

## Impact Explanation

Any verified, non-admin user can paginate through the entire `UserKey` table and retrieve for every user in the organization:
- `publicKey` — the on-chain Hedera public key
- `mnemonicHash` — the hash of the user's 24-word BIP-39 mnemonic recovery phrase
- `index` — the HD derivation index

An attacker with `mnemonicHash` values can attempt offline correlation or brute-force attacks against mnemonic phrases (particularly if the mnemonic space is constrained or the hash function is weak). Combined with `publicKey` and `index`, this constitutes a complete map of the organization's key infrastructure, enabling targeted attacks against individual users' wallets and signing keys. This is a cross-tenant confidentiality breach.

## Likelihood Explanation

The attacker precondition is minimal: a valid, verified account — the lowest privilege level after login. No admin role, no special permission, no leaked secret is required. The exploit is a single HTTP GET request. Any malicious insider, compromised low-privilege account, or attacker who registers a user account can immediately exploit this.

## Recommendation

Apply `AdminGuard` to `UserKeysAllController` so only administrators can access the unfiltered key listing:

```typescript
// back-end/apps/api/src/user-keys/user-keys-all.controller.ts
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard, AdminGuard)
export class UserKeysAllController {
``` [7](#0-6) 

Additionally, consider adding a `select` clause to `getUserKeys` in the service to suppress `mnemonicHash` and `index` even for admin callers unless explicitly needed, following the same pattern as `getUserKeysRestricted`. [8](#0-7) 

## Proof of Concept

```
# Step 1: Authenticate as any verified non-admin user
POST /auth/login
{ "email": "lowpriv@example.com", "password": "..." }
→ { "token": "<jwt>" }

# Step 2: Enumerate all user keys in the organization
GET /user-keys?page=1&limit=100
Authorization: Bearer <jwt>

# Response: full UserKey table including mnemonicHash and index for ALL users
{
  "totalItems": 250,
  "items": [
    { "id": 1, "userId": 2, "publicKey": "...", "mnemonicHash": "...", "index": 0 },
    { "id": 2, "userId": 3, "publicKey": "...", "mnemonicHash": "...", "index": 1 },
    ...
  ]
}

# Step 3: Paginate to retrieve remaining records
GET /user-keys?page=2&limit=100
GET /user-keys?page=3&limit=100
```

The endpoint at `back-end/apps/api/src/user-keys/user-keys-all.controller.ts` line 32–38 is reachable with only a verified JWT, and `getUserKeys` at `back-end/apps/api/src/user-keys/user-keys.service.ts` lines 145–148 returns all rows unconditionally. [9](#0-8) [10](#0-9)

### Citations

**File:** back-end/apps/api/src/user-keys/user-keys-all.controller.ts (L19-21)
```typescript
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

**File:** back-end/apps/api/src/user-keys/dtos/user-key.dto.ts (L3-21)
```typescript
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
