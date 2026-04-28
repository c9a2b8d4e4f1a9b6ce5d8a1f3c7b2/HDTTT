All referenced code is confirmed. Here is the audit result:

---

Audit Report

## Title
Any Authenticated User Can Enumerate All User Keys via Missing Access Control on `GET /user-keys`

## Summary
`UserKeysAllController` exposes `GET /user-keys` without an `AdminGuard`, allowing any verified, authenticated user to retrieve a paginated dump of every user key in the system — including sensitive `mnemonicHash` and `index` fields — with no ownership scoping.

## Finding Description

**`UserKeysAllController`** is protected only by `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`. No `AdminGuard` is applied: [1](#0-0) 

The handler passes no caller identity to the service: [2](#0-1) 

`getUserKeys` in `UserKeysService` issues an unfiltered `findAndCount` — no `where` clause, no `select` restriction: [3](#0-2) 

By contrast, the sibling `getUserKeysRestricted` method correctly scopes by `userId` and conditionally hides `mnemonicHash`/`index` from non-owners: [4](#0-3) 

The `UserKeyDto` serializer exposes `mnemonicHash` and `index` unconditionally: [5](#0-4) 

`AdminGuard` exists and is correctly applied to privileged operations elsewhere (e.g., `PATCH /users/:id`, `DELETE /users/:id`): [6](#0-5) [7](#0-6) 

## Impact Explanation

Any verified user calling `GET /user-keys?page=1&size=100` receives a paginated list of **all** `UserKey` records in the database, including:
- `publicKey` — the Hedera signing key
- `mnemonicHash` — a hash of the mnemonic phrase used for key derivation
- `index` — the HD wallet derivation index
- `userId` — linking each key to its owner

The `mnemonicHash` and `index` fields are the exact fields that `getUserKeysRestricted` deliberately hides from non-owners. Their exposure here breaks the ownership model enforced everywhere else in the API. An attacker can map all registered keys to their owners across the entire organization, enabling targeted transaction-signing or key-import attacks against specific key IDs.

This is not mere user enumeration (which is out of scope per `SECURITY.md`); it is disclosure of sensitive cryptographic metadata belonging to other users. [4](#0-3) 

## Likelihood Explanation

**High.** The only precondition is a valid, non-blacklisted JWT for any verified user account — the minimum privilege level in the system. No admin role, no special token, no leaked credential is required. The endpoint is a standard paginated `GET` with no additional friction. The front-end client already calls this endpoint via `getAllUserKeys` / `getUserKeysPaginated`: [8](#0-7) 

## Recommendation

Apply `AdminGuard` to `UserKeysAllController`, consistent with how other privileged bulk-read and write operations are protected:

```ts
// back-end/apps/api/src/user-keys/user-keys-all.controller.ts
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard, AdminGuard)
export class UserKeysAllController { ... }
```

Alternatively, if non-admin access to a paginated key list is a legitimate use case, replace the `getUserKeys` call with a scoped variant that filters by the authenticated user's ID and strips `mnemonicHash`/`index` for non-owners, matching the behavior of `getUserKeysRestricted`. [1](#0-0) 

## Proof of Concept

```
# 1. Obtain a JWT for any verified (non-admin) user account
POST /auth/login  { "email": "user@org.com", "password": "..." }
# → { "accessToken": "<JWT>" }

# 2. Call the unprotected bulk endpoint
GET /user-keys?page=1&size=100
Authorization: Bearer <JWT>

# 3. Response: full paginated list of every user's keys, including mnemonicHash and index
{
  "totalItems": 42,
  "items": [
    { "id": 1, "userId": 1, "publicKey": "...", "mnemonicHash": "...", "index": 0 },
    { "id": 2, "userId": 2, "publicKey": "...", "mnemonicHash": "...", "index": 1 },
    ...
  ],
  "page": 1,
  "size": 100
}
``` [9](#0-8) [10](#0-9)

### Citations

**File:** back-end/apps/api/src/user-keys/user-keys-all.controller.ts (L19-20)
```typescript
@Controller('user-keys')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
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

**File:** back-end/apps/api/src/user-keys/dtos/user-key.dto.ts (L10-14)
```typescript
  @Expose()
  mnemonicHash?: string;

  @Expose()
  index?: number;
```

**File:** back-end/apps/api/src/users/users.controller.ts (L103-104)
```typescript
  @UseGuards(AdminGuard)
  @Patch('/:id')
```

**File:** back-end/apps/api/src/users/users.controller.ts (L118-119)
```typescript
  @UseGuards(AdminGuard)
  @Delete('/:id')
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
