### Title
Any Authenticated User Can Retrieve All Transaction Groups Due to Missing Admin Guard on `getTransactionGroups`

### Summary
The `GET /transaction-groups` endpoint in `TransactionGroupsController` is explicitly marked as "TESTING ONLY" but is missing the `AdminGuard`. Because the class-level guards only enforce authentication and email verification — not admin privilege — any authenticated, verified user can call this endpoint and receive a full dump of every transaction group in the organization, bypassing the per-user access control enforced on every other group endpoint.

### Finding Description

**Vulnerability class:** Insufficient Access Controls (Authorization bypass — direct analog to the external report's missing role modifier).

**Root cause:**

`TransactionGroupsController` applies three class-level guards:

```
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
``` [1](#0-0) 

Every other endpoint in the same controller accepts a `@GetUser() user: User` parameter and passes it to the service so the service can scope results to that user's accessible groups. For example, `getTransactionGroup` (singular):

```typescript
getTransactionGroup(@GetUser() user: User, @Param('id', ParseIntPipe) groupId: number, ...)
  return this.transactionGroupsService.getTransactionGroup(user, groupId, full ?? true);
``` [2](#0-1) 

However, the `getTransactionGroups` (plural) endpoint — explicitly commented "TESTING ONLY" — takes **no user parameter** and calls the service with **no user context**:

```typescript
/* TESTING ONLY: Get all transactions groups */
@Get()
@Serialize(TransactionGroupDto)
getTransactionGroups(): Promise<TransactionGroup[]> {
  return this.transactionGroupsService.getTransactionGroups();
}
``` [3](#0-2) 

There is no `@UseGuards(AdminGuard)` on this method. The `AdminGuard` exists in the codebase and is used on other sensitive endpoints (e.g., `PATCH /users/:id`, `DELETE /users/:id`): [4](#0-3) 

The `AdminGuard` simply checks `user.admin`: [5](#0-4) 

Because `getTransactionGroups` has no such guard, any user who can log in and pass email verification can issue `GET /transaction-groups` and receive every transaction group stored in the database.

**Exploit path:**

1. Attacker registers or already has a normal (non-admin) account in the organization.
2. Attacker authenticates → receives a valid JWT.
3. Attacker sends `GET /transaction-groups` with the JWT.
4. The request passes `JwtBlackListAuthGuard`, `JwtAuthGuard`, and `VerifiedUserGuard`.
5. No further check exists; `transactionGroupsService.getTransactionGroups()` returns all groups.
6. Attacker receives the full list of every transaction group, including groups they were never added to as creator, approver, signer, or observer.

### Impact Explanation

Transaction groups aggregate multiple Hedera transactions that the organization is coordinating to approve, sign, and execute. Exposing all groups to any authenticated user leaks:

- The existence and metadata of every pending, in-progress, or historical multi-sig workflow.
- The set of transactions grouped together, which can reveal organizational financial activity, counterparties, and timing.
- Group IDs that can be used as input to other endpoints (e.g., `cancelTransactionGroup`, `removeTransactionGroup`) where the attacker now knows valid IDs to target.

This constitutes unauthorized cross-tenant data exposure and integrity risk (an attacker can now attempt to cancel or delete groups they should have no knowledge of).

### Likelihood Explanation

The precondition is only a valid, verified account — the lowest privilege level in the system. No admin credentials, no leaked secrets, and no special network access are required. The endpoint is a standard REST `GET` with no rate limiting noted. Any malicious insider or compromised low-privilege account can exploit this immediately.

### Recommendation

Add `@UseGuards(AdminGuard)` to the `getTransactionGroups` method, consistent with how other admin-only operations are protected:

```typescript
/* TESTING ONLY: Get all transactions groups */
@Get()
@UseGuards(AdminGuard)   // ← add this
@Serialize(TransactionGroupDto)
getTransactionGroups(): Promise<TransactionGroup[]> {
  return this.transactionGroupsService.getTransactionGroups();
}
```

If this endpoint is truly only needed for testing, it should be removed from the production codebase entirely or gated behind an environment flag in addition to the admin guard.

### Proof of Concept

**Preconditions:** Two accounts exist — `admin@org.com` (admin) and `user@org.com` (regular user). The admin has created transaction groups that `user@org.com` is not a member of.

**Steps:**

1. Authenticate as `user@org.com`:
   ```
   POST /auth/login  { "email": "user@org.com", "password": "..." }
   → { "accessToken": "<JWT>" }
   ```

2. Call the unguarded endpoint:
   ```
   GET /transaction-groups
   Authorization: Bearer <JWT>
   ```

3. **Expected (correct) behavior:** `403 Forbidden` — regular users should not see all groups.

4. **Actual behavior:** `200 OK` with the full list of every `TransactionGroup` in the database, including groups the user was never associated with. [3](#0-2)

### Citations

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L25-28)
```typescript
@ApiTags('Transaction Groups')
@Controller('transaction-groups')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionGroupsController {
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L52-57)
```typescript
  /* TESTING ONLY: Get all transactions groups */
  @Get()
  @Serialize(TransactionGroupDto)
  getTransactionGroups(): Promise<TransactionGroup[]> {
    return this.transactionGroupsService.getTransactionGroups();
  }
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L67-75)
```typescript
  @Get('/:id')
  @Serialize(TransactionGroupDto)
  getTransactionGroup(
    @GetUser() user: User,
    @Param('id', ParseIntPipe) groupId: number,
    @Query('full', new ParseBoolPipe({ optional: true })) full?: boolean,
  ): Promise<TransactionGroup> {
    return this.transactionGroupsService.getTransactionGroup(user, groupId, full ?? true);
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

**File:** back-end/apps/api/src/guards/admin.guard.ts (L4-8)
```typescript
export class AdminGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    const { user } = context.switchToHttp().getRequest();
    return user && user.admin;
  }
```
