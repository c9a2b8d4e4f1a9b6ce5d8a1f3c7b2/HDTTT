### Title
Missing User-Based Authorization on `getTransactionGroups` Endpoint Exposes All Organization Transaction Groups

### Summary
The `GET /transaction-groups` endpoint in `TransactionGroupsController` is explicitly marked "TESTING ONLY" in source code but remains deployed with no user-scoping or admin restriction. Any authenticated user can enumerate every transaction group in the organization, regardless of whether they are a creator, observer, approver, or signer of those groups.

### Finding Description
The `getTransactionGroups()` handler in `transaction-groups.controller.ts` is decorated only with the controller-level guards (`JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard`), which verify that the caller is a valid authenticated user — but impose no ownership or role restriction. [1](#0-0) 

The handler accepts no `@GetUser()` parameter and passes no user context to the service layer:

```typescript
/* TESTING ONLY: Get all transactions groups */
@Get()
@Serialize(TransactionGroupDto)
getTransactionGroups(): Promise<TransactionGroup[]> {
  return this.transactionGroupsService.getTransactionGroups();
}
```

Every other sensitive endpoint in the same controller correctly accepts `@GetUser() user: User` and passes it to the service for ownership verification: [2](#0-1) [3](#0-2) 

The controller-level guard stack requires authentication but provides no authorization: [4](#0-3) 

The `AdminGuard` exists and is used elsewhere (e.g., `PATCH /users/:id`, `DELETE /users/:id`, `POST /auth/signup`) but is not applied here: [5](#0-4) 

### Impact Explanation
Any authenticated organization member can call `GET /transaction-groups` and receive the full list of every transaction group ever created in the organization. Transaction groups contain references to grouped transactions, their statuses, and associated metadata. This allows a low-privileged user to:

- Enumerate all organizational transaction groups they have no legitimate access to.
- Discover transaction group IDs, which can then be used to probe individual group details via `GET /transaction-groups/:id`.
- Gain intelligence about organizational financial activity (transaction volumes, groupings, timing) without being a creator, observer, approver, or signer of those groups.

### Likelihood Explanation
The route is a standard REST `GET` with no obscure path. Any authenticated user who explores the API (e.g., via the Swagger docs exposed by the NestJS setup) will find it. The developer comment `/* TESTING ONLY */` confirms the intent was never to expose this to all users, making accidental production deployment the realistic scenario.

### Recommendation
Either:
1. **Remove the endpoint** if it is genuinely only for testing and has no production use case.
2. **Add `AdminGuard`** if admin-level visibility of all groups is required:

```typescript
@UseGuards(AdminGuard)
@Get()
@Serialize(TransactionGroupDto)
getTransactionGroups(): Promise<TransactionGroup[]> {
  return this.transactionGroupsService.getTransactionGroups();
}
```

3. **Scope by user** if regular users should see their own groups, consistent with how `getTransactionGroup` and `createTransactionGroup` work.

### Proof of Concept

1. Register or obtain credentials for any non-admin organization user.
2. Authenticate via `POST /auth/login` to obtain a JWT.
3. Issue the request:

```
GET /transaction-groups
Authorization: Bearer <jwt>
```

4. The response contains every `TransactionGroup` record in the database, including groups created by other users, with no filtering applied. [1](#0-0)

### Citations

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L25-29)
```typescript
@ApiTags('Transaction Groups')
@Controller('transaction-groups')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionGroupsController {
  constructor(private readonly transactionGroupsService: TransactionGroupsService) {}
```

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L44-50)
```typescript
  @Serialize(TransactionGroupDto)
  createTransactionGroup(
    @GetUser() user: User,
    @Body() dto: CreateTransactionGroupDto,
  ): Promise<TransactionGroup> {
    return this.transactionGroupsService.createTransactionGroup(user, dto);
  }
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

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L68-75)
```typescript
  @Serialize(TransactionGroupDto)
  getTransactionGroup(
    @GetUser() user: User,
    @Param('id', ParseIntPipe) groupId: number,
    @Query('full', new ParseBoolPipe({ optional: true })) full?: boolean,
  ): Promise<TransactionGroup> {
    return this.transactionGroupsService.getTransactionGroup(user, groupId, full ?? true);
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
