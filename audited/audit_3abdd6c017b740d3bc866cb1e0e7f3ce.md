### Title
Any Authenticated User Can Enumerate All Transaction Groups via Unguarded "Testing Only" Endpoint

### Summary
The `getTransactionGroups` endpoint in `TransactionGroupsController` is explicitly marked "TESTING ONLY" in the source code but remains deployed with no additional access control beyond basic JWT authentication. Any verified user can call `GET /transaction-groups` and retrieve every transaction group in the organization, regardless of whether they are a participant in those groups. This is a direct analog to the external report's missing privileged-role access control pattern.

### Finding Description

**Root Cause**

`TransactionGroupsController` applies class-level guards that only enforce authentication and account verification: [1](#0-0) 

The `getTransactionGroups` handler is explicitly commented as "TESTING ONLY" but carries no additional guard — no `AdminGuard`, no ownership filter, and no user parameter passed to the service: [2](#0-1) 

Contrast this with the single-group fetch at line 67, which at least passes `user` to the service layer for potential ownership enforcement: [3](#0-2) 

`getTransactionGroups()` passes no user context whatsoever, meaning the service returns the full, unfiltered set of all transaction groups in the database.

**Exploit Flow**

1. Attacker registers or obtains any valid verified-user account (normal product flow).
2. Attacker authenticates and receives a JWT.
3. Attacker sends `GET /transaction-groups` with the JWT bearer token.
4. Server returns every `TransactionGroup` record in the organization — including groups the attacker has no role in.

### Impact Explanation

A regular user gains read access to all transaction groups across the entire organization. Transaction groups contain references to transactions that may include sensitive financial operations, approver structures, signer lists, and execution schedules. This constitutes unauthorized cross-tenant/cross-user data exposure. The `AdminGuard` exists precisely to gate organization-wide data reads: [4](#0-3) 

Its absence here means the intended privilege boundary is completely absent.

### Likelihood Explanation

Likelihood is high. The attacker requires only a valid verified-user account — a normal product registration flow. No privileged credentials, no leaked secrets, no special network access. The endpoint is a standard REST `GET` with no obscure parameters. The "TESTING ONLY" comment confirms the developer was aware this endpoint should not be generally accessible, yet it was never removed or restricted before deployment.

### Recommendation

Apply `AdminGuard` to the `getTransactionGroups` handler so only administrators can enumerate all groups:

```typescript
@Get()
@UseGuards(AdminGuard)   // add this
@Serialize(TransactionGroupDto)
getTransactionGroups(): Promise<TransactionGroup[]> {
  return this.transactionGroupsService.getTransactionGroups();
}
```

Alternatively, if the endpoint is truly only for testing, remove it entirely from the production controller and cover the use case in integration tests via direct service injection.

### Proof of Concept

**Preconditions:** Two accounts exist — `admin@org.com` (admin) and `attacker@org.com` (regular verified user). The admin has created transaction groups that `attacker` is not a participant in.

```bash
# Step 1 – Attacker logs in as a normal verified user
TOKEN=$(curl -s -X POST https://<host>/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@org.com","password":"..."}' \
  | jq -r '.accessToken')

# Step 2 – Attacker calls the unguarded endpoint
curl -s -X GET https://<host>/transaction-groups \
  -H "Authorization: Bearer $TOKEN"
```

**Expected (correct) behavior:** `403 Forbidden` — only admins should be able to list all groups.

**Actual behavior:** `200 OK` with the full array of every `TransactionGroup` in the organization, including groups the attacker has no legitimate access to. [2](#0-1)

### Citations

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L25-29)
```typescript
@ApiTags('Transaction Groups')
@Controller('transaction-groups')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionGroupsController {
  constructor(private readonly transactionGroupsService: TransactionGroupsService) {}
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
