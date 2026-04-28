All code references check out. The vulnerability is real and confirmed. Here is the audit report:

---

Audit Report

## Title
Testing-Only `GET /transaction-groups` Endpoint Left in Production Exposes All Organization Transaction Groups to Any Authenticated User

## Summary
A `/* TESTING ONLY */` endpoint, `GET /transaction-groups`, was left in the production controller `transaction-groups.controller.ts`. It delegates to a service method that issues an unconditional database query returning every `TransactionGroup` row, with no user-scoping or ownership check. Any authenticated, verified user can call it.

## Finding Description

**Vulnerable endpoint** — controller lines 52–57:

```typescript
/* TESTING ONLY: Get all transactions groups */
@Get()
@Serialize(TransactionGroupDto)
getTransactionGroups(): Promise<TransactionGroup[]> {
  return this.transactionGroupsService.getTransactionGroups();
}
``` [1](#0-0) 

**Service implementation** — no `where` clause, no user parameter:

```typescript
getTransactionGroups(): Promise<TransactionGroup[]> {
  return this.dataSource.manager.find(TransactionGroup);
}
``` [2](#0-1) 

`dataSource.manager.find(TransactionGroup)` with no options is a `SELECT * FROM transaction_group` — every row is returned.

**Contrast with the adjacent production endpoint** (lines 67–75), which correctly passes `user` and enforces per-user access via `getTransactionGroupItemsQuery`: [3](#0-2) 

**Guards applied at class level** only require a valid, non-blacklisted JWT from a verified account — no ownership or role restriction: [4](#0-3) 

**Data exposed via `TransactionGroupDto`**: `id`, `description`, `atomic`, `sequential`, `createdAt`, `groupValidTime`, and `groupItems` (each item includes `transactionId`, `groupId`, `seq`, and nested `TransactionDto`): [5](#0-4) 

## Impact Explanation
Every `TransactionGroup` record in the organization is disclosed to any authenticated user. The response includes group descriptions, timestamps, sequencing/atomicity configuration, and linked transaction metadata. This information is explicitly gated per-user on every other group-related endpoint. An attacker learns the full set of pending and historical multi-signature workflows, their structure, and their statuses — constituting unauthorized cross-user data exposure.

## Likelihood Explanation
The only precondition is a valid, verified account — the lowest privilege level in the system. No admin role, no special key, no internal network access is required. The endpoint is a standard HTTP GET with no additional guard or rate limit beyond the class-level JWT check. Any registered user can trigger it immediately after login.

## Recommendation
Remove the `getTransactionGroups` handler from `transaction-groups.controller.ts` and the corresponding `getTransactionGroups()` method from `transaction-groups.service.ts` entirely. If a listing endpoint is genuinely needed for production use, it must accept a `@GetUser() user: User` parameter and filter results to only groups the requesting user is authorized to view, consistent with the access control pattern used by `getTransactionGroup`.

## Proof of Concept
```
# 1. Register and verify a normal user account (standard sign-up flow)
POST /auth/signup   { "email": "attacker@example.com", "password": "..." }

# 2. Obtain a JWT
POST /auth/login    { "email": "attacker@example.com", "password": "..." }
# → { "accessToken": "<JWT>" }

# 3. Call the unguarded listing endpoint
GET /transaction-groups
Authorization: Bearer <JWT>

# Response: array of ALL TransactionGroup records in the organization,
# including groups created by other users, with their descriptions,
# timestamps, and linked transaction metadata.
```

### Citations

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.controller.ts (L27-27)
```typescript
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
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

**File:** back-end/apps/api/src/transactions/groups/transaction-groups.service.ts (L36-38)
```typescript
  getTransactionGroups(): Promise<TransactionGroup[]> {
    return this.dataSource.manager.find(TransactionGroup);
  }
```

**File:** back-end/apps/api/src/transactions/dto/transaction-group.dto.ts (L4-26)
```typescript
export class TransactionGroupDto {
  @Expose()
  id: number;

  @Expose()
  description: string;

  @Expose()
  atomic: boolean;

  @Expose()
  sequential: boolean;

  @Expose()
  createdAt: Date;

  @Expose()
  groupValidTime: Date;

  @Expose()
  @Type(() => TransactionGroupItemDto)
  groupItems: TransactionGroupItemDto[];
}
```
