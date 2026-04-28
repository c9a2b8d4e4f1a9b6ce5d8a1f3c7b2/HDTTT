All claims are verified against the actual codebase. Here is the audit result:

---

Audit Report

## Title
Unbounded Batch Input and Dead Per-User Throttle Module Enable Authenticated Resource Exhaustion via `importSignatures`

## Summary
The `POST /transactions/signatures/import` endpoint accepts an unbounded array of `UploadSignatureMapDto` entries with no enforced size limit. The service layer contains a developer comment explicitly acknowledging the missing limit. Compounding this, the `UserThrottlerModule` — which defines per-user rate limits — is declared but never imported into the application module and never applied to any authenticated endpoint. An authenticated user can submit a single crafted request with thousands of entries, forcing unbounded database queries, cryptographic validation loops, and batch SQL updates, exhausting server resources.

## Finding Description

**Root cause 1 — Unbounded batch input:**

The controller at `back-end/apps/api/src/transactions/transactions.controller.ts` accepts `UploadSignatureMapDto[] | UploadSignatureMapDto` with no array length constraint: [1](#0-0) 

The service at `back-end/apps/api/src/transactions/transactions.service.ts` processes every element: a batch DB lookup (`SELECT … WHERE id IN (…)`), per-item `SDKTransaction.fromBytes` deserialization, per-item `validateSignature` cryptographic check, and a raw SQL `CASE … WHEN` update that grows linearly with input size. The developer explicitly flagged the missing limit at line 575: [2](#0-1) 

The `BATCH_SIZE = 500` constant only batches SQL writes — it does not cap the total input size: [3](#0-2) 

**Root cause 2 — `UserThrottlerModule` defined but never wired:**

A per-user throttler module exists at `back-end/apps/api/src/throttlers/user-throttler.module.ts` with limits of 100 req/min and 10 req/sec per user: [4](#0-3) 

However, it is not exported from the throttlers barrel (`back-end/apps/api/src/throttlers/index.ts`): [5](#0-4) 

It is not imported in `api.module.ts`, and no `UserThrottlerGuard` is registered as an `APP_GUARD` or applied to any controller. The only active global guard is `IpThrottlerGuard`: [6](#0-5) 

The `UserThrottlerGuard` exists at `back-end/apps/api/src/guards/user-throttler.guard.ts` but is referenced only in its own spec file — never in any module or controller: [7](#0-6) 

**Affected endpoint:**

`POST /transactions/signatures/import` — protected by `JwtBlackListAuthGuard`, `JwtAuthGuard`, `VerifiedUserGuard` (any verified org user), but no per-user or per-request payload-size throttle: [8](#0-7) 

## Impact Explanation
A single authenticated user can submit one HTTP POST request containing thousands of `UploadSignatureMapDto` entries. The server will:
1. Execute a `SELECT … WHERE id IN (…)` query with thousands of IDs.
2. Loop over every entry performing `SDKTransaction.fromBytes` (heap allocation) and `validateSignature` (asymmetric crypto).
3. Build and execute raw SQL `CASE id WHEN … THEN … END` statements that grow proportionally with input size, in batches of 500 — meaning 5,000 entries produce 10 separate large SQL statements.

This exhausts CPU, heap memory, and PostgreSQL connection pool slots, causing service degradation or crash for all users.

## Likelihood Explanation
Any user who has completed registration and email verification (`VerifiedUserGuard`) can reach this endpoint. No admin role, no special key, and no privileged credential is required. The attacker needs only a valid JWT obtained through the normal login flow. The attack is a single HTTP POST — no sustained traffic volume is needed, so it evades the IP-based rate limiter entirely. The `IpThrottlerGuard` counts requests per IP, not payload size, so a single large-batch request stays within the per-request IP limit while causing disproportionate server work.

## Recommendation
1. **Enforce a maximum array length** at the controller or DTO level (e.g., using `class-validator`'s `@ArrayMaxSize(N)` on the DTO, or a NestJS pipe that rejects arrays exceeding a defined limit such as 50 or 100 entries).
2. **Wire `UserThrottlerModule` and `UserThrottlerGuard`**: Export `UserThrottlerModule` from `back-end/apps/api/src/throttlers/index.ts`, import it in `api.module.ts`, and register `UserThrottlerGuard` as an `APP_GUARD` (or apply it specifically to authenticated endpoints).
3. **Consider adding a request body size limit** at the HTTP layer (e.g., NestJS/Express `bodyParser` `limit` option) as a defense-in-depth measure.

## Proof of Concept
```http
POST /transactions/signatures/import HTTP/1.1
Host: target.example.com
Authorization: Bearer <valid_jwt_for_any_verified_user>
Content-Type: application/json

[
  { "id": 1, "signatureMap": { ... } },
  { "id": 2, "signatureMap": { ... } },
  ... (repeat 5000 times with valid or invalid IDs)
]
```

The server will:
- Execute `SELECT … WHERE id IN (1, 2, …, 5000)` — one large DB query.
- Loop 5,000 times calling `SDKTransaction.fromBytes` and `validateSignature`.
- Execute 10 batched `CASE id WHEN … END` SQL updates (500 entries each).

No rate limit will fire because only one HTTP request is sent from one IP address.

### Citations

**File:** back-end/apps/api/src/transactions/transactions.controller.ts (L54-107)
```typescript
@ApiTags('Transactions')
@Controller('transactions')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
export class TransactionsController {
  constructor(private transactionsService: TransactionsService) {}

  /* Submit a transaction */
  @ApiOperation({
    summary: 'Create a transaction',
    description: 'Create a transaction for the organization to approve, sign, and execute.',
  })
  @ApiResponse({
    status: 201,
    type: TransactionDto,
  })
  @UseGuards(HasKeyGuard)
  @Post()
  @Serialize(TransactionDto)
  @OnlyOwnerKey<CreateTransactionDto>('creatorKeyId')
  async createTransaction(
    @Body() body: CreateTransactionDto,
    @GetUser() user,
  ): Promise<Transaction> {
    return this.transactionsService.createTransaction(body, user);
  }

  /* Import signatures from another transaction */
  @ApiOperation({
    summary: 'Import signatures',
    description:
      'Import all signatures for the specified transactions. No signature entities will be created.',
  })
  @ApiBody({
    type: UploadSignatureMapDto, // Or create a specific DTO for import if needed
  })
  @ApiResponse({
    status: 201,
    type: [SignatureImportResultDto],
  })
  @Post('/signatures/import')
  @HttpCode(201)
  @Serialize(SignatureImportResultDto)
  async importSignatures(
    @Body() body: UploadSignatureMapDto[] | UploadSignatureMapDto,
    @GetUser() user: User,
  ): Promise<SignatureImportResultDto[]> {
    const transformedSignatureMaps = await transformAndValidateDto(
      UploadSignatureMapDto,
      body
    );

    // Delegate to service to perform the import
    return this.transactionsService.importSignatures(transformedSignatureMaps, user);
  }
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L575-582)
```typescript
    //Added a batch mechanism, probably should limit this on the api side of things
    const BATCH_SIZE = 500;

    const updateArray = Array.from(updates.values());

    if (updateArray.length > 0) {
      for (let i = 0; i < updateArray.length; i += BATCH_SIZE) {
        const batch = updateArray.slice(i, i + BATCH_SIZE);
```

**File:** back-end/apps/api/src/throttlers/user-throttler.module.ts (L13-24)
```typescript
        throttlers: [
          {
            name: 'user-minute',
            ttl: seconds(60),
            limit: 100,
          },
          {
            name: 'user-second',
            ttl: seconds(1),
            limit: 10,
          },
        ],
```

**File:** back-end/apps/api/src/throttlers/index.ts (L1-2)
```typescript
export * from './email-throttler.module';
export * from './ip-throttler.module';
```

**File:** back-end/apps/api/src/api.module.ts (L68-77)
```typescript
    IpThrottlerModule,
    EmailThrottlerModule,
    BlacklistModule.register({ isGlobal: true }),
    SchedulerModule.register({ isGlobal: true }),
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: IpThrottlerGuard,
    },
```

**File:** back-end/apps/api/src/guards/user-throttler.guard.ts (L1-15)
```typescript
/* eslint-disable @typescript-eslint/no-explicit-any */
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

@Injectable()
export class UserThrottlerGuard extends ThrottlerGuard {
  protected getTracker(req: Record<string, any>): Promise<string> {
    const user = req.user;
    if (!user) {
      throw new HttpException('No user connected.', HttpStatus.BAD_REQUEST);
    }
    // console.log('user id', user.id);
    return user.id;
  }
}
```
