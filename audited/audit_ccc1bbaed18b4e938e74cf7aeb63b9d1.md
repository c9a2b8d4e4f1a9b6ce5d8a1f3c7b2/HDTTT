### Title
Any Authenticated User Can Remove Transaction Approvers Without Creator Authorization Check

### Summary

The `removeTransactionApprover` function in `approvers.service.ts` removes a `TransactionApprover` record without verifying that the calling user is the creator of the associated transaction. Every other approver-modification operation (`createTransactionApprovers`, `updateTransactionApprover`) explicitly calls `getCreatorsTransaction(transactionId, user)` to enforce creator-only access, but `removeTransactionApprover` accepts only an approver `id` with no `user` parameter and performs no ownership check. Any authenticated, verified user can therefore delete any approver from any transaction they did not create.

### Finding Description

**Vulnerability class**: Authorization bypass — caller identity not verified against resource owner.

**Root cause**

`createTransactionApprovers` and `updateTransactionApprover` both call `getCreatorsTransaction` before mutating state: [1](#0-0) [2](#0-1) 

`getCreatorsTransaction` enforces that `transaction.creatorKey?.userId === user.id`: [3](#0-2) 

`removeTransactionApprover`, by contrast, accepts only an approver `id`, passes no `user`, and performs no creator check: [4](#0-3) 

The controller applies only class-level JWT/verified-user guards, which confirm authentication but not transaction ownership: [5](#0-4) 

**Exploit path**

1. Attacker (any authenticated, verified user) learns or enumerates a `TransactionApprover.id` belonging to a transaction they did not create.
2. Attacker sends `DELETE /transactions/<any_id>/approvers/<approver_id>` with their own valid JWT.
3. `removeTransactionApprover(id)` is called; it finds the approver, calls `removeNode`, and soft-deletes it — no creator check is performed.
4. The approver is removed from the transaction's approval tree, potentially reducing the required threshold or eliminating a required approver entirely.

### Impact Explanation

An attacker can silently remove required approvers from any organization transaction. This can:
- Reduce or eliminate the approval threshold for a transaction, allowing it to proceed to execution without the intended multi-party authorization.
- Corrupt the approval tree of any in-flight transaction, undermining the integrity of the multi-signature workflow that is the core security model of the system.
- Cause permanent state corruption: once an approver is soft-deleted and the transaction status is updated, the approval record is gone.

This is a direct unauthorized state change affecting the trust model of the protocol.

### Likelihood Explanation

Any authenticated user with a valid JWT can exploit this. No privileged access is required. Approver IDs are sequential integers (`PrimaryGeneratedColumn`) and are returned in API responses to participants of a transaction, making enumeration trivial. The attacker does not need to know the transaction ID in advance — the approver record itself contains `transactionId`. [6](#0-5) 

### Recommendation

Add a `user: User` parameter to `removeTransactionApprover` and call `getCreatorsTransaction` before removing the node, mirroring the pattern used in `createTransactionApprovers` and `updateTransactionApprover`:

```typescript
async removeTransactionApprover(id: number, user: User): Promise<void> {
  const approver = await this.getTransactionApproverById(id);
  if (!approver) throw new BadRequestException(ErrorCodes.ANF);

  // Resolve root transactionId (approver may be a child node)
  const root = await this.getRootNodeFromNode(approver.id);
  await this.getCreatorsTransaction(root.transactionId, user); // throws if not creator

  const result = await this.removeNode(approver.id);
  emitTransactionStatusUpdate(...);
  return result;
}
```

Pass `@GetUser() user: User` from the controller's DELETE handler into the service call.

### Proof of Concept

**Preconditions**: Two accounts — `creator` (owns transaction T) and `attacker` (any other verified user). Transaction T has approver record with `id = 5`.

```
# Step 1 – attacker logs in and obtains JWT
POST /auth/login  { email: "attacker@org.com", password: "..." }
→ { accessToken: "ATTACKER_JWT" }

# Step 2 – attacker deletes approver id=5 from transaction T
DELETE /transactions/T/approvers/5
Authorization: Bearer ATTACKER_JWT

# Expected (broken) response: 200 OK
# removeTransactionApprover(5) executes with no creator check
# Approver record soft-deleted, approval tree corrupted
```

The service call chain is:

`ApproversController.removeTransactionApprover(id=5)` → `ApproversService.removeTransactionApprover(id=5)` → `removeNode(5)` — no `user` parameter, no `getCreatorsTransaction` call. [4](#0-3)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-239)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L366-394)
```typescript
  /* Updates an approver of a transaction */
  async updateTransactionApprover(
    id: number,
    dto: UpdateTransactionApproverDto,
    transactionId: number,
    user: User,
  ): Promise<TransactionApprover> {
    try {
      let updated = false;

      const approver = await this.dataSource.transaction(async transactionalEntityManager => {
        /* Check if the dto updates only one thing */
        if (Object.keys(dto).length > 1 || Object.keys(dto).length === 0)
          throw new Error(this.INVALID_UPDATE_APPROVER);

        /* Verifies that the approver exists */
        const approver = await this.getTransactionApproverById(id, transactionalEntityManager);
        if (!approver) throw new BadRequestException(ErrorCodes.ANF);

        /* Gets the root approver */
        const rootNode = await this.getRootNodeFromNode(approver.id, transactionalEntityManager);
        if (!rootNode) throw new BadRequestException(ErrorCodes.RANF);

        /* Verifies that the root transaction is the same as the param */
        if (rootNode.transactionId !== transactionId)
          throw new UnauthorizedException(this.ROOT_TRANSACTION_NOT_SAME);

        /* Verifies that the user is the creator of the transaction */
        await this.getCreatorsTransaction(rootNode.transactionId, user, transactionalEntityManager);
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L533-544)
```typescript
  /* Removes the transaction approver by id */
  async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);

    if (!approver) throw new BadRequestException(ErrorCodes.ANF);

    const result = await this.removeNode(approver.id);

    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);

    return result;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L623-644)
```typescript
  /* Get the transaction by id and verifies that the user is the creator */
  async getCreatorsTransaction(
    transactionId: number,
    user: User,
    entityManager?: EntityManager,
  ): Promise<Transaction> {
    const find: FindOneOptions<Transaction> = {
      where: { id: transactionId },
      relations: ['creatorKey', 'creatorKey.user'],
    };

    const transaction = await (entityManager
      ? entityManager.findOne(Transaction, find)
      : this.dataSource.manager.findOne(Transaction, find));

    if (!transaction) throw new BadRequestException(ErrorCodes.TNF);

    if (transaction.creatorKey?.userId !== user.id)
      throw new UnauthorizedException('Only the creator of the transaction is able to modify it');

    return transaction;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L31-36)
```typescript
@ApiTags('Transaction Approvers')
@Controller('transactions/:transactionId?/approvers')
@UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, VerifiedUserGuard)
@Serialize(TransactionApproverDto)
export class ApproversController {
  constructor(private approversService: ApproversService) {}
```

**File:** back-end/libs/common/src/database/entities/transaction-approver.entity.ts (L20-32)
```typescript
export class TransactionApprover {
  @PrimaryGeneratedColumn()
  id: number;

  /* If the approver has a listId, then transactionId should be null */
  @ManyToOne(() => Transaction, transaction => transaction.approvers, {
    nullable: true,
  })
  @JoinColumn({ name: 'transactionId' })
  transaction?: Transaction;

  @Column({ nullable: true })
  transactionId?: number;
```
