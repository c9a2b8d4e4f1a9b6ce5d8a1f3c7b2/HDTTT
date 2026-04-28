### Title
Transaction Creator Can Arbitrarily Modify Approver Threshold After Approvals Are Collected, Bypassing Multi-Signature Governance

### Summary
The `ApproversService` allows the transaction creator to modify the approver structure — including lowering the threshold, removing approvers, or replacing approvers — at any point during the transaction lifecycle with no check on the current transaction status or whether approvals have already been collected. This is the direct analog of the rage-quit report: a privileged role (creator) can arbitrarily change a governance parameter that other participants rely on as a guarantee, at any time and without restriction.

### Finding Description

**Root cause:** `updateTransactionApprover`, `createTransactionApprovers`, and `removeTransactionApprover` in `approvers.service.ts` enforce only that the caller is the transaction creator. None of them check the current `TransactionStatus` before mutating the approver tree.

`getCreatorsTransaction` — the sole guard used — only verifies creator identity: [1](#0-0) 

`updateTransactionApprover` calls this guard but then proceeds to mutate threshold, listId, or userId with no status gate: [2](#0-1) 

The threshold mutation path: [3](#0-2) 

The userId-replacement path clears the existing approval (signature, userKeyId, approved) of the replaced approver: [4](#0-3) 

`createTransactionApprovers` has the same gap — only a creator check, no status check: [5](#0-4) 

`removeTransactionApprover` has neither a creator check nor a status check: [6](#0-5) 

**Exploit flow:**

1. Creator sets up a transaction with a 3-of-5 approver threshold.
2. Approvers A, B, C, D, E are notified and begin their review.
3. Approver A approves. The approval is stored (`signature`, `approved = true`).
4. Creator immediately calls `updateTransactionApprover` with `{ threshold: 1 }` on the root tree node.
5. The threshold is now 1-of-5. The chain/execution service evaluates the current threshold from the database and sees the requirement is already met with A's single approval.
6. The transaction proceeds to execution without the remaining 4 approvers having any say.

Alternatively, the creator can call `updateTransactionApprover` with `{ userId: creatorCollusionUserId }` to replace an approver who has not yet approved, clearing any pending state and substituting a colluding user.

### Impact Explanation

The multi-signature approval model is the core trust guarantee of the organizational workflow. Approvers agree to participate under the assumption that the threshold they see when they are added will remain in force until execution. A malicious creator can:

- Reduce a 3-of-5 threshold to 1-of-5 after a single approval, executing a transaction that the other 4 approvers would have rejected.
- Replace non-approving approvers with colluding accounts, manufacturing artificial consensus.
- Remove approvers entirely via `removeTransactionApprover` (which has no creator check at all), reducing the pool to make the existing threshold trivially satisfiable.

This constitutes unauthorized state change and integrity failure in the consensus/trust model — a direct match to the RESEARCHER.md high-value impact categories. [7](#0-6) 

### Likelihood Explanation

- **Attacker profile**: Malicious normal user (transaction creator) abusing valid product flows. No admin keys or leaked credentials required.
- **Entry point**: Standard authenticated API endpoints for updating/removing approvers.
- **Precondition**: The attacker must be the creator of the transaction, which is a role any registered user can hold.
- **Detectability**: The modification looks like a normal threshold update; no anomaly detection exists.

### Recommendation

1. **Status gate on all approver mutations**: Before any mutation in `updateTransactionApprover`, `createTransactionApprovers`, and `removeTransactionApprover`, reject the request if the transaction status is not `NEW` (i.e., before any approvals have been collected). Once the status advances to `WAITING_FOR_SIGNATURES` or beyond, the approver structure should be immutable.

2. **Threshold can only increase**: If some flexibility is required, enforce that the threshold can only be raised, never lowered, once any approval has been recorded.

3. **Add creator check to `removeTransactionApprover`**: This function currently has no authorization check at all — any caller who knows an approver ID can delete it.

### Proof of Concept

**Setup:**
- Creator (user ID 1) creates a transaction with a threshold tree: `{ threshold: 3, approvers: [userA, userB, userC, userD, userE] }`.
- Transaction status: `WAITING_FOR_SIGNATURES`.

**Step 1 — Approver A approves:**
```
POST /transactions/{txId}/approvers/approve
{ userKeyId: A_keyId, signature: "...", approved: true }
```
`TransactionApprover` row for userA now has `approved = true`, `signature = "..."`.

**Step 2 — Creator lowers threshold:**
```
PATCH /transactions/{txId}/approvers/{rootNodeId}
Authorization: Bearer <creator_token>
{ "threshold": 1 }
```
`updateTransactionApprover` is called. `getCreatorsTransaction` passes (caller is creator). No status check. `threshold` is updated to `1` in the database.

**Step 3 — Execution service evaluates:**
The chain service reads the current approver tree, sees threshold = 1, sees userA has `approved = true`. Threshold is satisfied. Transaction is executed.

**Expected (correct) behavior:** The `PATCH` in Step 2 should be rejected because the transaction is already in `WAITING_FOR_SIGNATURES` state and approvals have been collected.

**Actual behavior:** The threshold is silently lowered and the transaction executes with a single approval, bypassing the original 3-of-5 governance requirement. [8](#0-7)

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L39-63)
```typescript
@Injectable()
export class ApproversService {
  private readonly CANNOT_CREATE_EMPTY_APPROVER = 'Cannot create empty approver';
  private readonly PARENT_APPROVER_NOT_FOUND = 'Parent approver not found';
  private readonly THRESHOLD_REQUIRED = 'Threshold must be set for the parent approver';
  private readonly CHILDREN_REQUIRED = 'Children must be set when there is a threshold';
  private readonly THRESHOLD_LESS_OR_EQUAL_APPROVERS = (total: number) =>
    `Threshold must be less or equal to the number of approvers (${total}) and not 0`;
  private readonly USER_NOT_FOUND = (id: number) => `User with id: ${id} not found`;
  private readonly APPROVER_ALREADY_EXISTS = 'Approver already exists';
  private readonly ONLY_USER_OR_TREE = 'You can only set a user or a tree of approvers, not both';
  private readonly ROOT_TRANSACTION_NOT_SAME = 'Root transaction is not the same';
  private readonly INVALID_UPDATE_APPROVER =
    'Only one property of the approver can be update user id, list id, or the threshold';
  private readonly APPROVER_NOT_TREE = 'Cannot update threshold, the approver is not a tree';
  private readonly APPROVER_IS_TREE = 'Cannot update user id, the approver is a tree';
  private readonly CANNOT_SET_CHILD_AS_PARENT = 'Cannot set a child as a parent';

  constructor(
    @InjectRepository(TransactionApprover)
    private repo: Repository<TransactionApprover>,
    @InjectDataSource() private dataSource: DataSource,
    private readonly transactionSignatureService: TransactionSignatureService,
    private readonly notificationsPublisher: NatsPublisherService,
  ) {}
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-240)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);

```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L367-395)
```typescript
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L467-488)
```typescript
        } else if (typeof dto.threshold === 'number') {
          /* Check if the approver is a tree */
          if (typeof approver.threshold !== 'number' || typeof approver.userId === 'number')
            throw new Error(this.APPROVER_NOT_TREE);

          /* Check if the approver threshold is less or equal to the number of approvers */
          if (
            approver.approvers &&
            (dto.threshold > approver.approvers.length || dto.threshold === 0)
          )
            throw new Error(this.THRESHOLD_LESS_OR_EQUAL_APPROVERS(approver.approvers.length));

          /* Update the threshold */
          if (approver.threshold !== dto.threshold) {
            await transactionalEntityManager.update(TransactionApprover, approver.id, {
              threshold: dto.threshold,
            });
            approver.threshold = dto.threshold;
            updated = true;

            return approver;
          }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L489-517)
```typescript
        } else if (typeof dto.userId === 'number') {
          /* Check if the approver is a tree */
          if (typeof approver.threshold === 'number') throw new Error(this.APPROVER_IS_TREE);

          /* Check if the user exists */
          const userCount = await transactionalEntityManager.count(User, {
            where: { id: dto.userId },
          });
          if (userCount === 0) throw new Error(this.USER_NOT_FOUND(dto.userId));

          /* Update the user */
          if (approver.userId !== dto.userId) {
            const data: DeepPartial<TransactionApprover> = {
              userId: dto.userId,
              userKeyId: undefined,
              signature: undefined,
              approved: undefined,
            };

            approver.userKeyId = undefined;
            approver.signature = undefined;
            approver.approved = undefined;

            await transactionalEntityManager.update(TransactionApprover, approver.id, data);
            approver.userId = dto.userId;
            updated = true;

            return approver;
          }
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

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L624-644)
```typescript
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
