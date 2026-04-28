### Title
Malicious Verified User Can Spam Identical-Looking Transactions to Confuse Approvers Into Approving Malicious Payloads

### Summary
Any verified user in the organization can create unlimited transactions with identical `name` and `description` fields but different (malicious) `transactionBytes`, then assign the same approvers as a legitimate transaction. Approvers see all assigned transactions in their approval queue with no way to distinguish real from fake by human-readable metadata alone, creating a confusion attack that can result in approvers cryptographically signing a malicious Hedera transaction body.

### Finding Description

**Root cause:** `createTransactions` enforces uniqueness only on the Hedera `transactionId` (`payerAccountId@validStartTime`). There is no uniqueness or rate constraint on the human-readable `name` or `description` fields. Any verified user can create arbitrarily many transactions with identical display metadata but different `transactionBytes`. [1](#0-0) 

The only duplicate guard is:

```
transactionId: In(transactionIds),
status: Not(In([CANCELED, REJECTED, ARCHIVED]))
```

Since each new transaction uses a different `validStart` timestamp, the attacker trivially bypasses this check by varying the Hedera transaction's valid-start nanosecond.

**Approver assignment:** `createTransactionApprovers` only requires the caller to be the creator of the *target* transaction. It places no restriction on which user IDs may be designated as approvers — it only checks that the user exists. [2](#0-1) [3](#0-2) 

**User enumeration:** `GET /users` is accessible to every verified user and returns all user IDs in the organization. [4](#0-3) 

**Approver queue:** `getTransactionsToApprove` returns every transaction where the authenticated user appears as an approver with a pending decision, regardless of who created the transaction. [5](#0-4) 

**Approval records a cryptographic signature:** When an approver calls `approveTransaction`, they supply a signature over the transaction body. The service verifies the signature against the stored `transactionBytes` and persists it. Approving the wrong transaction means the approver has cryptographically endorsed the malicious bytes. [6](#0-5) 

**Rate limiting:** The per-user throttler allows 100 requests per minute and 10 per second — sufficient to create dozens of decoy transactions before an approver acts. [7](#0-6) 

**Exploit flow:**

1. Attacker (verified user) calls `GET /users` to collect all user IDs.
2. Attacker observes (or guesses) that a legitimate transaction named "Monthly Payroll Transfer" is pending approval by users A and B.
3. Attacker creates N fake transactions with `name="Monthly Payroll Transfer"`, `description="..."`, but with `transactionBytes` encoding a transfer to the attacker's account. Each fake uses a slightly different `validStart` to satisfy the uniqueness check.
4. Attacker calls `POST /transactions/:fakeId/approvers` for each fake, assigning users A and B.
5. Users A and B now see N+1 identical-looking entries in their approval queue. The UI displays `name`, `description`, `type`, and `createdAt` — not the raw bytes. A careless approver approves the wrong entry.
6. The malicious transaction accumulates the required approvals and, once signers also sign, is submitted to the Hedera network.

### Impact Explanation

An approver who approves the wrong transaction provides a valid cryptographic signature over malicious `transactionBytes`. If the transaction also collects the required signer signatures (which may overlap with approvers in many org configurations), the malicious Hedera transaction is executed on-chain — e.g., an unauthorized HBAR transfer or a file update with attacker-controlled content. This is a direct, irreversible on-chain action.

### Likelihood Explanation

The attacker only needs to be a verified member of the organization — the lowest privilege level above anonymous. No admin rights, no leaked secrets, and no cryptographic breaks are required. User IDs are freely enumerable. The attack is scriptable within the existing rate limits. Organizations with high transaction volume are especially susceptible because approvers routinely process many similar-looking entries.

### Recommendation

1. **Enforce a per-user transaction creation rate limit** significantly lower than the current 100/min for the `POST /transactions` endpoint specifically.
2. **Display the Hedera `transactionId` (`payerAccountId@validStartTime`) and a hash of `transactionBytes` prominently** in the approval UI so approvers can distinguish transactions that share a human-readable name.
3. **Optionally, restrict approver assignment** so that only users who are already signers or observers of a transaction (i.e., have an established relationship to it) can be added as approvers, preventing a stranger from injecting themselves into an unrelated approval flow.
4. **Add a server-side warning or flag** when multiple active transactions share the same `name` + `type` + `mirrorNetwork` combination, alerting the creator and approvers to potential duplicates.

### Proof of Concept

```
# Step 1 – enumerate approver IDs
GET /users  →  [{ id: 5, email: "alice@org.com" }, { id: 6, email: "bob@org.com" }]

# Step 2 – build a malicious AccountCreateTransaction or TransferTransaction
#           with validStart = now+1ms, now+2ms, now+3ms … (bypasses duplicate check)

# Step 3 – create N fake transactions
for i in 1..10:
  POST /transactions
  {
    name: "Monthly Payroll Transfer",
    description: "Q2 payroll run",
    transactionBytes: <malicious_bytes_with_validStart_now+i_ms>,
    creatorKeyId: <attacker_key_id>,
    signature: <attacker_sig>,
    mirrorNetwork: "mainnet"
  }
  → 201 { id: fakeId_i }

# Step 4 – assign real approvers to each fake
for fakeId in [fakeId_1 .. fakeId_10]:
  POST /transactions/:fakeId/approvers
  { approversArray: [{ userId: 5 }, { userId: 6 }] }

# Result: Alice and Bob each see 10+ identical "Monthly Payroll Transfer"
# entries in GET /transactions/to-approve.
# Approving any fake entry records their signature over the malicious bytes.
``` [8](#0-7) [9](#0-8) [4](#0-3)

### Citations

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L352-378)
```typescript
    const [transactions, total] = await this.repo
      .createQueryBuilder()
      .setFindOptions(findOptions)
      .where(
        new Brackets(qb =>
          qb.where(whereForUser).andWhere(
            `
            (
              with recursive "approverList" as
                (
                  select * from "transaction_approver"
                  where "transaction_approver"."transactionId" = "Transaction"."id"
                    union all
                      select "approver".* from "transaction_approver" as "approver"
                      join "approverList" on "approverList"."id" = "approver"."listId"
                )
              select count(*) from "approverList"
              where "approverList"."deletedAt" is null and "approverList"."userId" = :userId and "approverList"."approved" is null
            ) > 0
        `,
            {
              userId: user.id,
            },
          ),
        ),
      )
      .getManyAndCount();
```

**File:** back-end/apps/api/src/transactions/transactions.service.ts (L400-433)
```typescript
  async createTransactions(dtos: CreateTransactionDto[], user: User): Promise<Transaction[]> {
    if (dtos.length === 0) return [];

    await attachKeys(user, this.entityManager);

    const client = await getClientFromNetwork(dtos[0].mirrorNetwork);

    try {
      // Validate all DTOs upfront
      const validatedData = await Promise.all(
        dtos.map(dto => this.validateAndPrepareTransaction(dto, user, client)),
      );

      // Batch check for existing transactions
      const transactionIds = validatedData.map(v => v.transactionId);
      const existing = await this.repo.find({
        where: {
          transactionId: In(transactionIds),
          status: Not(
            In([
              TransactionStatus.CANCELED,
              TransactionStatus.REJECTED,
              TransactionStatus.ARCHIVED,
            ]),
          ),
        },
        select: ['transactionId'],
      });

      if (existing.length > 0) {
        throw new BadRequestException(
          `Transactions already exist: ${existing.map(t => t.transactionId).join(', ')}`,
        );
      }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L234-277)
```typescript
  async createTransactionApprovers(
    user: User,
    transactionId: number,
    dto: CreateTransactionApproversArrayDto,
  ): Promise<TransactionApprover[]> {
    await this.getCreatorsTransaction(transactionId, user);

    const approvers: TransactionApprover[] = [];

    try {
      await this.dataSource.transaction(async transactionalEntityManager => {
        const createApprover = async (dtoApprover: CreateTransactionApproverDto) => {
          /* Validate Approver's DTO */
          this.validateApprover(dtoApprover);

          /* Check if the approver already exists */
          if (await this.isNode(dtoApprover, transactionId, transactionalEntityManager))
            throw new Error(this.APPROVER_ALREADY_EXISTS);

          /* Check if the parent approver exists and has threshold */
          if (typeof dtoApprover.listId === 'number') {
            const parent = await transactionalEntityManager.findOne(TransactionApprover, {
              where: { id: dtoApprover.listId },
            });

            if (!parent) throw new Error(this.PARENT_APPROVER_NOT_FOUND);

            /* Check if the root transaction is the same */
            const root = await this.getRootNodeFromNode(
              dtoApprover.listId,
              transactionalEntityManager,
            );
            if (root?.transactionId !== transactionId)
              throw new Error(this.ROOT_TRANSACTION_NOT_SAME);
          }

          /* Check if the user exists */
          if (typeof dtoApprover.userId === 'number') {
            const userCount = await transactionalEntityManager.count(User, {
              where: { id: dtoApprover.userId },
            });

            if (userCount === 0) throw new Error(this.USER_NOT_FOUND(dtoApprover.userId));
          }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L590-610)
```typescript
    const sdkTransaction = SDKTransaction.fromBytes(transaction.transactionBytes);

    /* Verify the signature matches the transaction */
    if (
      !verifyTransactionBodyWithoutNodeAccountIdSignature(sdkTransaction, dto.signature, publicKey)
    )
      throw new BadRequestException(ErrorCodes.SNMP);

    /* Update the approver with the signature */
    await this.dataSource.transaction(async transactionalEntityManager => {
      await transactionalEntityManager
        .createQueryBuilder()
        .update(TransactionApprover)
        .set({
          userKeyId: dto.userKeyId,
          signature: dto.signature,
          approved: dto.approved,
        })
        .whereInIds(userApprovers.map(a => a.id))
        .execute();
    });
```

**File:** back-end/apps/api/src/users/users.controller.ts (L46-50)
```typescript
  @Get()
  @Serialize(UserWithClientsDto)
  getUsers(@GetUser() requestingUser: User): Promise<User[]> {
    return this.usersService.getUsers(requestingUser);
  }
```

**File:** back-end/apps/api/src/throttlers/user-throttler.module.ts (L13-22)
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
```
