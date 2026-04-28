### Title
Missing Notification Emission After User Key State Changes in `UserKeysService`

---

### Summary

The `UserKeysService` performs sensitive cryptographic key state changes — uploading, removing, and updating user keys — without emitting any notifications via `NatsPublisherService`. Every other state-mutating service in the API layer consistently emits notifications after sensitive changes, but `UserKeysService` has no `NatsPublisherService` injection at all. In a multi-signature workflow, key removal directly affects which transactions can be signed and by whom, making this a meaningful observability gap.

---

### Finding Description

The grep across all API-layer services confirms that `NatsPublisherService` / notification emission is present in every state-mutating service **except** `UserKeysService` and `UsersService`:

- `transactions.service.ts` — emits on create, cancel, archive, remove, execute, import signatures
- `approvers.service.ts` — emits on create, update, remove, approve
- `signers.service.ts` — emits on signature upload
- `observers.service.ts` — emits on create, update, remove
- `transaction-groups.service.ts` — emits on group changes

`UserKeysService`, by contrast, has **no** `NatsPublisherService` injected and emits nothing after any of its mutations:

**`uploadKey`** — adds a new cryptographic key for a user, no notification: [1](#0-0) 

**`removeUserKey`** — soft-removes a user's key, no notification: [2](#0-1) 

**`updateMnemonicHash`** — updates the mnemonic hash/index for a key, no notification: [3](#0-2) 

The same gap exists in `UsersService.removeUser`, which soft-deletes the user **and all their keys** in one operation with no notification: [4](#0-3) 

The contrast with `ObserversService` is illustrative — even a low-sensitivity observer removal emits `emitTransactionUpdate`: [5](#0-4) 

There is also a commented-out notification call inside `ApproversService.removeNode`, showing that the developers were aware of the pattern but left it incomplete: [6](#0-5) 

---

### Impact Explanation

User keys are the cryptographic signing material for all multi-signature transactions. When `removeUserKey` or `removeUser` is called:

1. Any pending transaction in `WAITING_FOR_SIGNATURES` that lists the removed key as a required signer is now unresolvable — but no notification is emitted to inform other participants or update the transaction's status.
2. Connected clients relying on the real-time NATS notification stream will not learn about the key removal until they poll manually, leaving the UI in a stale state.
3. Administrators and co-signers have no audit trail through the notification system for key lifecycle events, reducing operational transparency in a tool explicitly designed for high-assurance multi-party signing.

---

### Likelihood Explanation

Any authenticated user can call `removeUserKey` on their own keys at any time. An admin can call `removeUser`, which cascades to all keys. Both paths are reachable through normal API usage with no special preconditions. Pending transactions that depend on the removed key will silently stall.

---

### Recommendation

Inject `NatsPublisherService` into `UserKeysService` and emit an appropriate notification after each state-mutating operation (`uploadKey`, `removeUserKey`, `updateMnemonicHash`). For `removeUser` in `UsersService`, emit a notification after the cascade soft-delete of keys. If a dedicated key-lifecycle notification type does not yet exist, define one analogous to `emitTransactionUpdate` so that downstream consumers (WebSocket clients, the notifications service) can react accordingly.

---

### Proof of Concept

1. User A and User B are co-signers on a transaction in `WAITING_FOR_SIGNATURES`.
2. User A calls `DELETE /user-keys/:id` to remove their signing key.
3. `UserKeysService.removeUserKey` soft-removes the key and returns `true`.
4. No NATS message is published; User B's client receives no real-time update.
5. The transaction remains in `WAITING_FOR_SIGNATURES` indefinitely with no indication to User B or the creator that the required signer's key no longer exists.
6. Compare: if User B had instead been removed as an **observer** via `ObserversService.removeTransactionObserver`, `emitTransactionUpdate` would have fired immediately, notifying all connected clients. [7](#0-6) [8](#0-7)

### Citations

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L17-19)
```typescript
export class UserKeysService {
  constructor(@InjectRepository(UserKey) private repo: Repository<UserKey>) {}

```

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L33-66)
```typescript
  async uploadKey(user: User, dto: UploadUserKeyDto): Promise<UserKey> {
    await attachKeys(user, this.repo.manager);

    // Check if the user already has the maximum number of keys
    if (user.keys.length >= MAX_USER_KEYS) {
      throw new BadRequestException(ErrorCodes.UMK);
    }

    // Find the userKey by the publicKey
    let userKey = await this.repo.findOne({
      where: { publicKey: dto.publicKey },
      withDeleted: true,
    });

    if (userKey) {
      // If the userKey found is owned by a different user,
      // or if the userKey has a non null hash or index that doesn't
      // match the hash or index provided
      // throw an error.
      if (userKey.userId !== user.id || (userKey.index && userKey.index !== dto.index)) {
        throw new BadRequestException(ErrorCodes.PU);
      }
      // Set the hash and/or index (only if the current value is null)
      Object.assign(userKey, dto);
    } else {
      userKey = await this.repo.create(dto);
      userKey.user = user;
    }

    if (userKey.deletedAt) {
      await this.repo.recover(userKey);
    }
    return this.repo.save(userKey);
  }
```

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L95-109)
```typescript
  async removeUserKey(user: User, id: number): Promise<boolean> {
    const userKey = await this.getUserKey({ id });

    if (!userKey) {
      throw new BadRequestException(ErrorCodes.KNF);
    }

    if (userKey.userId !== user.id) {
      throw new BadRequestException(ErrorCodes.PNY);
    }

    await this.repo.softRemove(userKey);

    return true;
  }
```

**File:** back-end/apps/api/src/user-keys/user-keys.service.ts (L117-137)
```typescript
  async updateMnemonicHash(
    user: User,
    id: number,
    dto: UpdateUserKeyMnemonicHashDto,
  ): Promise<UserKey> {
    const userKey = await this.getUserKey({ id });

    if (!userKey) {
      throw new BadRequestException(ErrorCodes.KNF);
    }

    if (userKey.userId !== user.id) {
      throw new BadRequestException(ErrorCodes.PNY);
    }

    await this.repo.update({ id }, { mnemonicHash: dto.mnemonicHash, index: dto.index });
    userKey.mnemonicHash = dto.mnemonicHash;
    userKey.index = dto.index || userKey.index;

    return userKey;
  }
```

**File:** back-end/apps/api/src/users/users.service.ts (L156-170)
```typescript
  async removeUser(id: number): Promise<boolean> {
    const user = await this.getUser({ id });

    if (!user) {
      throw new BadRequestException(ErrorCodes.UNF);
    }

    // Soft-delete all user keys first
    await this.repo.manager.softDelete(UserKey, { userId: id });

    // Then soft-delete the user
    await this.repo.softRemove(user);

    return true;
  }
```

**File:** back-end/apps/api/src/transactions/observers/observers.service.ts (L133-141)
```typescript
  async removeTransactionObserver(id: number, user: User): Promise<boolean> {
    const observer = await this.getUpdateableObserver(id, user);

    await this.repo.remove(observer);

    emitTransactionUpdate(this.notificationsPublisher, [{ entityId: observer.transactionId }]);

    return true;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.ts (L204-231)
```typescript
  /* Soft deletes approvers' tree */
  async removeNode(listId: number): Promise<void> {
    if (!listId || typeof listId !== 'number') return null;

    await this.repo.query(
      `
      with recursive approversToDelete AS
        (
          select "id", "listId", "deletedAt"
          from transaction_approver
          where "id" = $1
  
            union all
              select transaction_approver."id", transaction_approver."listId", transaction_approver."deletedAt"
              from transaction_approver, approversToDelete     
              where approversToDelete."id" = transaction_approver."listId"
      
        )
      update transaction_approver
      set "deletedAt" = now()
      from approversToDelete
      where approversToDelete."id" = transaction_approver."listId" or transaction_approver."id" = $1;
    `,
      [listId],
    );

    // notifyTransactionAction(this.notificationsService);
  }
```
