### Title
IDOR in `DELETE /transactions/:transactionId/approvers/:id` Allows Any Transaction Creator to Delete Approvers from Arbitrary Transactions

### Summary
The `removeTransactionApprover` controller action verifies that the authenticated user is the creator of the transaction identified by the URL's `:transactionId` parameter, but it never validates that the approver identified by `:id` actually belongs to that transaction. Any registered user who has created at least one transaction can therefore delete approvers from any other transaction in the system by supplying their own `transactionId` in the URL and an arbitrary approver `id` in the path.

### Finding Description

**Root cause — missing cross-object ownership check**

In `approvers.controller.ts` the `DELETE /:id` handler is:

```typescript
@Delete('/:id')
async removeTransactionApprover(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Param('id', ParseIntPipe) id: number,
) {
    await this.approversService.getCreatorsTransaction(transactionId, user);
    await this.approversService.removeTransactionApprover(id);
    return true;
}
``` [1](#0-0) 

`getCreatorsTransaction(transactionId, user)` only confirms that the caller is the creator of the transaction whose ID appears in the URL. [2](#0-1) 

`removeTransactionApprover(id)` then fetches the approver by its own primary key and deletes it — with no check that `approver.transactionId === transactionId`:

```typescript
async removeTransactionApprover(id: number): Promise<void> {
    const approver = await this.getTransactionApproverById(id);
    if (!approver) throw new BadRequestException(ErrorCodes.ANF);
    const result = await this.removeNode(approver.id);
    emitTransactionStatusUpdate(this.notificationsPublisher, [{ entityId: approver.transactionId }]);
    return result;
}
```

<cite repo="0xOyakhilome/hedera-transaction-tool--008" path="back-end/apps/api/src/transactions/approvers/approvers.

### Citations

**File:** back-end/apps/api/src/transactions/approvers/approvers.controller.ts (L102-113)
```typescript
  @Delete('/:id')
  async removeTransactionApprover(
    @GetUser() user: User,
    @Param('transactionId', ParseIntPipe) transactionId: number,
    @Param('id', ParseIntPipe) id: number,
  ) {
    await this.approversService.getCreatorsTransaction(transactionId, user);
    await this.approversService.removeTransactionApprover(id);
    // await this.approversService.emitSyncIndicators(transactionId);

    return true;
  }
```

**File:** back-end/apps/api/src/transactions/approvers/approvers.service.spec.ts (L1490-1501)
```typescript
    it('should throw if user is not creator', async () => {
      const transaction = {
        id: 1,
        creatorKey: { userId: 2 },
      };

      dataSource.manager.findOne.mockResolvedValueOnce(transaction);

      await expect(service.getCreatorsTransaction(1, user)).rejects.toThrow(
        'Only the creator of the transaction is able to modify it',
      );
    });
```
