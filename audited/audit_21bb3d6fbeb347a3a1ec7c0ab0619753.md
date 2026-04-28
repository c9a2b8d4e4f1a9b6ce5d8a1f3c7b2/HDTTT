Based on my investigation, I found a direct analog to the external report's vulnerability class.

The front-end `transaction-factory.ts` imports `NodeCreateTransactionModel` from `./node-create-transaction.model`: [1](#0-0) 

However, the file `node-create-transaction.model.ts` does **not exist** in the front-end `transactionSignatureModels` directory. The directory contains `node-update-transaction.model.ts` and `node-delete-transaction.model.ts`, but no `node-create-transaction.model.ts`:



The back-end has the file at `back-end/libs/common/src/transaction-signature/model/node-create-transaction.model.ts`, but the front-end counterpart is absent: [2](#0-1) 

---

### Title
Missing `node-create-transaction.model.ts` in Front-End Causes Build Failure

### Summary
The front-end `TransactionFactory` imports `NodeCreateTransactionModel` from a file that does not exist in the front-end codebase, mirroring the exact compilation failure pattern described in the external report.

### Finding Description
`front-end/src/renderer/utils/transactionSignatureModels/transaction-factory.ts` line 14 contains:

```typescript
import NodeCreateTransactionModel from './node-create-transaction.model';
```

The file `front-end/src/renderer/utils/transactionSignatureModels/node-create-transaction.model.ts` is absent from the repository. Every other transaction model imported by this factory (`node-update-transaction.model.ts`, `node-delete-transaction.model.ts`, `freeze-transaction.model.ts`, etc.) has a corresponding file in the same directory. The back-end equivalent (`back-end/libs/common/src/transaction-signature/model/node-create-transaction.model.ts`) exists, but the front-end copy was never created. [3](#0-2) 

### Impact Explanation
The front-end Vite/TypeScript build will fail to resolve the import, preventing the Electron application from being compiled and distributed. Any CI/CD pipeline that builds the front-end will break. At runtime, `TransactionFactory.fromTransaction` cannot handle `NodeCreateTransaction` payloads, meaning node-creation transactions cannot be deserialized or have their required signers computed in the front-end.

### Likelihood Explanation
This is a deterministic build-time failure — any developer or CI system that runs `pnpm build` (or equivalent) in the `front-end` directory will reproduce it immediately. The `NodeCreate` transaction type is explicitly listed as a supported type in the automation test data and the back-end model registry, confirming it is an intended, exercised code path. [4](#0-3) 

### Recommendation
Create `front-end/src/renderer/utils/transactionSignatureModels/node-create-transaction.model.ts` following the same pattern as the existing front-end models and the back-end counterpart:

```typescript
import { NodeCreateTransaction } from '@hiero-ledger/sdk';
import { TransactionBaseModel } from './transaction.model';

export default class NodeCreateTransactionModel extends TransactionBaseModel<NodeCreateTransaction> {}
```

Then add it to the `transactionModelMap` in `transaction-factory.ts` (it is already imported there but the map entry is missing as well).

### Proof of Concept
1. Clone the repository.
2. `cd front-end && pnpm install && pnpm build`
3. Observe TypeScript/Vite error: `Cannot find module './node-create-transaction.model'` originating from `transaction-factory.ts:14`. [1](#0-0)

### Citations

**File:** front-end/src/renderer/utils/transactionSignatureModels/transaction-factory.ts (L1-17)
```typescript
import { Transaction } from '@hiero-ledger/sdk';
import { TransactionBaseModel } from './transaction.model';
import TransferTransactionModel from './transfer-transaction.model';
import AccountCreateTransactionModel from './account-create-transaction.model';
import AccountUpdateTransactionModel from './account-update-transaction.model';
import SystemDeleteTransactionModel from './system-delete-transaction.model';
import SystemUndeleteTransactionModel from './system-undelete-transaction.model';
import FileUpdateTransactionModel from './file-update-transaction.model';
import FreezeTransactionModel from './freeze-transaction.model';
import FileAppendTransactionModel from './file-append-transaction.model';
import AccountDeleteTransactionModel from './account-delete-transaction.model';
import AccountAllowanceApproveTransactionModel from './approve-allowance-transaction.model';
import FileCreateTransactionModel from './file-create-transaction.model';
import NodeCreateTransactionModel from './node-create-transaction.model';
import NodeUpdateTransactionModel from './node-update-transaction.model';
import NodeDeleteTransactionModel from './node-delete-transaction.model';
import { getTransactionType } from '../sdk/transactions';
```

**File:** back-end/libs/common/src/transaction-signature/model/node-create-transaction.model.ts (L1-1)
```typescript
import { NodeCreateTransaction } from '@hiero-ledger/sdk';
```

**File:** back-end/libs/common/src/transaction-signature/model/transaction-factory.ts (L12-12)
```typescript
import { NodeCreateTransactionModel } from './node-create-transaction.model';
```
