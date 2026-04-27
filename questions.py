import json
import os

from decouple import config

MAX_REPO = 20
SOURCE_REPO = "hashgraph/hedera-transaction-tool"
REPO_NAME = "hedera-transaction-tool"
run_number = os.environ.get('GITHUB_RUN_NUMBER', '0')

target_scopes = [
    ""
]



def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index"""
    return (int(run_number) - 1) % max_index + 1


if run_number == "0":
    BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"
else:
    # Convert to cyclic index (1-100)
    run_index = get_cyclic_index(run_number, MAX_REPO)
    # Format the URL with leading zeros
    repo_number = f"{run_index:03d}"
    BASE_URL = f"https://deepwiki.com/0xOyakhilome/{REPO_NAME}--{repo_number}"



scope_files = [
    "back-end/apps/api/src/main.ts",
    "back-end/apps/api/src/setup-app.ts",
    "back-end/apps/api/src/api.module.ts",
    "back-end/apps/api/src/auth/auth.controller.ts",
    "back-end/apps/api/src/auth/auth.service.ts",
    "back-end/apps/api/src/auth/strategies/jwt.strategy.ts",
    "back-end/apps/api/src/auth/strategies/otp-jwt.strategy.ts",
    "back-end/apps/api/src/guards/jwt-auth.guard.ts",
    "back-end/apps/api/src/guards/jwt-blacklist.guard.ts",
    "back-end/apps/api/src/guards/otp-jwt-auth.guard.ts",
    "back-end/apps/api/src/guards/verified-user.guard.ts",
    "back-end/apps/api/src/transactions/transactions.controller.ts",
    "back-end/apps/api/src/transactions/transactions.service.ts",
    "back-end/apps/api/src/transactions/signers/signers.service.ts",
    "back-end/apps/api/src/transactions/nodes/transaction-nodes.service.ts",
    "back-end/apps/api/src/user-keys/user-keys.service.ts",
    "back-end/apps/api/src/users/users.service.ts",
    "back-end/apps/chain/src/main.ts",
    "back-end/apps/chain/src/setup-app.ts",
    "back-end/apps/chain/src/transaction-scheduler/transaction-scheduler.service.ts",
    "back-end/apps/chain/src/transaction-reminder/reminder-handler.service.ts",
    "back-end/apps/notifications/src/main.ts",
    "back-end/apps/notifications/src/setup-app.ts",
    "back-end/apps/notifications/src/fan-out/fan-out.service.ts",
    "back-end/apps/notifications/src/receiver/receiver.service.ts",
    "back-end/apps/notifications/src/websocket/middlewares/auth-websocket.middleware.ts",
    "back-end/apps/notifications/src/websocket/websocket.gateway.ts",
    "back-end/libs/common/src/database/entities/transaction.entity.ts",
    "back-end/libs/common/src/database/entities/user-key.entity.ts",
    "back-end/libs/common/src/blacklist/blacklist.service.ts",
    "back-end/libs/common/src/execute/execute.service.ts",
    "back-end/libs/common/src/interceptors/only-owner-key.interceptor.ts",
    "back-end/libs/common/src/decorators/is-signature-map.decorator.ts",
    "back-end/libs/common/src/validators/is-hedera-public-key.validator.ts",
    "back-end/libs/common/src/sql/queries/transaction.queries.ts",
    "back-end/libs/common/src/sql/sql-builder.service.ts",
    "back-end/libs/common/src/transaction-signature/transaction-signature.module.ts",
    "back-end/libs/common/src/transaction-signature/transaction-signature.service.ts",
    "back-end/libs/common/src/transaction-signature/mirror-node.client.ts",
    "back-end/libs/common/src/transaction-signature/account-cache.service.ts",
    "back-end/libs/common/src/transaction-signature/node-cache.service.ts",
    "back-end/libs/common/src/transaction-signature/model/transaction-factory.ts",
    "back-end/libs/common/src/transaction-signature/model/transaction-base.model.ts",
    "back-end/libs/common/src/transaction-signature/model/account-create-transaction.model.ts",
    "back-end/libs/common/src/transaction-signature/model/account-update-transaction.model.ts",
    "back-end/libs/common/src/transaction-signature/model/account-delete-transaction.model.ts",
    "back-end/libs/common/src/transaction-signature/model/account-allowance-approve-transaction.model.ts",
    "back-end/libs/common/src/transaction-signature/model/transfer-transaction.model.ts",
    "back-end/libs/common/src/transaction-signature/model/file-create-transaction.model.ts",
    "back-end/libs/common/src/transaction-signature/model/file-update-transaction.model.ts",
    "back-end/libs/common/src/transaction-signature/model/file-append-transaction.model.ts",
    "back-end/libs/common/src/transaction-signature/model/freeze-transaction.model.ts",
    "back-end/libs/common/src/transaction-signature/model/node-create-transaction.model.ts",
    "back-end/libs/common/src/transaction-signature/model/node-update-transaction.model.ts",
    "back-end/libs/common/src/transaction-signature/model/node-delete-transaction.model.ts",
    "back-end/libs/common/src/transaction-signature/model/system-delete-transaction.model.ts",
    "back-end/libs/common/src/transaction-signature/model/system-undelete-transaction.model.ts",
    "back-end/libs/common/src/utils/sdk/client.ts",
    "back-end/libs/common/src/utils/sdk/key.ts",
    "back-end/libs/common/src/utils/sdk/transaction.ts",
    "back-end/libs/common/src/utils/mirrorNode/index.ts",
    "back-end/libs/common/src/utils/transaction/index.ts",
    "front-end/src/main/index.ts",
    "front-end/src/main/modules/ipcHandlers/localUser/transactions.ts",
    "front-end/src/main/modules/ipcHandlers/localUser/transactionFile.ts",
    "front-end/src/main/services/localUser/transactions.ts",
    "front-end/src/main/services/localUser/transactionGroups.ts",
    "front-end/src/main/services/localUser/encryptedKeys.ts",
    "front-end/src/main/services/localUser/keyPairs.ts",
    "front-end/src/main/utils/transactionFile.ts",
    "front-end/src/main/utils/crypto.ts",
    "front-end/src/preload/index.ts",
    "front-end/src/preload/localUser/transactions.ts",
    "front-end/src/preload/localUser/transactionFile.ts",
    "front-end/src/preload/localUser/encryptedKeys.ts",
    "front-end/src/preload/localUser/keyPairs.ts",
    "front-end/src/renderer/caches/AppCache.ts",
    "front-end/src/renderer/services/organization/auth.ts",
    "front-end/src/renderer/services/encryptedKeys.ts",
    "front-end/src/renderer/services/keyPairService.ts",
    "front-end/src/renderer/services/sdkService.ts",
    "front-end/src/renderer/services/transactionService.ts",
    "front-end/src/renderer/services/transactionGroupsService.ts",
    "front-end/src/renderer/utils/signatureTools.ts",
    "front-end/src/renderer/utils/transactionFile.ts",
    "front-end/src/renderer/utils/sdk/createTransactions.ts",
    "front-end/src/renderer/utils/sdk/transactions.ts",
    "front-end/src/renderer/utils/transactionSignatureModels/transaction.model.ts",
    "front-end/src/shared/utils/transactionFile.ts",
    "shared/src/ITransactionNode.ts",
]


target_scopes += [
    "Critical: Network not being able to confirm new transactions (total network shutdown)",
    "Critical: Network partition caused outside of design parameters",
    "Critical: Direct loss of funds",
    "Critical: Unintended permanent freezing of funds",
    "Critical: Any impact caused by Tampering/Manipulating Hashgraph history",

    "High: Temporary freezing of network transactions by delaying one block by 500% or more of the average block time of the preceding 24 hours beyond standard difficulty adjustments",
    "High: Preventing gossip of a transaction or multiple transactions",
    "High: Reorganizing transaction history without direct theft of funds",
    "High: Any impacts caused by Tampering with submitted transactions",
    "High: Authorizing transactions without approval from signers/owners",
    "High: Non-network-based DoS affecting projects with greater than or equal to 25% of the market capitalization on top of the respective layer",

    "Medium: Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours",
    "Medium: Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network",
    "Medium: A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk",
    "Medium: Incorrect or missing records exported to mirror nodes",
    "Medium: Impacts caused by griefing with no economic damage to any user on the network",
    "Medium: Theft of unpaid staking rewards",
    "Medium: Modification of transaction fees outside of design parameters"
]


def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit questions for one scope file.
    """
    prompt = f"""
Generate exploit-focused security audit questions for `{target_file}` only.

Important: `{target_file}` is in-scope in this  repository and is accessible context.
Do not say the file is missing/inaccessible and do not ask for file content.

Rules:
- Every question must start with `[File: {target_file}]`.
- Use symbols/function names from `{target_file}` when possible.
- Each question must include attacker action, preconditions, trigger, and concrete impact.
- Every question MUST assume the attacker is a user with NO special permissions (unprivileged external user).
- Do not assume admin keys, owner roles, privileged APIs, internal network access, or operator-only controls.
- Only include privileged-access scenarios if they clearly start from a no-permission user path that leads to escalation.
- Focus questions on user without privilege this is very important 
- Focus on the scope solely and only generate questions base on the scope .
- Never return empty; output the maximum valid high-signal set.
- Hard minimum 80 questions; target up to 150.
- Do not generate questions base on the Security.MD file that would result in out of scope and rejected vulnerability 
- Generate question base on the scope provided this is very very important 
- Focus questions in scope if scope is provided 

Note: Think like an attacker with no permission (very important), check Researcher.MD also to get more info.

Output only valid Python (no markdown, no explanations):
questions = [
    "[File: {target_file}] [Function: functionName()] Can an unprivileged external user do X by exploiting Y under Z preconditions, causing concrete impact?",
    "[File: {target_file}] [Function: anotherFunction()] Can a user without permission craft malformed input/path W to bypass check Q and violate invariant R, leading to impact S?",
]
"""
    return prompt


def audit_format(security_question: str) -> str:
    """
    Generate a focused security-audit prompt.
    """
    prompt = f"""# SECURITY AUDIT PROMPT

## Security Question
{security_question}

## Access Rules (Strict)
- In-scope paths referenced by this question exist in this repository and are accessible context.
- Do not claim files are missing/inaccessible.
- Do not ask for file content.
- Do not output repo-navigation/help text.
- Vuln is valid mostly when it requires user with no privileged 

## Mission
Investigate only this question for real, exploitable protocol-security issues in contracts.
Ignore style/refactor/docs issues.



Note: Think like a real attacker in a real world and  check Researcher.MD also to get more info and be smart.


## Validation Gate (all required)
1. Exact in-scope code location (file, function, line range).
2. Clear root cause and failed assumption.
3. Practical exploit path (preconditions -> trigger -> result).
4. Existing checks reviewed and shown insufficient.
5. Concrete impact + realistic likelihood.

## Output (Strict)
If and only if all validation checks pass, output this exact structure:

### Title
[Concise vulnerability title]

### Summary
[2-3 sentence summary]

### Finding Description
[Exact code path, root cause, exploit flow, why checks fail]

### Impact Explanation
[Concrete protocol impact and severity rationale]

### Likelihood Explanation
[Realistic attacker capability, feasibility, repeatability]

### Recommendation
[Specific fix guidance]

### Proof of Concept
[Reproducible steps]

Else output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a short strict-validation prompt for  security claims.
    """
    prompt = f"""#  VALIDATION PROMPT

## Security Claim
{report}


Note: Check the Security.MD and never generate report that would result in out of scope and rejected vulnerability 


## Required Checks (all must pass)
1. Exact file/function/line references.
2. Clear root cause and failed assumption.
3. Realistic exploit flow and why checks fail.
4. Concrete impact and realistic likelihood.

## Output (Strict)
If valid, output:

Audit Report
## Title
## Summary
## Finding Description
## Impact Explanation
## Likelihood Explanation
## Recommendation
## Proof of Concept

Else output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above.
"""
    return prompt


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for .
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Access Rules (Strict)
- Treat in-scope  files as accessible context.
- Do not claim missing/inaccessible files.
- Do not ask for repository contents.

## Objective
Find whether the same vulnerability class can occur in  in-scope code.
Use the external report as a hint, not as proof.


Note: Check the RESEARCHER.md and think in this actual way 
Note: Check the Security.MD and never generate report that would result in out of scope and rejected vulnerability 

## Method
1. Classify vuln type (auth, accounting, state transition, pricing/rounding, replay, reentrancy, DoS).
2. Map this external report to this protocol and check every scenario in this protocol to find valid vulnerability.
3. Prove root cause with exact file/function/line references.
4. Confirm concrete impact + realistic likelihood.

## Disqualify Immediately
- No reachable attacker-controlled entry path.
- Trusted-role compromise required.
- Theoretical-only issue with no protocol impact.
- Impact or likelihood missing.

## Output (Strict)
If valid analog exists, output:

### Title
### Summary
### Finding Description
### Impact Explanation
### Likelihood Explanation
### Recommendation
### Proof of Concept

If not, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt
