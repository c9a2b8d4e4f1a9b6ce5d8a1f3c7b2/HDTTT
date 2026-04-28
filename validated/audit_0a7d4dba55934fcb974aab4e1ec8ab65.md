### Title
Unpinned `actions/upload-artifact@v7` Tag in Test Frontend Workflow Enables Supply Chain Attack

### Summary
The `test-frontend.yaml` workflow uses `actions/upload-artifact@v7` — pinned only to a mutable version tag — in four separate steps. If the tag is silently moved to a malicious commit (e.g., via a compromised `actions` org account or a tag-force-push), the injected code would execute with access to the runner environment and any secrets available to the job, including `CODECOV_TOKEN`.

### Finding Description
In `.github/workflows/test-frontend.yaml`, the `actions/upload-artifact` action is referenced four times using the mutable tag `@v7` rather than a full-length commit SHA:

- Line 392: Upload Playwright Report
- Line 402: Upload Playwright Test Results
- Line 429: Upload Solo Diagnostics
- Line 441: Upload Kind Logs

All other actions in this repository are correctly pinned to full commit SHAs (e.g., `actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd`). The `upload-artifact` steps are the sole exception. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Impact Explanation
A malicious version of `actions/upload-artifact` executing in the `test` job context would have access to:
- The `CODECOV_TOKEN` secret (used in the `unit-test` job at line 499)
- The full runner filesystem, including build artifacts and checked-out source
- The ability to exfiltrate or tamper with uploaded artifacts (Playwright reports, test results, Solo diagnostics, Kind logs)

The workflow runs on `push` to `main`/`release/**` branches and on `pull_request` events, meaning it triggers on every significant code change. [5](#0-4) [6](#0-5) 

### Likelihood Explanation
`actions/upload-artifact` is a GitHub first-party action, which lowers the probability of compromise compared to a random third-party action. However, the `v7` tag is still mutable — any maintainer of the `actions/upload-artifact` repository with sufficient access could force-push the tag to a different commit. The inconsistency with the rest of the repository (all other actions are SHA-pinned) suggests this was an oversight rather than an intentional policy decision.

### Recommendation
**Short term**: Replace all four `actions/upload-artifact@v7` references with the full commit SHA corresponding to the intended `v7` release. For example:
```yaml
uses: actions/upload-artifact@65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08 # v4.6.0
```
Verify the correct SHA from the [actions/upload-artifact releases page](https://github.com/actions/upload-artifact/releases).

**Long term**: Enforce SHA pinning for all actions via a tool such as [Dependabot for GitHub Actions](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot) or [StepSecurity's `pin-github-action`](https://github.com/step-security/pin-github-action), which can automatically update pinned SHAs when new versions are released.

### Proof of Concept
1. An attacker gains write access to the `actions/upload-artifact` repository (e.g., via a compromised maintainer account).
2. The attacker force-pushes the `v7` tag to a commit that exfiltrates environment variables and secrets to an external endpoint.
3. A developer pushes a commit to `main` or opens a PR against `main`/`release/**` in this repository.
4. The `test-frontend.yaml` workflow triggers, the malicious `upload-artifact` action executes in the `test` job, and `CODECOV_TOKEN` (and any other available environment data) is exfiltrated.
5. The attacker uses the stolen token to inject false coverage data or pivot further into the CI/CD pipeline.

### Citations

**File:** .github/workflows/test-frontend.yaml (L1-12)
```yaml
name: Test Frontend

on:
  push:
    branches:
      - main
      - release/**
  pull_request:
    branches:
      - main
      - release/**
  workflow_dispatch:
```

**File:** .github/workflows/test-frontend.yaml (L391-396)
```yaml
        if: ${{ always() }}
        uses: actions/upload-artifact@v7
        with:
          name: playwright-report-${{ matrix.test-suite.name }}
          path: automation/reports/playwright
          if-no-files-found: warn
```

**File:** .github/workflows/test-frontend.yaml (L399-406)
```yaml
      - name: Upload Playwright Test Results
        if: ${{ always() }}
        uses: actions/upload-artifact@v7
        with:
          name: playwright-test-results-${{ matrix.test-suite.name }}
          path: automation/test-results
          if-no-files-found: warn
          retention-days: 3
```

**File:** .github/workflows/test-frontend.yaml (L428-434)
```yaml
        if: ${{ always() && matrix.test-suite.soloRequired }}
        uses: actions/upload-artifact@v7
        with:
          name: solo-diagnostics-${{ matrix.test-suite.name }}
          path: solo-diagnostics
          if-no-files-found: warn
          retention-days: 3
```

**File:** .github/workflows/test-frontend.yaml (L440-447)
```yaml
      - name: Upload Kind Logs
        if: ${{ failure() && matrix.test-suite.soloRequired }}
        uses: actions/upload-artifact@v7
        with:
          name: kind-logs-${{ matrix.test-suite.name }}
          path: kind-logs
          if-no-files-found: warn
          retention-days: 3
```

**File:** .github/workflows/test-frontend.yaml (L498-500)
```yaml
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@5c47607acb93fed5485fdbf7232e8a31425f672a # v5.0.2
        with:
```
