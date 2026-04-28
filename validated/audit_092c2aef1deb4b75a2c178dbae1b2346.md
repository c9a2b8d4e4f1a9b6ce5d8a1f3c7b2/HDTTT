### Title
OTP Token Exposed in Plaintext via Custom Protocol Deep Link URL

### Summary
The Electron desktop application processes password-reset OTP tokens delivered via a custom protocol deep link in the form `hedera-transaction-tool://token=<OTP_TOKEN>`. The sensitive token is embedded directly in the URL, which is subject to capture by OS-level URL scheme logs, browser history, email client logs, and any process monitoring URL scheme activations. This is a direct analog to the external report's "Private Access Token in URL" vulnerability class.

### Finding Description

The deep link handler in `front-end/src/main/modules/deepLink.ts` parses the custom protocol URL and extracts the OTP token from the URL string:

```
hedera-transaction-tool://token=<OTP_TOKEN>
``` [1](#0-0) 

The Electron main process registers this handler via `app.setAsDefaultProtocolClient(PROTOCOL_NAME)` and fires it on the `open-url` event: [2](#0-1) [3](#0-2) 

The OTP token extracted from the URL is then forwarded to the renderer process via IPC as `deepLink:otp`: [4](#0-3) [5](#0-4) 

The renderer auto-fills the OTP input with the token received from the deep link: [6](#0-5) 

The OTP token is a JWT-signed credential issued by the backend's `POST /auth/reset-password` endpoint. It is used to authenticate the password-reset flow — verifying it at `POST /auth/verify-reset` grants the ability to set a new password for the account: [7](#0-6) [8](#0-7) 

The token has a configurable expiry (`OTP_EXPIRATION` minutes) and a TOTP window of `step=60, window=20` (~20 minutes): [9](#0-8) [10](#0-9) 

**Exposure vectors for the token-in-URL:**
- macOS Console / Windows Event Viewer logs URL scheme activations
- Browser history (if the deep link is clicked from a web browser or email client rendered in a browser)
- Email client logs and message stores
- Any process on the machine monitoring URL scheme activations (e.g., malware, security tools)

**Secondary observation — `LoggerMiddleware` logs `originalUrl` unmasked:**

The backend logger masks the parsed `query['token']` field but logs `originalUrl` verbatim, which includes the raw query string. If any future endpoint accepts a token as a query parameter, it would be logged in plaintext in server logs despite the masking attempt: [11](#0-10) 

No current HTTP endpoint passes a token as a query parameter, so this is a latent gap rather than an immediately exploitable path.

### Impact Explanation

An attacker who captures the deep link URL (via OS logs, browser history, email client logs, or local process monitoring) obtains a valid OTP JWT. Submitting this token to `POST /auth/verify-reset` with the correct TOTP code (derivable from the shared `OTP_SECRET + email` if the secret is known, or by brute-forcing the 8-digit TOTP) yields a verified OTP JWT, which can then be used at `PATCH /auth/set-password` to overwrite the victim's account password — full account takeover within the OTP validity window.

### Likelihood Explanation

The attacker must be able to read OS-level URL scheme logs, browser history, or email client storage on the victim's machine — or have a process running locally that intercepts URL scheme activations. This requires either local access or malware already present on the machine. The OTP validity window is approximately 20 minutes. Likelihood is low but realistic in shared-machine or malware scenarios, consistent with the external report's Likelihood: 2 rating.

### Recommendation

1. **Do not embed the OTP token in the URL.** Instead, deliver the OTP code only via email as a plain numeric/alphanumeric code that the user types manually. Remove the deep link auto-fill mechanism entirely, or replace it with a mechanism that does not place the token in the URL (e.g., a short-lived server-side session ID that is not the token itself).
2. If the deep link mechanism is retained for UX reasons, use an opaque, single-use, server-side lookup code in the URL (not the JWT itself), and exchange it for the JWT only after the app has opened and made a server-side call.
3. Fix the `LoggerMiddleware` to strip the query string from `originalUrl` before logging, or reconstruct the log line from `req.path` only, to prevent future token-in-URL leakage into server logs.

### Proof of Concept

1. Attacker has local read access to the victim's machine (e.g., shared workstation, or malware).
2. Victim initiates password reset in the Hedera Transaction Tool for their organization account.
3. Backend sends an email containing a deep link: `hedera-transaction-tool://token=<OTP_JWT>`.
4. Victim clicks the link in their email client or browser.
5. The OS activates the custom URL scheme; the full URL including `token=<OTP_JWT>` is recorded in macOS Console (`com.apple.launchservices`) or Windows Event Log.
6. Attacker reads the log entry and extracts `<OTP_JWT>`.
7. Attacker sends:
   ```
   POST /auth/verify-reset
   otp: <OTP_JWT>
   { "token": "<8-digit TOTP>" }
   ```
   The TOTP is either obtained from the email (if attacker can read email) or brute-forced (8 digits = 100,000,000 combinations, but the server's TOTP window limits valid values to a small set at any moment).
8. On success, attacker receives a verified OTP JWT and calls `PATCH /auth/set-password` to set a new password, achieving full account takeover. [12](#0-11) [2](#0-1) [13](#0-12)

### Citations

**File:** front-end/src/main/modules/deepLink.ts (L1-22)
```typescript
import { BrowserWindow } from 'electron';

export const PROTOCOL_NAME = 'hedera-transaction-tool';

export default function (
  window: BrowserWindow,
  event: {
    preventDefault: () => void;
    readonly defaultPrevented: boolean;
  },
  url: string,
) {
  event.preventDefault();

  const params = url.split(`${PROTOCOL_NAME}://`)[1];

  if (params.includes('token')) {
    const token = params.split('token=')[1];
    window.webContents.send('deepLink:otp', token);
    window.show();
  }
}
```

**File:** front-end/src/main/index.ts (L94-97)
```typescript
  app.on('open-url', (event, url) => {
    if (mainWindow === null) return;
    handleDeepLink(mainWindow, event, url);
  });
```

**File:** front-end/src/main/index.ts (L114-123)
```typescript
function setupDeepLink() {
  if (process.defaultApp) {
    if (process.argv.length >= 2) {
      app.setAsDefaultProtocolClient(PROTOCOL_NAME, process.execPath, [
        path.resolve(process.argv[1]),
      ]);
    }
  } else {
    app.setAsDefaultProtocolClient(PROTOCOL_NAME);
  }
```

**File:** front-end/src/preload/localUser/deepLink.ts (L1-14)
```typescript
import { ipcRenderer } from 'electron';

export default {
  deepLink: {
    onOTPReceived: (callback: (otp: string) => void) => {
      const subscription = (_e: Electron.IpcRendererEvent, otp: string) => callback(otp);
      ipcRenderer.on('deepLink:otp', subscription);
      return () => {
        ipcRenderer.removeListener('deepLink:otp', subscription);
      };
    },
  },
};

```

**File:** front-end/src/renderer/components/ForgotPasswordModal.vue (L174-179)
```vue
onBeforeMount(async () => {
  onOTPReceivedUnsubscribe.value = window.electronAPI.local.deepLink.onOTPReceived(
    (token: string) => {
      otpInputRef.value?.setOTP(token);
    },
  );
```

**File:** back-end/apps/api/src/auth/auth.service.ts (L30-34)
```typescript
totp.options = {
  digits: 8,
  step: 60,
  window: 20,
};
```

**File:** back-end/apps/api/src/auth/auth.service.ts (L98-110)
```typescript
  async createOtp(email: string): Promise<{ token: string }> {
    const user = await this.usersService.getUser({ email });

    if (!user) return;

    const secret = this.getOtpSecret(user.email);
    const otp = totp.generate(secret);

    emitUserPasswordResetEmail(this.notificationsPublisher, [{ email: user.email, additionalData: { otp } }]);

    const token = this.getOtpToken({ email: user.email, verified: false });
    return { token };
  }
```

**File:** back-end/apps/api/src/auth/auth.service.ts (L131-139)
```typescript
  /* Sets the OTP jwt */
  private getOtpToken(otpPayload: OtpPayload) {
    const expires = new Date();
    expires.setSeconds(expires.getSeconds() + totp.options.step * (totp.options.window as number));

    return this.jwtService.sign(otpPayload, {
      expiresIn: `${this.configService.get('OTP_EXPIRATION')}m`,
    });
  }
```

**File:** back-end/apps/api/src/auth/auth.controller.ts (L152-175)
```typescript
  @Post('/verify-reset')
  @HttpCode(200)
  @UseGuards(JwtBlackListOtpGuard, OtpJwtAuthGuard)
  async verifyOtp(@GetUser() user: User, @Body() dto: OtpDto, @Req() req) {
    const result = await this.authService.verifyOtp(user, dto);
    await this.blacklistService.blacklistToken(extractJwtOtp(req));
    return result;
  }

  /* Set the password for the user if the email has been verified */
  @ApiOperation({
    summary: 'Set the password',
    description: 'Set the password for the verified email.',
  })
  @ApiResponse({
    status: 200,
    description: 'Password successfully set.',
  })
  @UseGuards(JwtBlackListOtpGuard, OtpVerifiedAuthGuard)
  @Patch('/set-password')
  async setPassword(@GetUser() user: User, @Body() dto: NewPasswordDto, @Req() req): Promise<void> {
    await this.authService.setPassword(user, dto.password);
    await this.blacklistService.blacklistToken(extractJwtOtp(req));
  }
```

**File:** back-end/libs/common/src/middleware/logger.middleware.ts (L11-24)
```typescript
    const { method, originalUrl, body = {}, query = {} } = req;
    const start = Date.now();

    const maskedBody = maskSensitiveData(body, ['password', 'email']);
    const maskedQuery = maskSensitiveData(query, ['token']);

    res.on('finish', () => {
      const { statusCode } = res;
      const duration = Date.now() - start;
      const payload =
        Object.keys(maskedBody).length || Object.keys(maskedQuery).length
          ? ` - Payload: ${JSON.stringify({ body: maskedBody, query: maskedQuery })}`
          : '';
      this.logger.info(`${method} ${originalUrl} ${statusCode} - ${duration}ms${payload}`);
```
