The code is confirmed. Let me verify the guard setup on the `signUp` endpoint as well.

All claims are verified against the actual code. Here is my assessment:

---

Audit Report

## Title
Use of Non-Cryptographically Secure `Math.random()` for Temporary Password Generation

## Summary
The `generatePassword()` private method in `back-end/apps/api/src/auth/auth.service.ts` uses `Math.random()` — a non-CSPRNG — to produce temporary passwords that are emailed to newly registered users and serve as their sole credential until changed.

## Finding Description
The `generatePassword()` method at lines 147–154 of `back-end/apps/api/src/auth/auth.service.ts` constructs a temporary password of the form `xxxxx-xxxxx` using `Math.random()`:

```typescript
private generatePassword() {
  const getRandomLetters = (length: number) =>
    Array.from({ length }, () => String.fromCharCode(97 + Math.floor(Math.random() * 26))).join('');
  return `${getRandomLetters(5)}-${getRandomLetters(5)}`;
}
``` [1](#0-0) 

This password is then passed directly to `usersService.createUser()` (for new accounts) or used to update an existing `UserStatus.NEW` account, and is emailed to the user as their initial credential via `emitUserRegistrationEmail`: [2](#0-1) 

The `signUp` endpoint is protected by `JwtBlackListAuthGuard`, `JwtAuthGuard`, `AdminGuard`, and `EmailThrottlerGuard`: [3](#0-2) 

Node.js (V8) implements `Math.random()` using the **xorshift128+** algorithm, which is **not a CSPRNG**. Its 128-bit internal state can be recovered from as few as 3 consecutive outputs. The password alphabet is restricted to 26 lowercase letters, yielding 26^10 ≈ 1.4 × 10^14 theoretical combinations — but effective entropy is far lower when the PRNG state is recoverable.

## Impact Explanation
An attacker who can observe or infer the approximate time of account creation (e.g., via a registration notification, a public user directory, or a side-channel) and who can observe any other `Math.random()` outputs from the same Node.js process can reconstruct the V8 PRNG state and predict the temporary password. With the predicted password, the attacker can authenticate as the newly created user before that user changes their password, achieving full account takeover. The compromised account may have access to sensitive organization transactions, signing keys, and approval workflows.

## Likelihood Explanation
**Low-Medium.** Exploiting V8's xorshift128+ requires observing prior `Math.random()` outputs from the same process (possible if any other endpoint or log leaks random values) or brute-forcing the reduced keyspace. The window of opportunity is the interval between account creation and the user's first login and password change. The attack is non-trivial but has been demonstrated in research contexts against Node.js applications.

## Recommendation
Replace `Math.random()` with Node.js's cryptographically secure `crypto.randomBytes()` or `crypto.getRandomValues()`. For example:

```typescript
import { randomBytes } from 'crypto';

private generatePassword(): string {
  const getRandomLetters = (length: number) => {
    const bytes = randomBytes(length);
    return Array.from(bytes, b => String.fromCharCode(97 + (b % 26))).join('');
  };
  return `${getRandomLetters(5)}-${getRandomLetters(5)}`;
}
```

This ensures the temporary password is generated with cryptographically strong randomness, eliminating PRNG state recovery attacks.

## Proof of Concept

1. **Observe PRNG outputs**: If any endpoint in the same Node.js process exposes `Math.random()` outputs (e.g., via UUIDs, tokens, or debug endpoints), collect at least 3 consecutive values.
2. **Reconstruct V8 state**: Use a known V8 xorshift128+ state-recovery tool (e.g., [v8-randomness-predictor](https://github.com/nicowillis/v8-randomness-predictor)) to recover the 128-bit internal state from the observed outputs.
3. **Predict the next password**: Advance the recovered PRNG state to the point of the `generatePassword()` call (timed against the account creation event) and compute the 10 `Math.random()` calls that produce the password characters.
4. **Authenticate**: Submit the predicted password to `POST /auth/login` with the newly registered user's email before the user changes their password.
5. **Result**: Successful login as the victim user, achieving account takeover.

### Citations

**File:** back-end/apps/api/src/auth/auth.service.ts (L52-66)
```typescript
    const tempPassword = this.generatePassword();

    const existingUser = await this.usersService.getUser({ email: dto.email }, true);
    let user: User;

    if (existingUser && !existingUser.deletedAt && existingUser.status === UserStatus.NEW) {
      const hashedPass = await this.usersService.getSaltedHash(tempPassword);
      user = await this.usersService.updateUserById(existingUser.id, { password: hashedPass });
    } else {
      user = await this.usersService.createUser(dto.email, tempPassword);
    }

    this.logger.log(`User ${user.id} registered and temporary password generated.`);

    emitUserRegistrationEmail(this.notificationsPublisher, [{ email: user.email, additionalData: { url, tempPassword, downloadUrl } }]);
```

**File:** back-end/apps/api/src/auth/auth.service.ts (L147-154)
```typescript
  private generatePassword() {
    const getRandomLetters = (length: number) =>
      Array.from({ length }, () => String.fromCharCode(97 + Math.floor(Math.random() * 26))).join(
        '',
      );

    return `${getRandomLetters(5)}-${getRandomLetters(5)}`;
  }
```

**File:** back-end/apps/api/src/auth/auth.controller.ts (L60-66)
```typescript
  @Post('/signup')
  @Serialize(AuthDto)
  @UseGuards(JwtBlackListAuthGuard, JwtAuthGuard, AdminGuard, EmailThrottlerGuard)
  async signUp(@Body() dto: SignUpUserDto, @Req() req: Request): Promise<User> {
    const url = `${req.protocol}://${req.get('host')}`;
    return this.authService.signUpByAdmin(dto, url);
  }
```
