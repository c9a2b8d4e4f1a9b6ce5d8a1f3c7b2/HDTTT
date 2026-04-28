### Title
Unbounded Password Length Passed to `argon2.verify()` Enables DoS on Login Endpoint

### Summary
The `POST /auth/login` endpoint accepts a `password` field with no maximum length constraint. The authentication flow passes this unbounded string directly to `argon2.verify()`, a memory-hard hashing function that processes the full input regardless of size. An attacker who knows a valid user email can send concurrent requests with megabyte-scale passwords, causing severe CPU and memory exhaustion on the server — a direct analog to the "lack of restriction on seed length" class from the external report.

### Finding Description
The `LoginDto` enforces only `@IsString()` and `@IsNotEmpty()` on the `password` field, with no `@MaxLength()` bound. [1](#0-0) 

The login route applies `LocalAuthGuard` **before** `EmailThrottlerGuard`. NestJS executes guards in declaration order, so the passport strategy — and therefore the argon2 computation — runs before any rate-limit check can block the request. [2](#0-1) 

`LocalStrategy.validate()` calls `UsersService.getVerifiedUser()`, which calls `dualCompareHash()`: [3](#0-2) 

`dualCompareHash` calls both `bcrypt.compare` and `argon2.verify` unconditionally. bcrypt silently truncates input at 72 bytes, but `argon2.verify` processes the **full** input string: [4](#0-3) 

The same unbounded path exists in `AuthService.dualCompareHash`: [5](#0-4) 

The `ChangePasswordDto.oldPassword` field has the same problem — `@IsString()` + `@IsNotEmpty()` with no `@MaxLength()`: [6](#0-5) 

### Impact Explanation
argon2 (default: `memoryCost=65536`, `timeCost=3`) is intentionally slow and memory-intensive. Processing a 10 MB password string multiplies that cost dramatically. A small number of concurrent requests with oversized passwords can saturate the Node.js event loop and exhaust available memory, making the API unresponsive for all users — a full Denial of Service.

### Likelihood Explanation
The `POST /auth/login` endpoint is publicly reachable with no authentication prerequisite. The only prerequisite is knowing one valid user email, which is realistic in an organization context (emails are often guessable or leaked). The `EmailThrottlerGuard` does not prevent the attack because it runs after the argon2 computation has already been triggered. A single attacker with a script sending a handful of concurrent requests with a large password is sufficient to trigger the condition.

### Recommendation
Add a `@MaxLength()` decorator to all password fields in DTOs before they reach any hashing function. A limit of 72–128 characters is standard practice:

```typescript
// login.dto.ts
@IsString()
@IsNotEmpty()
@MaxLength(128)
password: string;

// change-password.dto.ts
@IsString()
@IsNotEmpty()
@MaxLength(128)
oldPassword: string;
```

Apply the same fix to `NewPasswordDto` and any other DTO that feeds into `argon2.hash` or `argon2.verify`. Additionally, consider reordering guards so `EmailThrottlerGuard` runs before `LocalAuthGuard`, or apply a global body-size limit at the HTTP layer.

### Proof of Concept

```bash
# Attacker knows a valid email (e.g., from org directory)
HUGE_PASSWORD=$(python3 -c "print('A' * 10_000_000)")

# Send concurrent requests — each triggers argon2.verify on 10 MB input
for i in $(seq 1 10); do
  curl -s -X POST https://<target>/auth/login \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"known.user@org.com\",\"password\":\"$HUGE_PASSWORD\"}" &
done
wait
```

Each request causes `argon2.verify` to process 10 MB of data under its default memory-hard parameters. Ten concurrent requests are sufficient to saturate a typical Node.js server process, causing timeouts for all other users. [1](#0-0) [4](#0-3) [2](#0-1)

### Citations

**File:** back-end/apps/api/src/auth/dtos/login.dto.ts (L1-10)
```typescript
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class LoginDto {
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
```

**File:** back-end/apps/api/src/auth/auth.controller.ts (L81-88)
```typescript
  @Post('/login')
  @HttpCode(200)
  @UseGuards(LocalAuthGuard, EmailThrottlerGuard)
  @Serialize(LoginResponseDto)
  async login(@GetUser() user: User) {
    const accessToken = await this.authService.login(user);
    return { user, accessToken };
  }
```

**File:** back-end/apps/api/src/users/users.service.ts (L50-74)
```typescript
  async getVerifiedUser(email: string, password: string): Promise<User> {
    let user: User;

    try {
      user = await this.getUser({ email });
    } catch {
      throw new InternalServerErrorException('Failed to retrieve user.');
    }

    if (!user) {
      throw new UnauthorizedException('Please check your login credentials');
    }

    const { correct, isBcrypt } = await this.dualCompareHash(password, user.password);

    if (!correct) {
      throw new UnauthorizedException('Please check your login credentials');
    }

    if (isBcrypt) {
      await this.setPassword(user, password);
    }

    return user;
  }
```

**File:** back-end/apps/api/src/users/users.service.ts (L179-183)
```typescript
  async dualCompareHash(data: string, hash: string) {
    const matchBcrypt = await bcrypt.compare(data, hash);
    const matchArgon2 = await argon2.verify(hash, data);
    return { correct: matchBcrypt || matchArgon2, isBcrypt: matchBcrypt };
  }
```

**File:** back-end/apps/api/src/auth/auth.service.ts (L168-172)
```typescript
  async dualCompareHash(data: string, hash: string) {
    const matchBcrypt = await bcrypt.compare(data, hash);
    const matchArgon2 = await argon2.verify(hash, data);
    return { correct: matchBcrypt || matchArgon2, isBcrypt: matchBcrypt };
  }
```

**File:** back-end/apps/api/src/auth/dtos/change-password.dto.ts (L1-20)
```typescript
import { IsNotEmpty, IsString, IsStrongPassword } from 'class-validator';

export class ChangePasswordDto {
  @IsString()
  @IsNotEmpty()
  oldPassword: string;

  @IsStrongPassword(
    {
      minLength: 8,
      minLowercase: 0,
      minNumbers: 0,
      minSymbols: 0,
      minUppercase: 0,
    },
    {
      message: 'Password is too weak, must contain at least 8 characters.',
    },
  )
  newPassword: string;
```
