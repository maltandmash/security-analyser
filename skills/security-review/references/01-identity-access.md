# Identity & Access Controls

Covers authentication, authorisation, session management, and API key lifecycle.

---

## 1. Authentication

### OAuth 2.0 / OIDC

Verify the following in any OAuth/OIDC implementation:

- **`redirect_uri` validation** — must exactly match a registered URI; no wildcard patterns, no open redirects
- **`state` parameter** — must be a random, unguessable value tied to the session to prevent CSRF
- **PKCE for public clients** — `code_challenge` / `code_verifier` required for SPAs and mobile apps
- **`nonce` in ID tokens** — prevents replay attacks when using `response_type=id_token`
- **Audience (`aud`) check** — validate the token was issued for your specific application
- **Issuer (`iss`) check** — validate the token comes from the expected identity provider

❌ NEVER:
```typescript
// Accepting any redirect_uri without validation
const redirectUri = req.query.redirect_uri  // attacker-controlled redirect
await oauth.authenticate({ redirect_uri: redirectUri })

// Ignoring state parameter
const { code } = req.query  // no CSRF protection
```

✅ ALWAYS:
```typescript
// Validate state before exchanging code
const storedState = req.session.oauthState
if (req.query.state !== storedState) {
  return res.status(403).json({ error: 'Invalid state parameter' })
}

// Validate audience and issuer on every token
const payload = jwt.verify(token, publicKey, {
  algorithms: ['RS256'],
  audience: process.env.OAUTH_CLIENT_ID,
  issuer: process.env.OAUTH_ISSUER,
})
```

```python
# FastAPI with python-jose
from jose import jwt, JWTError

def verify_token(token: str):
    try:
        payload = jwt.decode(
            token,
            settings.PUBLIC_KEY,
            algorithms=["RS256"],
            audience=settings.CLIENT_ID,
            issuer=settings.ISSUER,
        )
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
```

### Multi-Factor Authentication (MFA)

- Enforce MFA for all admin and privileged accounts — not just recommended, required
- MFA must not be bypassable via account recovery flows or support escalation
- TOTP codes must be single-use and expire after 30 seconds
- WebAuthn/passkey is preferred over SMS OTP (SIM swap resistant)

Checklist:
- [ ] MFA enforced for admin roles at the IdP level (not just application level)
- [ ] TOTP tokens are invalidated after use
- [ ] Account recovery does not silently bypass MFA
- [ ] SMS OTP (if used) has rate limiting and SIM swap notification

### Password Authentication

❌ NEVER:
```typescript
// MD5, SHA-1, unsalted hashes
const hash = crypto.createHash('md5').update(password).digest('hex')

// Storing plaintext
await db.users.create({ password: password })
```

✅ ALWAYS:
```typescript
import argon2 from 'argon2'

// Hash on registration
const hash = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 65536,  // 64 MB
  timeCost: 3,
  parallelism: 4,
})

// Verify on login
const valid = await argon2.verify(storedHash, password)
if (!valid) {
  // Constant-time failure — do not reveal whether user exists
  return res.status(401).json({ error: 'Invalid credentials' })
}
```

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

# Hash
hash = ph.hash(password)

# Verify
try:
    ph.verify(stored_hash, password)
except VerifyMismatchError:
    raise HTTPException(status_code=401, detail="Invalid credentials")
```

Account lockout after N failed attempts (5 is a common default), with exponential backoff.

---

## 2. Authorisation

### Role-Based Access Control (RBAC)

- Define roles with minimum necessary permissions — avoid fat roles like "admin" that cover everything
- Store role assignments server-side; never trust a role claim from the client
- Check the role at the function/endpoint level, not just at the route level

❌ NEVER:
```typescript
// Trusting client-supplied role
const role = req.body.role  // attacker can set role = 'admin'
if (role === 'admin') { ... }
```

✅ ALWAYS:
```typescript
// Load role from verified identity on every request
export async function requireRole(role: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const userId = req.user?.id  // set by JWT middleware
    if (!userId) return res.status(401).json({ error: 'Unauthenticated' })

    const user = await db.users.findUnique({ where: { id: userId } })
    if (user?.role !== role) {
      return res.status(403).json({ error: 'Forbidden' })
    }
    next()
  }
}

// Apply per endpoint
router.delete('/users/:id', requireRole('admin'), deleteUserHandler)
```

```python
from functools import wraps
from fastapi import Depends, HTTPException

def require_role(role: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: User = Depends(get_current_user), **kwargs):
            if current_user.role != role:
                raise HTTPException(status_code=403, detail="Forbidden")
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator
```

### Attribute-Based Access Control (ABAC)

Use ABAC when role alone is insufficient (e.g. "user can edit their own posts, editors can edit any post in their department"):

```typescript
// Policy engine approach (e.g. Casbin or custom)
async function canAccess(user: User, action: string, resource: Resource): Promise<boolean> {
  // Owner can always read/write their own resources
  if (resource.ownerId === user.id) return true
  // Department editor can write within their department
  if (action === 'write' && user.role === 'editor' && resource.departmentId === user.departmentId) return true
  // Admins have full access
  if (user.role === 'admin') return true
  return false
}
```

Checklist:
- [ ] Roles are defined in server configuration, not client tokens
- [ ] Every privileged endpoint checks role/permissions independently
- [ ] Deny by default — no implicit "allow all" fallthrough
- [ ] Role assignments are audited and reviewed quarterly

---

## 3. Session Management

### Token Expiry

| Token type | Recommended TTL |
|-----------|----------------|
| Access token (JWT) | 15 minutes |
| Refresh token | 7–30 days (context-dependent) |
| API session cookie | 24 hours of inactivity |
| Password reset token | 15–60 minutes, single-use |
| Email verification token | 24 hours, single-use |

### Refresh Token Rotation

Each time a refresh token is used, issue a new one and immediately invalidate the previous. Store a hash of the refresh token server-side to enable revocation.

❌ NEVER:
```typescript
// Long-lived access tokens with no refresh rotation
const token = jwt.sign({ userId }, secret, { expiresIn: '365d' })
```

✅ ALWAYS:
```typescript
// Rotating refresh tokens with DB-backed revocation
async function refreshTokens(refreshToken: string) {
  const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex')
  const stored = await db.refreshTokens.findUnique({ where: { hash: tokenHash } })

  if (!stored || stored.revoked || stored.expiresAt < new Date()) {
    throw new Error('Invalid or expired refresh token')
  }

  // Revoke the used token
  await db.refreshTokens.update({ where: { id: stored.id }, data: { revoked: true } })

  // Issue new pair
  const newAccessToken = jwt.sign({ userId: stored.userId }, secret, { expiresIn: '15m' })
  const newRefreshToken = crypto.randomBytes(32).toString('hex')
  await db.refreshTokens.create({
    data: {
      userId: stored.userId,
      hash: crypto.createHash('sha256').update(newRefreshToken).digest('hex'),
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    }
  })

  return { accessToken: newAccessToken, refreshToken: newRefreshToken }
}
```

### Token Storage

❌ NEVER:
```typescript
// localStorage is vulnerable to XSS — any injected script can steal the token
localStorage.setItem('accessToken', token)
```

✅ ALWAYS:
```typescript
// httpOnly cookie: JS cannot read it, but it's sent automatically
res.cookie('accessToken', token, {
  httpOnly: true,
  secure: true,           // HTTPS only
  sameSite: 'strict',     // CSRF protection
  maxAge: 15 * 60 * 1000, // 15 minutes
})
```

### Session Invalidation

Sessions must be fully invalidated on:
- Logout
- Password change
- Password reset
- MFA method change
- Account suspension/deletion

Checklist:
- [ ] Access tokens expire within 15 minutes
- [ ] Refresh tokens rotate on every use
- [ ] Refresh tokens are revocable server-side
- [ ] Sessions are invalidated on password change
- [ ] Tokens stored in httpOnly cookies, not localStorage

---

## 4. API Key Management

### Scoping

Every API key must have the minimum required scopes. Never issue "full access" keys to external integrations.

```typescript
// Store API keys hashed, with scope metadata
const rawKey = `sk_live_${crypto.randomBytes(32).toString('hex')}`
const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex')

await db.apiKeys.create({
  data: {
    hash: keyHash,
    prefix: rawKey.substring(0, 12), // for identification in logs
    scopes: ['read:users', 'write:orders'],  // minimum necessary
    expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days
    createdBy: userId,
  }
})

// Return raw key ONCE — never store it
return { key: rawKey }
```

### Rotation

- API keys must have a defined expiry (90 days is a common default for service keys)
- Rotation must be automated via secrets manager where possible (HashiCorp Vault, AWS Secrets Manager)
- Old keys must be invalidated immediately on rotation, not kept as fallback

### Storage

- Never store API keys in source code, `.env` files committed to git, or plain-text config files
- Store in secrets managers with access policies and audit logs
- Log key usage with the key prefix (not the full key) for traceability

Checklist:
- [ ] All API keys have defined scopes — no "full access" keys to third parties
- [ ] Keys expire within 90 days and rotation is automated
- [ ] Keys are stored hashed in the database, raw key shown only once at creation
- [ ] Key usage is logged with prefix identifier
- [ ] Compromised keys can be revoked immediately via admin interface
