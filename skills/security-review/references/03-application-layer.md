# Application Layer Security

Covers middleware authentication, function-level authorisation, IDOR prevention, OAuth scope enforcement, rate limiting, input validation, and output encoding/XSS prevention.

---

## 1. Middleware Authentication

Every request to a protected route must validate the token before the handler runs. JWT validation must check algorithm, signature, expiry, audience, and issuer.

❌ NEVER:
```typescript
// algorithm: 'none' allows unsigned tokens
jwt.verify(token, secret, { algorithms: ['none', 'HS256'] })

// Trusting the JWT header's `kid` without a validated JWKS endpoint
const { kid } = jwt.decode(token, { complete: true }).header
const key = await fetchKey(kid)  // SSRF risk if kid is a URL
```

✅ ALWAYS:
```typescript
import jwt from 'jsonwebtoken'
import { Request, Response, NextFunction } from 'express'

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = req.cookies.accessToken  // httpOnly cookie, not Authorization header from localStorage

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' })
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_PUBLIC_KEY!, {
      algorithms: ['RS256'],    // explicit allowlist — never ['none', ...]
      audience: process.env.JWT_AUDIENCE,
      issuer: process.env.JWT_ISSUER,
    })
    req.user = payload as JWTPayload
    next()
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' })
  }
}
```

```python
from fastapi import Depends, HTTPException, Cookie
from jose import jwt, JWTError

async def get_current_user(access_token: str = Cookie(None)) -> User:
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(
            access_token,
            settings.PUBLIC_KEY,
            algorithms=["RS256"],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
        )
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        return await get_user(user_id)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
```

Checklist:
- [ ] JWT algorithm is explicitly allowlisted — `RS256` or `ES256` preferred for stateless
- [ ] `aud` and `iss` claims are validated on every token
- [ ] Tokens read from httpOnly cookies, not `Authorization: Bearer` headers sourced from localStorage
- [ ] Auth middleware applied globally; handlers opt-in to public access, not opt-out of auth

---

## 2. Function-Level Authorisation

Route-level auth is insufficient. Every function/handler that performs a privileged action must independently check that the caller has the necessary permission.

❌ NEVER:
```typescript
// Only checking auth at route level — any authenticated user can do anything
router.use('/api', requireAuth)

// Handler with no role/permission check
app.delete('/api/users/:id', async (req, res) => {
  await db.users.delete({ where: { id: req.params.id } })  // any authenticated user can delete any user
  res.json({ success: true })
})
```

✅ ALWAYS:
```typescript
app.delete('/api/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  await db.users.delete({ where: { id: req.params.id } })
  res.json({ success: true })
})

// For granular permissions, use a permissions decorator
@RequirePermission('users:delete')
async deleteUser(userId: string, currentUser: User) {
  if (!currentUser.permissions.includes('users:delete')) {
    throw new ForbiddenError()
  }
  return this.userService.delete(userId)
}
```

```python
from fastapi import Depends

@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: User = Depends(require_role("admin"))
):
    await user_service.delete(user_id)
    return {"success": True}
```

---

## 3. IDOR Prevention (Object Ownership Checks)

Insecure Direct Object Reference occurs when an endpoint accepts a resource ID and returns or modifies the resource without verifying the requester owns it.

❌ NEVER:
```typescript
// No ownership check — any authenticated user can read any order
app.get('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await db.orders.findUnique({ where: { id: req.params.id } })
  res.json(order)
})
```

✅ ALWAYS:
```typescript
// Enforce ownership at the query level
app.get('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await db.orders.findFirst({
    where: {
      id: req.params.id,
      userId: req.user.id,  // ownership enforced in query, not in application code after fetch
    }
  })

  if (!order) {
    // Return 404 not 403 — do not confirm the resource exists
    return res.status(404).json({ error: 'Not found' })
  }

  res.json(order)
})
```

```python
@router.get("/orders/{order_id}")
async def get_order(
    order_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    order = await db.execute(
        select(Order).where(Order.id == order_id, Order.user_id == current_user.id)
    )
    result = order.scalar_one_or_none()
    if not result:
        raise HTTPException(status_code=404, detail="Not found")
    return result
```

```sql
-- Always join on ownership in raw SQL
SELECT * FROM orders
WHERE id = $1
  AND user_id = $2;  -- $2 = authenticated user's ID from JWT
```

Review every endpoint that accepts an ID in path or query params — these are IDOR candidates.

Checklist:
- [ ] Every endpoint that fetches a resource by ID enforces ownership in the query
- [ ] 404 (not 403) returned when resource exists but requester doesn't own it
- [ ] Admin bypass is explicit and role-checked, not a default

---

## 4. OAuth Scope Enforcement

OAuth scopes must be verified on every endpoint, not just at token issuance.

```typescript
function requireScope(scope: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const tokenScopes: string[] = req.user?.scopes ?? []
    if (!tokenScopes.includes(scope)) {
      return res.status(403).json({ error: `Insufficient scope. Required: ${scope}` })
    }
    next()
  }
}

// Apply per endpoint
router.get('/api/users', requireAuth, requireScope('read:users'), listUsersHandler)
router.post('/api/users', requireAuth, requireScope('write:users'), createUserHandler)
```

Checklist:
- [ ] Every endpoint declares required scopes
- [ ] Scope validation is middleware/decorator-based, not inline logic per handler
- [ ] Token scopes are sourced from the verified JWT payload, not from the request body

---

## 5. Rate Limiting & Throttling

Apply rate limits to prevent brute force, credential stuffing, and abusive scraping.

```typescript
import rateLimit from 'express-rate-limit'
import RedisStore from 'rate-limit-redis'

// General API limit
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  store: new RedisStore({ client: redisClient }),
})

// Auth endpoints — much stricter
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,  // 10 attempts per 15 minutes per IP
  message: 'Too many login attempts. Please try again later.',
  store: new RedisStore({ client: redisClient }),
})

app.use('/api/', apiLimiter)
app.use('/api/auth/login', authLimiter)
app.use('/api/auth/forgot-password', authLimiter)
app.use('/api/auth/verify-otp', rateLimit({ windowMs: 5 * 60 * 1000, max: 5 }))
```

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@router.post("/auth/login")
@limiter.limit("10/15minutes")
async def login(request: Request, credentials: LoginCredentials):
    ...
```

Endpoints requiring strict rate limiting:
- `POST /auth/login` — brute force protection
- `POST /auth/register` — account creation spam
- `POST /auth/forgot-password` — user enumeration + abuse
- `POST /auth/verify-otp` — OTP brute force
- `GET /api/search` — scraping prevention
- Any LLM/AI inference endpoints — cost protection

---

## 6. Input Validation & Sanitisation

Validate all user input at the server boundary using typed schemas. Never trust client-side validation alone.

❌ NEVER:
```typescript
// Direct use of unvalidated input
app.post('/api/users', async (req, res) => {
  const { name, email, age } = req.body  // no validation
  await db.users.create({ name, email, age })
})

// String interpolation in SQL
const query = `SELECT * FROM users WHERE email = '${req.body.email}'`
```

✅ ALWAYS:
```typescript
import { z } from 'zod'

const CreateUserSchema = z.object({
  name: z.string().min(1).max(100).trim(),
  email: z.string().email().toLowerCase(),
  age: z.number().int().min(0).max(150).optional(),
  role: z.enum(['user', 'editor']),  // whitelist, never accept arbitrary role
})

app.post('/api/users', requireAuth, requireRole('admin'), async (req, res) => {
  const result = CreateUserSchema.safeParse(req.body)
  if (!result.success) {
    return res.status(400).json({ error: result.error.flatten() })
  }

  const user = await db.users.create({ data: result.data })
  res.status(201).json(user)
})
```

```python
from pydantic import BaseModel, EmailStr, validator

class CreateUserRequest(BaseModel):
    name: str
    email: EmailStr
    age: int | None = None
    role: Literal["user", "editor"]

    @validator("name")
    def name_not_empty(cls, v):
        if not v.strip():
            raise ValueError("Name cannot be empty")
        return v.strip()

@router.post("/users")
async def create_user(body: CreateUserRequest, current_user: User = Depends(require_role("admin"))):
    return await user_service.create(body)
```

File upload validation:
```typescript
function validateFileUpload(file: Express.Multer.File) {
  const MAX_SIZE = 5 * 1024 * 1024  // 5 MB

  if (file.size > MAX_SIZE) {
    throw new ValidationError('File exceeds 5MB limit')
  }

  const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf']
  if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
    throw new ValidationError('Invalid file type')
  }

  // Check magic bytes — don't trust the mimetype header
  const magicBytes = file.buffer.slice(0, 4).toString('hex')
  const MAGIC = { jpeg: 'ffd8ffe', png: '89504e47', pdf: '25504446' }
  const isValid = Object.values(MAGIC).some(m => magicBytes.startsWith(m))
  if (!isValid) {
    throw new ValidationError('File content does not match declared type')
  }
}
```

---

## 7. Output Encoding & XSS Prevention

Encode user-provided content before rendering it in HTML, JavaScript, CSS, or URLs.

❌ NEVER:
```typescript
// React: dangerouslySetInnerHTML without sanitisation
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// Direct DOM manipulation
element.innerHTML = userComment
```

✅ ALWAYS:
```typescript
import DOMPurify from 'isomorphic-dompurify'

// Sanitise before rendering as HTML
const clean = DOMPurify.sanitize(userContent, {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li'],
  ALLOWED_ATTR: [],  // no attributes — prevents event handler injection
})
<div dangerouslySetInnerHTML={{ __html: clean }} />

// React auto-escapes JSX expressions — use this where possible
<p>{userComment}</p>  // safe: React escapes special characters
```

Content Security Policy headers:
```typescript
// Next.js — add in next.config.js or middleware
const cspHeader = `
  default-src 'self';
  script-src 'self' 'nonce-${nonce}';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self' ${process.env.NEXT_PUBLIC_API_URL};
  frame-ancestors 'none';
  upgrade-insecure-requests;
`.replace(/\s{2,}/g, ' ').trim()

res.setHeader('Content-Security-Policy', cspHeader)
res.setHeader('X-Content-Type-Options', 'nosniff')
res.setHeader('X-Frame-Options', 'DENY')
res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
```

```python
# FastAPI security headers middleware
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response
```

CORS configuration:
```typescript
import cors from 'cors'

// Only allow known origins — never wildcard on authenticated routes
app.use(cors({
  origin: [process.env.APP_URL!, 'https://admin.example.com'],
  credentials: true,  // required for cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
}))
```

Checklist:
- [ ] All user-supplied HTML passes through DOMPurify before rendering
- [ ] CSP headers set on all responses — `script-src` does not include `'unsafe-inline'` without nonce/hash
- [ ] CORS origin whitelist is explicit — no wildcard on credentialed endpoints
- [ ] `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` on all responses
- [ ] Error responses do not leak stack traces or internal paths to clients
