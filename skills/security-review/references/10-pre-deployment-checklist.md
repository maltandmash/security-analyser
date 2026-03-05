# Pre-Deployment Security Checklist

**Gate rule:** Any `[CRITICAL]` item unchecked = **NO-GO**. Any `[HIGH]` item unchecked = requires a documented exception with owner name and remediation date before go-live.

Complete this checklist before every production deployment. Sign off at the bottom when done.

---

## 1. Identity & Access

- [ ] `[CRITICAL]` Passwords are hashed with Argon2id (≥64MiB/3 iterations) or bcrypt (≥12 rounds) — never MD5, SHA-1, or plaintext
- [ ] `[CRITICAL]` JWT algorithm is explicitly allowlisted (RS256 or ES256) — `alg: none` cannot be accepted
- [ ] `[CRITICAL]` JWT `aud` and `iss` claims validated on every token verification
- [ ] `[CRITICAL]` Admin accounts enforce MFA at the identity provider level
- [ ] `[HIGH]` Access tokens expire within 15 minutes
- [ ] `[HIGH]` Refresh tokens rotate on every use and are revocable server-side
- [ ] `[HIGH]` Tokens stored in `httpOnly; Secure; SameSite=Strict` cookies — not localStorage
- [ ] `[HIGH]` Sessions fully invalidated on password change and logout
- [ ] `[HIGH]` OAuth `state` parameter validated before code exchange (CSRF protection)
- [ ] `[HIGH]` PKCE implemented for all public OAuth clients (SPAs, mobile)
- [ ] `[MEDIUM]` API keys have defined scopes — no "full access" keys to external services
- [ ] `[MEDIUM]` API keys have expiry dates (≤90 days) and rotation is automated

---

## 2. Data Access Controls

- [ ] `[CRITICAL]` Row-Level Security enabled (`ENABLE` + `FORCE`) on every table containing user data
- [ ] `[CRITICAL]` No table has a default-allow RLS policy (missing policy = deny all access)
- [ ] `[HIGH]` Column-level grants restrict access to PII/sensitive columns by role
- [ ] `[HIGH]` Application database user cannot SELECT columns it does not need
- [ ] `[HIGH]` ORM queries use explicit column selection — no `SELECT *` returned to API responses
- [ ] `[HIGH]` ABAC policies tested by impersonating each role in staging
- [ ] `[MEDIUM]` Field masking applied to PII visible to support/analyst roles
- [ ] `[MEDIUM]` Dynamic Data Masking (DDM) configured for columns that must never be returned in full

---

## 3. Application Layer

- [ ] `[CRITICAL]` Every API endpoint that accepts a resource ID by path/query param verifies ownership (IDOR check)
- [ ] `[CRITICAL]` Every endpoint validates and sanitises all user input with a typed schema (Zod, Pydantic)
- [ ] `[CRITICAL]` All database queries use parameterised statements — no string concatenation in SQL
- [ ] `[CRITICAL]` No `eval()`, `exec()`, or equivalent on user-controlled input
- [ ] `[HIGH]` Function-level authorisation applied to every privileged handler — not just route-level
- [ ] `[HIGH]` OAuth scope validation on every endpoint
- [ ] `[HIGH]` Rate limiting on auth endpoints: login, register, forgot-password, OTP (≤10 requests/15 min per IP)
- [ ] `[HIGH]` CORS origin whitelist is explicit — no wildcard on authenticated/credentialed endpoints
- [ ] `[HIGH]` User-supplied HTML sanitised with DOMPurify before rendering
- [ ] `[HIGH]` Content Security Policy header set — `script-src` does not include `'unsafe-inline'` without nonce
- [ ] `[MEDIUM]` `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` on all responses
- [ ] `[MEDIUM]` Error responses do not expose stack traces, file paths, or internal service details to clients
- [ ] `[MEDIUM]` File uploads validated: size limit, MIME type allowlist, magic byte verification

---

## 4. Network & Infrastructure

- [ ] `[CRITICAL]` Database ports (5432, 3306, 27017, 6379) are not reachable from 0.0.0.0/0
- [ ] `[CRITICAL]` No production database or internal service has a public IP
- [ ] `[HIGH]` SSH (22) and RDP (3389) not open to 0.0.0.0/0 — admin access via SSM/bastion only
- [ ] `[HIGH]` All databases and caches are in private subnets with no internet gateway route
- [ ] `[HIGH]` WAF enabled in BLOCK mode on all public-facing load balancers/CloudFront distributions
- [ ] `[HIGH]` WAF managed rules enabled: CommonRuleSet, SQLiRuleSet, KnownBadInputsRuleSet
- [ ] `[MEDIUM]` VPC Flow Logs enabled and forwarding to SIEM
- [ ] `[MEDIUM]` CloudFront or equivalent CDN/DDoS protection in front of all public endpoints
- [ ] `[MEDIUM]` Admin interfaces restricted to IP allowlist or protected by zero-trust gateway (Cloudflare Access, etc.)

---

## 5. Secrets & Configuration

- [ ] `[CRITICAL]` No hardcoded secrets, API keys, passwords, or tokens in source code
- [ ] `[CRITICAL]` `.env` files containing real credentials are not committed to git (check `git log -p`)
- [ ] `[CRITICAL]` All production secrets stored in a secrets manager (Vault, AWS Secrets Manager, Parameter Store)
- [ ] `[HIGH]` truffleHog or gitleaks ran on full git history — no historical secret leaks detected
- [ ] `[HIGH]` Secret scanning enabled in CI — blocks PR merge on detected secrets
- [ ] `[HIGH]` GitHub Advanced Security push protection enabled (or equivalent)
- [ ] `[HIGH]` Container images scanned for secrets baked into layers (`docker history` clean)
- [ ] `[MEDIUM]` All required environment variables validated at application startup — fail fast if missing
- [ ] `[MEDIUM]` Secrets have rotation schedule documented; rotation is automated where possible

---

## 6. Cryptography

- [ ] `[CRITICAL]` Passwords hashed with Argon2id or bcrypt — not encrypted (encryption is reversible; hashing is not)
- [ ] `[CRITICAL]` TLS 1.2 minimum on all connections; RC4, DES, 3DES, export ciphers disabled
- [ ] `[CRITICAL]` No custom/home-grown encryption schemes — use AES-256-GCM or libsodium
- [ ] `[HIGH]` AES-256-GCM used for all field/file encryption — not ECB mode
- [ ] `[HIGH]` HSTS header with `max-age=31536000; includeSubDomains; preload` set on all HTTPS responses
- [ ] `[HIGH]` Encryption keys not stored in the same database as encrypted data
- [ ] `[HIGH]` KMS auto-rotation enabled for all symmetric CMKs
- [ ] `[MEDIUM]` TLS certificate expiry alarms configured at 30 days and 7 days before expiry
- [ ] `[MEDIUM]` TLS configuration tested with testssl.sh or SSL Labs — A grade minimum

---

## 7. Audit & Monitoring

- [ ] `[CRITICAL]` Audit log written synchronously before API response returns — not fire-and-forget
- [ ] `[CRITICAL]` Audit logs are append-only (S3 Object Lock, write-once table, or equivalent)
- [ ] `[HIGH]` Audit log captures: actor ID, IP, action, resource, outcome, timestamp for every sensitive operation
- [ ] `[HIGH]` Secrets, passwords, and tokens never appear in logs
- [ ] `[HIGH]` GuardDuty enabled in all AWS accounts and regions
- [ ] `[HIGH]` Alerting configured for: admin role assignment, IAM policy changes, failed login spikes
- [ ] `[HIGH]` On-call rotation configured with runbooks for each alert type
- [ ] `[MEDIUM]` SIEM receiving logs from: application, CloudTrail, VPC Flow Logs, WAF
- [ ] `[MEDIUM]` Audit logs retained for minimum 1 year; archived for 7 years

---

## 8. Code & Supply Chain

- [ ] `[CRITICAL]` SAST running in CI — PR merge blocked on HIGH/CRITICAL findings
- [ ] `[HIGH]` `npm audit` / `pip-audit` / `govulncheck` in CI — no HIGH or CRITICAL unpatched CVEs in direct dependencies
- [ ] `[HIGH]` Lockfiles (`package-lock.json`, `poetry.lock`, etc.) committed to git
- [ ] `[HIGH]` `npm ci` (not `npm install`) used in CI — respects lockfile exactly
- [ ] `[HIGH]` Container images scanned with Trivy — no HIGH/CRITICAL unfixed CVEs in production image
- [ ] `[HIGH]` Production container does not run as root user
- [ ] `[MEDIUM]` Base images pinned to specific digest (not just tag)
- [ ] `[MEDIUM]` Dependabot or equivalent configured — automatic PRs for dependency updates
- [ ] `[MEDIUM]` Branch protection requires signed commits on default branch
- [ ] `[MEDIUM]` SBOM generated and stored with release artifacts

---

## 9. Compliance & Policy

- [ ] `[CRITICAL]` EU personal data stored only in EU regions (if GDPR applies)
- [ ] `[CRITICAL]` Data Processing Agreements (DPAs) signed with all sub-processors handling personal data
- [ ] `[HIGH]` Erasure (right to be forgotten) API implemented and tested end-to-end
- [ ] `[HIGH]` Consent records stored with: user ID, purpose, status, version, timestamp, IP
- [ ] `[HIGH]` Non-essential cookies blocked until consent granted — no analytics/marketing loading pre-consent
- [ ] `[HIGH]` Application DB user has only the minimum necessary grants — no DDL in production
- [ ] `[MEDIUM]` Data retention policies documented per data class; automated enforcement running
- [ ] `[MEDIUM]` PII fields tagged in database schema/data catalog
- [ ] `[MEDIUM]` Access rights reviewed in the past 90 days — unused permissions revoked
- [ ] `[MEDIUM]` JIT/session-based production access in place — no standing admin DB access

---

## Sign-Off

| Field | Value |
|-------|-------|
| **Reviewer name** | |
| **Review date** | |
| **Application version / commit** | |
| **Environment** | Production / Staging |
| **CRITICAL items checked** | ___ / ___ |
| **HIGH items checked** | ___ / ___ (exceptions below) |
| **MEDIUM items checked** | ___ / ___ |
| **Go / No-Go decision** | ☐ GO &nbsp;&nbsp; ☐ NO-GO |

### HIGH Item Exceptions (if any)

| Item | Owner | Remediation Date | Approved By |
|------|-------|-----------------|-------------|
| | | | |
| | | | |

> A NO-GO decision blocks deployment until all CRITICAL items are resolved and all HIGH exceptions are signed off by a security lead.
