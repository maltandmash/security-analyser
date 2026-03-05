# security-analyser

A comprehensive Claude Code plugin that performs security reviews across 9 categories of developer security controls. Covers the full OWASP surface area from identity and access through to supply chain security and GDPR compliance.

## Installation

### Option 1: GitHub (once published)

```bash
/plugin install YOUR_GITHUB_USERNAME/security-analyser
```

### Option 2: Live-updating local install (recommended for development)

Clone the repo and symlink it into your Claude Code plugins directory. Changes take effect immediately — no reinstall needed after `git pull`.

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/security-analyser \
  ~/Documents/GitHub\ Repos/AI/security-analyser

ln -s ~/Documents/GitHub\ Repos/AI/security-analyser \
  ~/.claude/plugins/security-analyser
```

This is the **recommended pattern for all personal Claude Code plugins** — it means a `git pull` is all you need to update a plugin, and local edits are live immediately.

To apply this pattern to other plugins you already have locally:
```bash
ln -s /path/to/your/plugin-repo ~/.claude/plugins/plugin-name
```

## Usage

The skill activates automatically when you ask for a security review. Example trigger phrases:

| What you say | What happens |
|-------------|-------------|
| "Do a security review of this codebase" | Full context assessment across all 9 categories |
| "Review my authentication implementation" | Deep dive on Identity & Access |
| "Check my Supabase RLS policies" | Deep dive on Data Access Controls |
| "Is my JWT implementation secure?" | Focuses on token validation, algorithm, storage |
| "Check for hardcoded secrets" | Focuses on Secrets & Configuration |
| "Run through the pre-deployment checklist" | Loads the master sign-off checklist |
| "Quick security scan — just flag critical issues" | Surface-level pass, CRITICAL findings only |
| "Deep dive on cryptography" | Loads cryptography reference in full |
| "GDPR compliance check" | Focuses on Compliance & Policy |
| "Pen test prep — what should I fix?" | Full audit with prioritised remediation |

## Security Categories

| # | Category | Key Controls |
|---|----------|-------------|
| 1 | [Identity & Access](skills/security-review/references/01-identity-access.md) | Authentication (OAuth/SSO/MFA/passkeys), authorisation (RBAC/ABAC), session management, API key lifecycle |
| 2 | [Data Access Controls](skills/security-review/references/02-data-access-controls.md) | Row-level security, column-level security, object permissions, ABAC, field masking, DDM, cell-level security |
| 3 | [Application Layer](skills/security-review/references/03-application-layer.md) | Middleware auth, IDOR prevention, OAuth scope enforcement, rate limiting, input validation, XSS/output encoding |
| 4 | [Network & Infrastructure](skills/security-review/references/04-network-infrastructure.md) | Security groups, VPC/private networking, mTLS, zero trust, IP allowlisting, WAF, DDoS protection |
| 5 | [Secrets & Configuration](skills/security-review/references/05-secrets-configuration.md) | HashiCorp Vault, AWS Secrets Manager, env var security, encrypted config stores, secret scanning |
| 6 | [Cryptography](skills/security-review/references/06-cryptography.md) | Encryption at rest/in transit, E2EE, password hashing (Argon2id/bcrypt), key management, HSM |
| 7 | [Audit & Monitoring](skills/security-review/references/07-audit-monitoring.md) | Immutable audit logging, access logging, anomaly detection, SIEM integration, privilege escalation alerts |
| 8 | [Code & Supply Chain](skills/security-review/references/08-code-supply-chain.md) | SAST, DAST, SCA, dependency pinning, container scanning, signed commits, SBOM |
| 9 | [Compliance & Policy](skills/security-review/references/09-compliance-policy.md) | GDPR/data residency, data retention, consent enforcement, PII tagging, least privilege |

The skill also includes a [pre-deployment sign-off checklist](skills/security-review/references/10-pre-deployment-checklist.md) with ~65 items across all categories, each labelled CRITICAL / HIGH / MEDIUM.

## Findings Format

Every finding produced by the skill follows this structure:

```
### [SEVERITY] Finding Title

Category: Application Layer — IDOR
Location: src/routes/orders.ts:42
Description: ...
Impact: ...
Remediation: [code example]
Reference: OWASP A01:2021 / CWE-639
```

Severity levels: **CRITICAL** (fix before deployment) → **HIGH** (fix within sprint) → **MEDIUM** (plan for next quarter) → **LOW/INFO**

## Code Example Languages

Reference files include examples in:
- TypeScript / Node.js (Express, Next.js, Fastify)
- Python (FastAPI, SQLAlchemy, Pydantic)
- SQL (PostgreSQL, SQL Server, Supabase)
- Generic / infrastructure (Terraform, Docker, GitHub Actions, Nginx)

## Contributing

1. Fork the repo
2. Create a branch: `git checkout -b feat/your-improvement`
3. Follow the existing reference file structure (overview → sub-sections → ❌ NEVER → ✅ ALWAYS → checklist)
4. Submit a PR — include the security category and controls affected in the description

## License

MIT
