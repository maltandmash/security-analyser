# Secrets & Configuration Security

Covers secrets managers, environment variable security, encrypted config stores, and secret scanning.

---

## 1. Secrets Managers

### HashiCorp Vault

Vault provides centralised secret storage with dynamic secrets, lease management, and a full audit trail.

Key features to verify:
- **Dynamic secrets** — Vault generates short-lived DB credentials on demand; no long-lived passwords
- **Leases** — secrets automatically expire; applications must renew or get new credentials
- **Audit logging** — every read/write of a secret is logged to an immutable audit device
- **Policies** — fine-grained access control per secret path, per AppRole/Kubernetes service account

```typescript
// Reading a secret from Vault at runtime
import vault from 'node-vault'

const client = vault({
  apiVersion: 'v1',
  endpoint: process.env.VAULT_ADDR,
  token: process.env.VAULT_TOKEN,  // in production: use AppRole or Kubernetes auth, not static token
})

async function getSecret(path: string): Promise<Record<string, string>> {
  const result = await client.read(`secret/data/${path}`)
  return result.data.data
}

// At startup — inject into process, never re-read in request handlers
const dbCreds = await getSecret('myapp/database')
const pool = new Pool({
  host: dbCreds.host,
  password: dbCreds.password,
  user: dbCreds.username,
})
```

```python
import hvac

def get_vault_secret(path: str) -> dict:
    client = hvac.Client(url=settings.VAULT_ADDR, token=settings.VAULT_TOKEN)
    response = client.secrets.kv.v2.read_secret_version(path=path)
    return response["data"]["data"]

# Load at startup
db_creds = get_vault_secret("myapp/database")
```

Production Vault setup checklist:
- [ ] Static root token is not used in production — use AppRole, Kubernetes auth, or AWS IAM auth
- [ ] Vault is in HA mode with auto-unseal (AWS KMS or Azure Key Vault)
- [ ] Audit log device configured (file or syslog)
- [ ] Secret leases are short (database: 1 hour, tokens: 15 minutes)
- [ ] Dynamic database credentials configured — no static DB passwords

### AWS Secrets Manager

```typescript
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager'

const client = new SecretsManagerClient({ region: process.env.AWS_REGION })

async function getSecret(secretName: string): Promise<string> {
  const command = new GetSecretValueCommand({ SecretId: secretName })
  const response = await client.send(command)
  return response.SecretString!
}

// Parse JSON secrets
const dbConfig = JSON.parse(await getSecret('prod/myapp/database'))
```

```python
import boto3
import json

def get_aws_secret(secret_name: str) -> dict:
    client = boto3.client("secretsmanager", region_name=settings.AWS_REGION)
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])
```

AWS Secrets Manager checklist:
- [ ] Automatic rotation enabled for all database credentials (30-day default)
- [ ] Resource policy restricts access to specific IAM roles/accounts
- [ ] VPC endpoint configured — no internet egress needed to access secrets
- [ ] CloudTrail logs all `GetSecretValue` calls

---

## 2. Environment Variable Security

❌ NEVER:
```typescript
// Secrets in source code
const apiKey = 'sk-prod-xxxxxxxxxxxxxxxx'
const dbPassword = 'supersecret123'

// Secrets in .env committed to git
// (even if .env is in .gitignore, .env.example with real values is common mistake)
```

```bash
# .env.example with real credentials (this gets committed)
DATABASE_URL=postgres://admin:realpassword@prod-db.example.com/myapp
STRIPE_SECRET_KEY=sk_live_xxxxxxxx
```

✅ ALWAYS:
```bash
# .env.example with placeholder values only
DATABASE_URL=postgres://user:password@localhost:5432/myapp_dev
STRIPE_SECRET_KEY=sk_test_your_stripe_test_key_here
OPENAI_API_KEY=your_openai_key_here
```

```typescript
// Validate all required env vars at startup — fail fast if missing
const requiredEnvVars = [
  'DATABASE_URL',
  'JWT_SECRET',
  'STRIPE_SECRET_KEY',
  'NEXTAUTH_SECRET',
]

for (const varName of requiredEnvVars) {
  if (!process.env[varName]) {
    throw new Error(`Missing required environment variable: ${varName}`)
  }
}
```

Prevent secrets from appearing in logs:
```typescript
// Redact sensitive keys from any object before logging
function redactSecrets(obj: Record<string, unknown>): Record<string, unknown> {
  const sensitiveKeys = /password|secret|token|key|credential|auth/i
  return Object.fromEntries(
    Object.entries(obj).map(([k, v]) => [
      k,
      sensitiveKeys.test(k) ? '[REDACTED]' : v,
    ])
  )
}

logger.info('Config loaded', redactSecrets(process.env as any))
```

---

## 3. Encrypted Config Stores

For configuration that is not secret but must be protected at rest:

- **AWS Parameter Store (SecureString)** — KMS-encrypted, IAM-controlled, versioned
- **Azure Key Vault** — secrets, keys, and certificates in one store
- **GCP Secret Manager** — auto-replication, IAM-based access, audit logging

```typescript
// AWS Parameter Store
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm'

const ssm = new SSMClient({ region: process.env.AWS_REGION })

async function getParameter(name: string): Promise<string> {
  const cmd = new GetParameterCommand({ Name: name, WithDecryption: true })
  const response = await ssm.send(cmd)
  return response.Parameter!.Value!
}
```

---

## 4. Secret Scanning

Prevent secrets from being committed to source control. Run scanning in CI and as a pre-commit hook.

### GitHub Actions — truffleHog scan on every PR

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scanning

on: [pull_request, push]

jobs:
  trufflehog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # full history for thorough scan

      - name: TruffleHog OSS
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
          extra_args: --debug --only-verified
```

### gitleaks pre-commit hook

```bash
# Install gitleaks
brew install gitleaks

# Add pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/sh
gitleaks protect --staged --redact --verbose
if [ $? -ne 0 ]; then
  echo "Secrets detected. Commit blocked."
  exit 1
fi
EOF
chmod +x .git/hooks/pre-commit
```

### Scan git history for historical secrets

```bash
# Scan entire git history (run once on existing repos)
trufflehog git file://. --since-commit HEAD --only-verified

# gitleaks on full history
gitleaks detect --source . --report-format json --report-path gitleaks-report.json
```

### GitHub Advanced Security — Enable Push Protection

In GitHub repository settings → Code security and analysis:
- Enable "Secret scanning"
- Enable "Push protection" — blocks pushes containing detected secrets

Checklist:
- [ ] `.gitignore` includes `.env`, `.env.local`, `.env.production`, `*.pem`, `*.key`, `credentials.json`
- [ ] truffleHog or gitleaks runs in CI on every PR — blocks merge if secrets detected
- [ ] gitleaks pre-commit hook installed for all developers
- [ ] GitHub Advanced Security push protection enabled
- [ ] Full git history scan completed and any findings remediated (rotate exposed secrets)
- [ ] Docker images scanned for secrets baked into layers (`docker history` + truffleHog)
- [ ] Secrets rotation documented — who to contact and what to rotate if a leak is detected
