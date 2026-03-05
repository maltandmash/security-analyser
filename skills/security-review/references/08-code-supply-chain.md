# Code & Supply Chain Security

Covers SAST, DAST, SCA, dependency pinning, container image scanning, signed commits, and SBOM.

---

## 1. SAST (Static Application Security Testing)

SAST analyses source code without executing it, finding vulnerabilities during development and CI.

### Semgrep — Universal SAST

```yaml
# .github/workflows/sast.yml
name: SAST

on: [pull_request, push]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep
    steps:
      - uses: actions/checkout@v4
      - run: semgrep scan --config=p/owasp-top-ten --config=p/jwt --config=p/secrets --error
        # --error: exit code 1 if findings above threshold → blocks PR merge
```

### CodeQL (GitHub Advanced Security)

```yaml
# .github/workflows/codeql.yml
name: CodeQL

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: javascript, python  # add your languages
          queries: security-extended     # broader ruleset
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
        with:
          category: /language:javascript
```

### Language-specific tools

| Language | Tool | Key rules |
|----------|------|-----------|
| JavaScript/TypeScript | eslint-plugin-security, eslint-plugin-no-secrets | eval, RegExp injection, hardcoded secrets |
| Python | Bandit | subprocess shell=True, hardcoded passwords, SQL injection |
| Python | pylint-secure-coding-standard | — |
| Java | SpotBugs + Find Security Bugs | SQL injection, XXE, deserialisation |
| Go | gosec | SQL injection, command injection, weak crypto |

```bash
# Bandit for Python
pip install bandit
bandit -r ./src -ll  # report medium and high severity only

# ESLint security for TypeScript
npx eslint --plugin security --rule 'security/detect-eval-with-expression: error' src/
```

SAST checklist:
- [ ] SAST runs on every PR — findings block merge at HIGH/CRITICAL threshold
- [ ] SAST also runs on the default branch on schedule (catches rule updates)
- [ ] Language-specific tools configured in addition to universal tools
- [ ] Suppressed findings have documented justification in code comments

---

## 2. DAST (Dynamic Application Security Testing)

DAST tests the running application by simulating attacker inputs. Run against a staging environment.

### OWASP ZAP in CI

```yaml
# .github/workflows/dast.yml
name: DAST

on:
  push:
    branches: [main]

jobs:
  zap:
    runs-on: ubuntu-latest
    steps:
      - name: ZAP Full Scan
        uses: zaproxy/action-full-scan@v0.10.0
        with:
          target: 'https://staging.example.com'
          rules_file_name: .zap/rules.tsv  # configure false-positive suppression
          cmd_options: '-a'  # include ajax spider
```

### Nuclei — Template-based scanning

```bash
# Scan for OWASP Top 10
nuclei -u https://staging.example.com -t ~/nuclei-templates/vulnerabilities/ -severity high,critical

# Focus on authentication issues
nuclei -u https://staging.example.com -t ~/nuclei-templates/vulnerabilities/auth/ -severity medium,high,critical
```

DAST checklist:
- [ ] DAST runs against staging after every deploy to staging
- [ ] Authentication configured so DAST can test authenticated endpoints
- [ ] False positives suppressed with documented rules
- [ ] DAST results reviewed by a human — automated block only for verified CRITICAL findings

---

## 3. SCA (Software Composition Analysis)

SCA audits third-party dependencies for known CVEs and licence compliance.

### Dependabot

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
    open-pull-requests-limit: 10
    groups:
      dev-dependencies:
        patterns: ["*"]
        update-types: ["minor", "patch"]
    ignore:
      - dependency-name: "*"
        update-types: ["version-update:semver-major"]  # review majors manually

  - package-ecosystem: pip
    directory: /
    schedule:
      interval: weekly
```

### Snyk in CI

```yaml
- name: Snyk dependency scan
  uses: snyk/actions/node@master
  with:
    args: --severity-threshold=high --fail-on=all
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
```

### npm audit in CI (no token required)

```yaml
- name: npm audit
  run: |
    npm audit --audit-level=high
    # Fail build if high or critical vulnerabilities exist
```

```bash
# Manual audit
npm audit --json | jq '.vulnerabilities | to_entries[] | select(.value.severity == "critical" or .value.severity == "high")'

# Python
pip-audit --desc --format json

# Go
govulncheck ./...
```

Licence compliance:
```bash
# Check for GPL/AGPL contamination in a commercial project
npx license-checker --onlyAllow 'MIT;ISC;Apache-2.0;BSD-2-Clause;BSD-3-Clause;CC0-1.0' --failOn 'GPL;AGPL'
```

---

## 4. Dependency Pinning

Pin exact versions to prevent silent supply chain changes from breaking production or introducing malicious code.

❌ NEVER:
```json
// package.json — unpinned ranges can silently pull malicious patch versions
{
  "dependencies": {
    "express": "*",
    "lodash": "^4.0.0"  // any 4.x.y — attacker can compromise 4.1.x after you lock
  }
}
```

✅ ALWAYS:
- Commit `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` to git
- Use `npm ci` (not `npm install`) in CI — respects lockfile exactly

```yaml
- name: Install dependencies
  run: npm ci  # not npm install — CI mode uses lockfile
```

```bash
# Python — pin exact versions in requirements.txt
pip freeze > requirements.txt
# Or use Poetry with poetry.lock committed

# Go — go.sum committed to git; go mod verify in CI
go mod verify
```

---

## 5. Container Image Scanning

Scan Docker images for OS-level CVEs and secrets baked into layers.

### Trivy in CI

```yaml
- name: Build image
  run: docker build -t myapp:${{ github.sha }} .

- name: Scan with Trivy
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'myapp:${{ github.sha }}'
    format: 'table'
    exit-code: '1'          # fail build on findings
    severity: 'HIGH,CRITICAL'
    ignore-unfixed: true    # skip if no patch available

- name: Push to ECR
  if: success()             # only push if scan passed
  run: ...
```

### Dockerfile hardening

```dockerfile
# Use minimal base image — fewer packages = smaller attack surface
FROM node:20-alpine AS base

# Run as non-root user
RUN addgroup -g 1001 -S appgroup && adduser -S appuser -G appgroup -u 1001

# Multi-stage build — don't include dev dependencies in production image
FROM base AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM base AS production
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules

USER appuser  # run as non-root

EXPOSE 3000
CMD ["node", "dist/index.js"]
```

❌ NEVER:
```dockerfile
FROM node:latest        # unpinned — changes silently
USER root               # running as root in container
RUN apt-get install -y build-essential  # heavy base image in final stage
COPY . .                # copies .env and other secrets into image
```

Container checklist:
- [ ] Images scanned with Trivy before push to registry
- [ ] Base images are pinned to specific digest (not just tag)
- [ ] Final image runs as non-root user
- [ ] No secrets in image layers — verify with `docker history --no-trunc`
- [ ] Multi-stage build used — dev dependencies not in production image
- [ ] AWS ECR enhanced scanning enabled (auto-scans on push)

---

## 6. Signed Commits & Code Signing

### GPG Commit Signing

```bash
# Generate GPG key
gpg --full-generate-key  # RSA 4096-bit

# Configure git
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true

# Verify signed commits
git log --show-signature -1
```

GitHub branch protection — require signed commits:
```hcl
resource "github_branch_protection" "main" {
  repository_id  = github_repository.app.node_id
  pattern        = "main"

  require_signed_commits = true
  required_status_checks {
    strict   = true
    contexts = ["ci/tests", "sast", "dependency-scan"]
  }
  required_pull_request_reviews {
    required_approving_review_count = 2
    dismiss_stale_reviews           = true
  }
}
```

### Container Image Signing (Sigstore/Cosign)

```bash
# Sign image after push
cosign sign --key cosign.key myregistry.io/myapp:$DIGEST

# Verify before deployment
cosign verify --key cosign.pub myregistry.io/myapp:$DIGEST

# Keyless signing using OIDC (GitHub Actions)
- name: Sign image
  run: cosign sign --yes myregistry.io/myapp:${{ github.sha }}
  env:
    COSIGN_EXPERIMENTAL: 1  # keyless via Sigstore Rekor transparency log
```

---

## 7. SBOM (Software Bill of Materials)

An SBOM is a formal inventory of all components in a software build. Required for vulnerability tracking, licence auditing, and incident response.

```bash
# Generate SBOM with syft (CycloneDX format)
syft myapp:latest -o cyclonedx-json > sbom.json

# Or from source code
syft dir:. -o cyclonedx-json > sbom.json

# SPDX format
syft myapp:latest -o spdx-json > sbom.spdx.json

# Scan SBOM for vulnerabilities with grype
grype sbom:./sbom.json --fail-on high
```

GitHub Actions — generate and attest SBOM:
```yaml
- name: Generate SBOM
  uses: anchore/sbom-action@v0
  with:
    image: myregistry.io/myapp:${{ github.sha }}
    format: cyclonedx-json
    output-file: sbom.cyclonedx.json
    upload-artifact: true
    upload-artifact-retention: 30
```

SBOM checklist:
- [ ] SBOM generated for every production image/release
- [ ] SBOM stored alongside release artifacts (GitHub Release, ECR image attestation)
- [ ] SBOM scanned with grype or OWASP Dependency-Track after generation
- [ ] SBOM available to security team for incident response (can identify affected versions quickly)
