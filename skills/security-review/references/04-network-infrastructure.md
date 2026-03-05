# Network & Infrastructure Security

Covers firewall rules, VPC architecture, mTLS, zero trust networking, IP allowlisting, WAF, and DDoS protection.

---

## 1. Firewall Rules / Security Groups

Default posture: deny all ingress, allow only explicitly defined traffic.

### AWS Security Groups — Review Checklist

| Port / Protocol | Allowed source | Risk if open to 0.0.0.0/0 |
|----------------|---------------|--------------------------|
| 22 (SSH) | Bastion/VPN IP only | Remote code execution |
| 3389 (RDP) | Bastion/VPN IP only | Remote takeover |
| 5432 (Postgres) | App server SG only | Direct DB access, data theft |
| 3306 (MySQL) | App server SG only | Direct DB access |
| 6379 (Redis) | App server SG only | Cache poisoning, data theft |
| 27017 (MongoDB) | App server SG only | Data theft |
| 443 (HTTPS) | 0.0.0.0/0 | Intentional — public web |
| 80 (HTTP) | Load balancer only | Redirect to 443 |

❌ NEVER:
```hcl
# Terraform — security group open to world on database port
resource "aws_security_group_rule" "db_ingress" {
  type        = "ingress"
  from_port   = 5432
  to_port     = 5432
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # CRITICAL: database exposed to internet
}
```

✅ ALWAYS:
```hcl
# Only allow traffic from the application server security group
resource "aws_security_group_rule" "db_from_app" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.app.id  # only app servers
  security_group_id        = aws_security_group.db.id
}
```

Egress: restrict outbound traffic from databases and internal services — they should not be able to initiate connections to arbitrary internet hosts.

---

## 2. VPC / Private Networking

Architecture principle: databases, caches, and internal services must never be in public subnets.

```
Internet → CloudFront/ALB (public subnet)
         → Application servers (private subnet)
         → Database / Cache (private subnet, no route to internet)
```

Key requirements:
- **Databases in private subnets** — no public IP, no internet gateway route
- **No direct SSH to production** — use AWS Systems Manager Session Manager or a bastion in a restricted subnet
- **VPC endpoints** for AWS services (S3, Secrets Manager, SQS) — traffic stays within AWS network, no internet routing
- **Flow logs enabled** — VPC Flow Logs to CloudWatch for network visibility

```hcl
# Ensure database subnet has no route to internet gateway
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  # No route to igw — only NAT gateway for outbound (if needed)
  tags = { Name = "private-rt" }
}

# VPC endpoint for Secrets Manager — no internet egress needed
resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}
```

---

## 3. mTLS (Mutual TLS)

mTLS requires both client and server to present certificates, providing strong service-to-service authentication.

Use cases:
- Service mesh internal communication (Istio, Linkerd)
- Client certificates for high-value API integrations
- Zero-trust architectures where services must prove their identity

```yaml
# Istio mTLS policy — require mTLS for all services in namespace
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT  # reject plaintext; never use PERMISSIVE in production
```

```typescript
// Node.js server requiring client certificate
import https from 'https'
import fs from 'fs'

const server = https.createServer({
  key: fs.readFileSync(process.env.SERVER_KEY_PATH!),
  cert: fs.readFileSync(process.env.SERVER_CERT_PATH!),
  ca: fs.readFileSync(process.env.CA_CERT_PATH!),
  requestCert: true,    // require client certificate
  rejectUnauthorized: true,  // reject if cert is invalid or missing
}, app)

// Verify client identity in middleware
app.use((req: any, res, next) => {
  const cert = req.socket.getPeerCertificate()
  if (!cert.subject) {
    return res.status(401).json({ error: 'Client certificate required' })
  }
  const allowedCNs = process.env.ALLOWED_CLIENT_CNS?.split(',') ?? []
  if (!allowedCNs.includes(cert.subject.CN)) {
    return res.status(403).json({ error: 'Untrusted client certificate' })
  }
  next()
})
```

Certificate management:
- Use cert-manager (Kubernetes) for automated certificate rotation
- Set certificate expiry to 90 days maximum — automate renewal
- Store CA private key offline or in HSM

---

## 4. Zero Trust Networking

Zero trust: never trust implicitly based on network location. Verify every request regardless of whether it comes from inside or outside the corporate network.

Principles:
1. **Verify explicitly** — authenticate and authorise every request using all available data points
2. **Least privilege access** — limit access with just-in-time and just-enough-access
3. **Assume breach** — minimise blast radius, encrypt everything in transit, use analytics to detect threats

Implementation options:
- **Cloudflare Access** — identity-aware proxy for internal tools; no VPN needed
- **AWS Verified Access** — access internal apps without VPN, validates identity on every request
- **BeyondCorp Enterprise** (Google) — context-aware access based on device state + identity
- **Teleport** — unified access for SSH, Kubernetes, databases, web apps with audit trail

```yaml
# Cloudflare Access — protect an internal admin panel
# Configured via Cloudflare dashboard or Terraform:
resource "cloudflare_access_application" "admin" {
  zone_id          = var.cloudflare_zone_id
  name             = "Admin Panel"
  domain           = "admin.internal.example.com"
  session_duration = "4h"
}

resource "cloudflare_access_policy" "admin_policy" {
  application_id = cloudflare_access_application.admin.id
  zone_id        = var.cloudflare_zone_id
  name           = "Engineering team only"
  precedence     = 1
  decision       = "allow"

  include {
    email_domain = ["example.com"]
    group        = [var.engineering_group_id]
  }
}
```

---

## 5. IP Allowlisting

Restrict access to known, trusted IP ranges for admin panels, internal APIs, CI/CD webhook endpoints, and database administration interfaces.

```typescript
// Express IP allowlist middleware
const ALLOWED_IPS = process.env.ADMIN_ALLOWLIST_IPS?.split(',') ?? []

export function ipAllowlist(req: Request, res: Response, next: NextFunction) {
  const clientIp = req.ip ?? req.socket.remoteAddress ?? ''
  // Handle X-Forwarded-For from load balancer
  const forwardedFor = req.headers['x-forwarded-for'] as string
  const realIp = forwardedFor ? forwardedFor.split(',')[0].trim() : clientIp

  if (!ALLOWED_IPS.includes(realIp)) {
    return res.status(403).json({ error: 'Access denied' })
  }
  next()
}

app.use('/admin', ipAllowlist, requireAuth, requireRole('admin'), adminRouter)
```

Warning: `X-Forwarded-For` can be spoofed if not set by a trusted proxy. Only trust this header when the ALB/reverse proxy is configured to always overwrite it.

---

## 6. WAF (Web Application Firewall)

A WAF filters malicious HTTP traffic before it reaches the application.

### AWS WAF

```hcl
resource "aws_wafv2_web_acl" "main" {
  name  = "production-waf"
  scope = "REGIONAL"

  default_action { allow {} }

  # Enable AWS managed rules
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSet"
    }
  }

  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 2
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLiRuleSet"
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "ProductionWAF"
  }
}
```

WAF checklist:
- [ ] WAF in **BLOCK** mode, not just COUNT/detection mode
- [ ] AWS Managed Rules: CommonRuleSet, SQLiRuleSet, KnownBadInputsRuleSet enabled
- [ ] WAF logs forwarded to SIEM
- [ ] Bot control rules enabled for public-facing APIs
- [ ] Rate-based rules as secondary DDoS layer

---

## 7. DDoS Protection

### Network Layer (L3/L4)

- **AWS Shield Standard** — automatically included, protects against volumetric attacks
- **AWS Shield Advanced** — for critical workloads; provides 24/7 DRT access, cost protection, attack diagnostics
- **Cloudflare** — anycast network absorbs volumetric attacks at the edge

### Application Layer (L7)

```typescript
// Application-layer DDoS mitigation: Cloudflare Turnstile for high-volume endpoints
// Server-side validation of Cloudflare Turnstile token
async function validateTurnstileToken(token: string, ip: string): Promise<boolean> {
  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      secret: process.env.TURNSTILE_SECRET_KEY,
      response: token,
      remoteip: ip,
    }),
  })
  const result = await response.json()
  return result.success === true
}
```

Checklist:
- [ ] CloudFront or Cloudflare in front of all public endpoints — absorbs volumetric attacks
- [ ] AWS Shield Standard active (automatic for all AWS resources behind CloudFront/ALB/Route 53)
- [ ] WAF rate-based rules as secondary L7 protection
- [ ] CAPTCHA/Turnstile on login and registration flows
- [ ] Auto-scaling configured — application scales before it falls over under load
