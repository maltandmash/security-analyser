# Audit & Monitoring

Covers immutable audit logging, access logging, anomaly detection, SIEM integration, and privilege escalation alerting.

---

## 1. Audit Logging

An audit log is an immutable, chronological record of security-relevant events. It must answer: **who** did **what**, **when**, from **where**, and did it **succeed or fail**.

### What to Log

Always log:
- Authentication events (login success, login failure, logout, MFA enrolled/removed)
- Authorisation decisions (access granted, access denied — especially denials)
- Administrative actions (user created, role changed, user deleted, config modified)
- Data access on sensitive resources (read of PII, financial records, health data)
- Data mutations (create, update, delete on sensitive tables)
- Privilege changes (role assignment, permission grant, API key created/revoked)
- Security configuration changes (firewall rules, WAF rules, secret rotation)

Never log:
- Passwords, tokens, secrets, or session IDs
- Full credit card numbers (only last 4 digits)
- Health data in raw form (reference by record ID)

### Log Schema

Use structured JSON with a consistent schema across all services:

```typescript
interface AuditEvent {
  timestamp: string       // ISO 8601, UTC
  eventId: string         // UUID — unique per event
  correlationId: string   // trace across distributed systems
  actor: {
    userId: string
    email?: string
    ipAddress: string
    userAgent: string
    sessionId: string
  }
  action: string          // "user.login", "order.delete", "role.assign"
  resource: {
    type: string          // "user", "order", "role"
    id: string
    attributes?: Record<string, unknown>  // non-sensitive metadata only
  }
  outcome: 'success' | 'failure' | 'error'
  reason?: string         // for failures: "invalid_password", "permission_denied"
  environment: string     // "production", "staging"
  service: string         // "api", "auth-service", "worker"
}
```

```typescript
// Audit log utility
import { randomUUID } from 'crypto'

async function auditLog(event: Omit<AuditEvent, 'timestamp' | 'eventId'>) {
  const entry: AuditEvent = {
    ...event,
    timestamp: new Date().toISOString(),
    eventId: randomUUID(),
  }

  // Write to append-only store — never to a mutable DB table
  await auditWriter.write(JSON.stringify(entry))
  // Also forward to SIEM in real-time
  await siemForwarder.send(entry)
}

// Usage
await auditLog({
  correlationId: req.correlationId,
  actor: { userId: req.user.id, ipAddress: req.ip, userAgent: req.headers['user-agent'], sessionId: req.session.id },
  action: 'user.role.assign',
  resource: { type: 'user', id: targetUserId, attributes: { newRole: 'admin' } },
  outcome: 'success',
  environment: process.env.NODE_ENV,
  service: 'api',
})
```

```python
import json
from datetime import datetime, timezone
from uuid import uuid4

def audit_log(actor: dict, action: str, resource: dict, outcome: str, **kwargs):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_id": str(uuid4()),
        "actor": actor,
        "action": action,
        "resource": resource,
        "outcome": outcome,
        **kwargs,
    }
    audit_writer.write(json.dumps(entry))
    siem_forwarder.send(entry)
```

### Immutability

Audit logs must be written to an append-only, tamper-evident store:

- **AWS S3 with Object Lock** — WORM (write once, read many); set Compliance mode for regulatory requirements
- **AWS CloudTrail with log file validation** — SHA-256 hash chain; integrity verifiable via `validate-logs` CLI command
- **Separate audit database** — append-only table, revoke UPDATE/DELETE grants from application user

```hcl
# S3 bucket with Object Lock for audit logs
resource "aws_s3_bucket" "audit_logs" {
  bucket = "myapp-audit-logs-${var.environment}"

  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    default_retention {
      mode = "COMPLIANCE"  # Cannot be deleted even by root account
      days = 2555          # 7 years retention
    }
  }
}
```

```sql
-- PostgreSQL: append-only audit table
-- Revoke UPDATE and DELETE from application role
REVOKE UPDATE, DELETE ON TABLE audit_log FROM app_user;

-- Enable logical replication for audit log sync to SIEM
-- (application can only INSERT)
```

---

## 2. Access Logging

Log all API and database access, including read operations.

### API Access Logs

```typescript
// Express request logging middleware
import morgan from 'morgan'

// Custom log format including user identity
morgan.token('user-id', (req: any) => req.user?.id ?? 'anonymous')
morgan.token('correlation-id', (req: any) => req.headers['x-correlation-id'] ?? '')

app.use(morgan(':date[iso] :user-id :correlation-id :method :url :status :response-time ms :res[content-length]'))
```

AWS ALB / CloudFront access logs:
- Enable ALB access logs to S3 — captures all requests including those blocked by WAF
- Enable CloudFront access logs — client IP, edge location, cache hit/miss

### Database Query Logging

```sql
-- PostgreSQL: enable query logging for audit purposes
-- In postgresql.conf:
log_min_duration_statement = 1000  -- log queries > 1 second
log_connections = on
log_disconnections = on
log_duration = off  -- use min_duration_statement instead

-- pg_audit extension for statement-level audit logging
-- In postgresql.conf:
shared_preload_libraries = 'pg_audit'
pgaudit.log = 'read, write, ddl'  -- log reads on sensitive tables
pgaudit.log_relation = on
```

---

## 3. Anomaly Detection

Automated detection of unusual patterns that may indicate a breach, account takeover, or insider threat.

### AWS GuardDuty

Enable GuardDuty in every AWS account and every region:

```hcl
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection {
      scan_ec2_instance_with_findings { ebs_volumes { enable = true } }
    }
  }
}
```

Key findings to alert on immediately:
- `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` — login from unusual country
- `Recon:IAMUser/TorIPCaller` — console access via Tor
- `PrivilegeEscalation:IAMUser/AdministrativePermissions` — unusual privilege grant
- `Exfiltration:S3/ObjectRead.Unusual` — high-volume S3 reads from unusual identity

### Application-Level Anomaly Detection

Patterns to detect and alert on:

```typescript
// Failed login spike — potential credential stuffing
async function checkFailedLoginRate(ipAddress: string): Promise<void> {
  const key = `failed_login:${ipAddress}`
  const count = await redis.incr(key)
  await redis.expire(key, 900)  // 15-minute window

  if (count === 5) {
    await alerting.send({
      severity: 'MEDIUM',
      title: 'Multiple failed logins from single IP',
      detail: `IP ${ipAddress} has failed login ${count} times in 15 minutes`,
    })
  }
  if (count >= 20) {
    await ipBlocklist.add(ipAddress, 3600)  // block for 1 hour
  }
}

// Unusual data access volume — potential data exfiltration
async function checkDataAccessVolume(userId: string, recordsAccessed: number): Promise<void> {
  const today = new Date().toISOString().slice(0, 10)
  const key = `data_access:${userId}:${today}`
  const total = await redis.incrby(key, recordsAccessed)
  await redis.expire(key, 86400)

  if (total > 10000) {
    await alerting.send({
      severity: 'HIGH',
      title: 'Unusual data access volume',
      detail: `User ${userId} has accessed ${total} records today`,
    })
  }
}
```

---

## 4. SIEM Integration

A SIEM (Security Information and Event Management) aggregates logs from all sources for correlation, alerting, and forensic investigation.

### Log Forwarding Architecture

```
Application → CloudWatch Logs
CloudTrail → CloudWatch Logs
VPC Flow Logs → CloudWatch Logs
              ↓
         Kinesis Firehose (buffered delivery)
              ↓
         SIEM (Splunk / Datadog / Elastic SIEM / AWS Security Hub)
```

```hcl
# CloudWatch → Kinesis Firehose → S3/SIEM
resource "aws_cloudwatch_log_subscription_filter" "to_siem" {
  name            = "application-logs-to-siem"
  log_group_name  = "/aws/application/api"
  filter_pattern  = ""  # forward all logs
  destination_arn = aws_kinesis_firehose_delivery_stream.siem.arn
}
```

### Correlation Rules to Configure

| Rule | Threshold | Severity |
|------|-----------|----------|
| Failed logins same user, different IPs | 10 failures in 5 min | HIGH |
| Admin login outside business hours | Any | MEDIUM |
| New IAM admin user created | Any | HIGH |
| S3 bucket policy made public | Any | CRITICAL |
| Database accessed from new IP | Any | HIGH |
| Secrets Manager secret accessed by new role | Any | HIGH |
| Multiple `GetSecretValue` calls in rapid succession | 50+ in 1 min | HIGH |

---

## 5. Alerting on Privilege Escalation

Privilege escalation is one of the highest-signal indicators of a breach or insider threat.

```typescript
// Application-level privilege change alert
async function assignRole(targetUserId: string, newRole: string, assignedBy: string) {
  const previousRole = (await db.users.findUnique({ where: { id: targetUserId } }))?.role

  await db.users.update({ where: { id: targetUserId }, data: { role: newRole } })

  await auditLog({
    actor: { userId: assignedBy, ... },
    action: 'user.role.assign',
    resource: { type: 'user', id: targetUserId, attributes: { previousRole, newRole } },
    outcome: 'success',
  })

  // Alert immediately on admin assignment
  if (newRole === 'admin') {
    await alerting.critical({
      title: 'Admin role assigned',
      detail: `User ${targetUserId} was elevated to admin by ${assignedBy}`,
      channel: '#security-alerts',
    })
  }
}
```

AWS CloudWatch alarm for IAM privilege escalation:
```hcl
resource "aws_cloudwatch_metric_alarm" "iam_policy_change" {
  alarm_name          = "iam-policy-change"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "PolicyEventCount"  # from CloudTrail metric filter
  namespace           = "CloudTrailMetrics"
  period              = 300  # 5 minutes
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
```

Checklist:
- [ ] Audit log written to append-only store before API response is sent — not async/best-effort
- [ ] Audit log schema includes timestamp, actor ID, IP, action, resource, outcome
- [ ] S3 Object Lock or equivalent immutability for audit log storage
- [ ] GuardDuty enabled in all regions and accounts
- [ ] SIEM receiving logs from: application, CloudTrail, VPC Flow Logs, WAF
- [ ] Alert rules configured for: failed login spikes, admin role assignment, IAM changes, unusual data volume
- [ ] On-call rotation with runbooks for each alert type
- [ ] Audit logs retained for minimum 1 year online, 7 years in cold storage (regulatory baseline)
