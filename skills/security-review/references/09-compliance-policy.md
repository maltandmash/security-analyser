# Compliance & Policy Controls

Covers GDPR/data residency, data retention, consent enforcement, PII tagging, and least privilege.

---

## 1. GDPR & Data Residency

### Data Residency

EU personal data must be processed and stored within the EU or in countries with an adequacy decision unless a valid transfer mechanism exists.

| AWS Regions (EU) | Location |
|-----------------|----------|
| eu-west-1 | Ireland |
| eu-west-2 | London |
| eu-west-3 | Paris |
| eu-central-1 | Frankfurt |
| eu-central-2 | Zurich |
| eu-north-1 | Stockholm |
| eu-south-1 | Milan |

Infrastructure checklist:
- [ ] Database (RDS/Aurora) deployed in EU region for EU users
- [ ] S3 bucket with user data in EU region; bucket policy blocks replication to non-EU regions
- [ ] CDN distribution does not cache PII responses (Cache-Control: no-store on user data endpoints)
- [ ] Sub-processors (third-party APIs) have signed DPAs and are GDPR-compliant

```hcl
# Terraform: restrict S3 replication to EU regions only
resource "aws_s3_bucket_replication_configuration" "eu_only" {
  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.user_data.id

  rule {
    id     = "eu-replication"
    status = "Enabled"
    destination {
      bucket        = aws_s3_bucket.user_data_backup.arn
      storage_class = "STANDARD_IA"
      # Destination must also be an EU region
    }
  }
}
```

### Cross-Border Transfers

If data must leave the EU:
- **Adequacy decisions**: USA (Data Privacy Framework), UK, Switzerland, Japan, South Korea — transfers allowed without additional mechanisms
- **Standard Contractual Clauses (SCCs)**: use 2021 SCCs for all other third-country transfers; document in data processing register

### Right to Erasure (Article 17)

```typescript
// Erasure service — hard delete vs pseudonymisation
async function eraseUser(userId: string): Promise<void> {
  // Option A: Hard delete (simpler, may break audit log referential integrity)
  await db.transaction(async (tx) => {
    await tx.userProfiles.delete({ where: { userId } })
    await tx.orders.updateMany({
      where: { userId },
      data: { userId: null, customerEmail: '[deleted]', customerName: '[deleted]' }
    })
    await tx.users.delete({ where: { id: userId } })
  })

  // Option B: Pseudonymisation (preserves audit trail integrity)
  const pseudoId = `deleted_${randomUUID()}`
  await db.users.update({
    where: { id: userId },
    data: {
      email: `${pseudoId}@deleted.invalid`,
      name: '[deleted]',
      phone: null,
      dateDeleted: new Date(),
      erasureRequestId: erasureRequestId,
    }
  })

  // Purge from search indexes, caches, CDN
  await searchIndex.delete(userId)
  await redis.del(`user:${userId}:*`)
}
```

Data subject access request (DSAR) handling:
- Must respond within 30 days
- Provide all personal data held, in portable format
- Log the request and response in the audit trail

---

## 2. Data Retention Policies

Define and automate retention periods per data class.

| Data class | Retention period | Basis |
|-----------|-----------------|-------|
| User account data | Duration of account + 30 days | Contractual |
| Transaction records | 7 years | Financial regulation |
| Communication logs | 2 years | Legitimate interest |
| Audit logs | 7 years | Regulatory (PCI, SOX) |
| Marketing consent records | Until withdrawal + 3 years | GDPR accountability |
| Session/access logs | 90 days | Security monitoring |
| Backup data | 30–90 days | Operational |

```typescript
// Automated retention enforcement via scheduled job
async function enforceRetention(): Promise<void> {
  const cutoffDate = new Date()
  cutoffDate.setDate(cutoffDate.getDate() - 90)

  // Delete old session logs
  await db.accessLogs.deleteMany({
    where: { createdAt: { lt: cutoffDate } }
  })

  // Anonymise old marketing records
  const marketingCutoff = new Date()
  marketingCutoff.setFullYear(marketingCutoff.getFullYear() - 3)
  await db.marketingEvents.updateMany({
    where: { createdAt: { lt: marketingCutoff } },
    data: { userId: null, email: '[anonymised]' }
  })

  logger.info('Retention enforcement completed', { cutoffDate: cutoffDate.toISOString() })
}
```

```sql
-- PostgreSQL: TTL-style retention with a scheduled cron
DELETE FROM access_logs WHERE created_at < NOW() - INTERVAL '90 days';
DELETE FROM email_tracking WHERE created_at < NOW() - INTERVAL '2 years';
```

AWS S3 lifecycle rules:
```hcl
resource "aws_s3_bucket_lifecycle_configuration" "logs_lifecycle" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "access-log-retention"
    status = "Enabled"

    expiration { days = 90 }

    noncurrent_version_expiration { noncurrent_days = 30 }
  }
}
```

Checklist:
- [ ] Retention policy documented per data class with legal basis
- [ ] Automated deletion job runs daily; failures alert on-call
- [ ] Backups covered by retention policy — old backups deleted
- [ ] Retention enforcement tested annually by sampling purged records

---

## 3. Consent Enforcement

### Recording Consent

```typescript
// Store consent with full audit trail
interface ConsentRecord {
  id: string
  userId: string
  purpose: 'marketing' | 'analytics' | 'functional'
  status: 'granted' | 'withdrawn'
  version: string          // version of privacy policy/consent notice
  timestamp: Date
  ipAddress: string
  userAgent: string
  channel: 'web' | 'mobile' | 'api'
}

async function recordConsent(
  userId: string,
  purpose: ConsentRecord['purpose'],
  status: ConsentRecord['status'],
  context: { ip: string; userAgent: string; channel: ConsentRecord['channel'] }
): Promise<void> {
  await db.consentRecords.create({
    data: {
      userId,
      purpose,
      status,
      version: process.env.PRIVACY_POLICY_VERSION!,
      timestamp: new Date(),
      ipAddress: context.ip,
      userAgent: context.userAgent,
      channel: context.channel,
    }
  })
}
```

### Gating Processing on Consent

```typescript
// Check consent before processing
async function sendMarketingEmail(userId: string, email: MarketingEmail): Promise<void> {
  const consent = await db.consentRecords.findFirst({
    where: {
      userId,
      purpose: 'marketing',
      status: 'granted',
    },
    orderBy: { timestamp: 'desc' }
  })

  if (!consent) {
    logger.info('Marketing email suppressed: no consent', { userId })
    return  // silently skip — do not send
  }

  await emailService.send(email)
}
```

### Cookie Consent (IAB TCF)

- Use a CMP (Consent Management Platform): OneTrust, Cookiebot, or CookieYes
- Block all non-essential scripts until consent is given (do not load analytics, marketing tags pre-consent)
- Respect `Do Not Track` header for analytics

---

## 4. PII Tagging & Classification

Classify data assets to apply the right controls automatically.

### Data Classification Tiers

| Tier | Examples | Controls |
|------|---------|---------|
| Public | Product names, public docs | No restrictions |
| Internal | Employee names, org structure | Access control, no external sharing |
| Confidential | Customer emails, IP addresses, payment data | Encryption at rest, RLS, column masking |
| Restricted | SSN, health data, biometrics, financial records | E2EE, HSM, strict ABAC, audit log every access |

### Column-Level PII Tagging

```sql
-- PostgreSQL: use column comments as metadata tags
COMMENT ON COLUMN users.email IS 'PII:Confidential;GDPR:PersonalData';
COMMENT ON COLUMN users.phone IS 'PII:Confidential;GDPR:PersonalData';
COMMENT ON COLUMN health_records.diagnosis IS 'PII:Restricted;GDPR:SpecialCategory';

-- Query tagged columns for compliance reporting
SELECT
  c.table_name,
  c.column_name,
  c.col_description(c.table_name::regclass, c.ordinal_position) AS pii_classification
FROM information_schema.columns c
WHERE c.table_schema = 'public'
  AND col_description(c.table_name::regclass, c.ordinal_position) LIKE '%PII%';
```

```typescript
// Application-level PII inventory (dbt/data catalog approach)
const piiFields = {
  users: ['email', 'phone', 'name', 'ipAddress', 'dateOfBirth'],
  orders: ['shippingAddress', 'billingAddress'],
  healthRecords: ['diagnosis', 'medications', 'testResults'],  // Restricted
}

// Automatically apply masking based on classification
function applyPiiMasking<T extends object>(data: T, fields: string[], role: string): T {
  if (role === 'admin') return data
  return Object.fromEntries(
    Object.entries(data).map(([k, v]) => [
      k,
      fields.includes(k) ? '[REDACTED]' : v
    ])
  ) as T
}
```

---

## 5. Least Privilege Principle

Grant the minimum permissions needed, review regularly, and revoke what is no longer used.

### Application Service Accounts

```sql
-- Create a dedicated DB user for the application with minimal grants
CREATE USER app_user WITH PASSWORD 'rotation-managed';

-- Grant only the tables the application actually needs
GRANT SELECT, INSERT, UPDATE ON TABLE orders, products, users TO app_user;
GRANT SELECT ON TABLE categories, regions TO app_user;
GRANT USAGE, SELECT ON SEQUENCE orders_id_seq TO app_user;

-- Explicitly deny anything sensitive
REVOKE ALL ON TABLE audit_log FROM app_user;
REVOKE ALL ON TABLE admin_settings FROM app_user;

-- Audit current grants quarterly
SELECT grantee, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee = 'app_user'
ORDER BY table_name;
```

### AWS IAM — Least Privilege

```json
// IAM policy for Lambda reading from specific S3 path only
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::myapp-uploads/user-documents/*"
    },
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::myapp-uploads/admin-exports/*"
    }
  ]
}
```

### Just-in-Time (JIT) Access

For production access, use JIT tools rather than standing permissions:

- **AWS SSM Session Manager** — SSH without opening port 22; access logged; no standing access
- **Teleport** — unified SSH, Kubernetes, database, and web app access with full session recording
- **HashiCorp Boundary** — identity-based access proxy with just-in-time credential injection

```bash
# AWS SSM Session Manager — no SSH key, no open port 22
aws ssm start-session --target i-0123456789abcdef0

# Database access via Teleport (audit logged, no standing DB credentials)
tsh db connect --db-user=readonly --db-name=production myapp-db
```

### Quarterly Access Review

```sql
-- PostgreSQL: identify over-privileged roles
SELECT
  r.rolname,
  array_agg(DISTINCT p.table_name ORDER BY p.table_name) AS tables_with_access,
  array_agg(DISTINCT p.privilege_type ORDER BY p.privilege_type) AS privileges
FROM pg_roles r
JOIN information_schema.role_table_grants p ON p.grantee = r.rolname
WHERE r.rolname NOT IN ('postgres', 'pg_monitor', 'pg_read_all_settings')
GROUP BY r.rolname
ORDER BY r.rolname;
```

Checklist:
- [ ] GDPR Data Processing Register maintained with all data flows and sub-processors
- [ ] Data residency controls: EU user data stays in EU regions
- [ ] Erasure API implemented and tested — processes requests within 30 days
- [ ] Consent records stored with timestamp, version, and IP
- [ ] Non-essential cookies blocked server-side until consent granted
- [ ] PII fields tagged in data catalog/database comments
- [ ] Retention jobs run daily and are monitored
- [ ] Application DB user has only necessary grants — no DDL in production
- [ ] IAM roles use explicit Deny for sensitive resources
- [ ] JIT access used for production — no standing admin access
- [ ] Access rights reviewed quarterly — unused roles/permissions revoked
