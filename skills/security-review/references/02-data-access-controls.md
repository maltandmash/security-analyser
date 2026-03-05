# Data Access Controls

Covers row-level security, column-level security, object-level permissions, ABAC at the database layer, field masking, dynamic data masking, and cell-level security.

---

## 1. Row-Level Security (RLS)

RLS filters rows at the database engine level so that a query only returns rows the current user is permitted to see — regardless of how the application queries the table.

### PostgreSQL / Supabase

```sql
-- Enable RLS on every user-data table
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

-- FORCE RLS even for the table owner (prevents accidental bypass)
ALTER TABLE orders FORCE ROW LEVEL SECURITY;

-- Policy: users can only see their own orders
CREATE POLICY "users_own_orders_select"
  ON orders FOR SELECT
  USING (user_id = auth.uid());

-- Policy: users can only insert their own orders
CREATE POLICY "users_own_orders_insert"
  ON orders FOR INSERT
  WITH CHECK (user_id = auth.uid());

-- Policy: users can update only their own orders
CREATE POLICY "users_own_orders_update"
  ON orders FOR UPDATE
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

-- Admins can see all orders
CREATE POLICY "admins_all_orders"
  ON orders FOR ALL
  USING (auth.jwt() ->> 'role' = 'admin');
```

Testing RLS policies:
```sql
-- Impersonate a specific user to test policies
SET LOCAL ROLE authenticated;
SET LOCAL "request.jwt.claims" TO '{"sub": "user-uuid-123", "role": "authenticated"}';

SELECT * FROM orders;  -- should only return user-uuid-123's orders
```

### SQL Server

```sql
-- Create a security predicate function
CREATE FUNCTION dbo.fn_user_order_predicate(@user_id INT)
  RETURNS TABLE
  WITH SCHEMABINDING
AS
  RETURN SELECT 1 AS fn_result
  WHERE @user_id = CAST(SESSION_CONTEXT(N'UserId') AS INT)
    OR IS_MEMBER('db_owner') = 1;

-- Bind the security policy to the table
CREATE SECURITY POLICY OrderFilter
  ADD FILTER PREDICATE dbo.fn_user_order_predicate(user_id) ON dbo.Orders,
  ADD BLOCK PREDICATE dbo.fn_user_order_predicate(user_id) ON dbo.Orders AFTER INSERT
  WITH (STATE = ON);
```

❌ NEVER:
```sql
-- No RLS — entire table accessible to any role
SELECT * FROM users WHERE id = $1;  -- only checked at application layer

-- Disabling RLS on tables with user data
ALTER TABLE users DISABLE ROW LEVEL SECURITY;

-- RLS policy that trusts mutable session variable an attacker could manipulate
USING (user_id = current_setting('app.user_id'));  -- can be SET by any session
```

✅ ALWAYS: Use `auth.uid()` (Supabase) or verified JWT claims — not user-settable `current_setting` values.

Checklist:
- [ ] RLS enabled (`ENABLE` + `FORCE`) on every table containing user data
- [ ] Each table has at least one SELECT policy; no default-allow tables
- [ ] Policies tested by impersonating different roles in staging
- [ ] Admin bypass policies are explicit and audited, not implicit

---

## 2. Column-Level Security

Restrict which roles can read or write specific columns — useful for hiding PII, salary data, internal scores, etc.

```sql
-- Revoke all column access from the application role first
REVOKE ALL ON TABLE users FROM app_user;

-- Grant only necessary columns
GRANT SELECT (id, name, email, created_at) ON TABLE users TO app_user;

-- Support staff can see more, but not password hash or internal score
GRANT SELECT (id, name, email, phone, created_at, support_notes) ON TABLE users TO support_role;

-- Only backend admin can see everything
GRANT SELECT ON TABLE users TO admin_role;
```

For applications using ORMs, enforce at the query level too:

```typescript
// Never SELECT * in queries returned to API responses
const user = await db.users.findUnique({
  where: { id: userId },
  select: { id: true, name: true, email: true }  // explicit column list
})
```

```python
# SQLAlchemy — explicit columns
result = session.query(User.id, User.name, User.email).filter(User.id == user_id).first()
```

Checklist:
- [ ] Sensitive columns (PII, secrets, scores) have restricted grants
- [ ] Application DB user cannot SELECT sensitive columns it does not need
- [ ] ORM queries use explicit column selection, not `SELECT *`

---

## 3. Object-Level Permissions

Review that database roles have only the necessary object-level grants (table, view, function, sequence).

```sql
-- Audit current grants
SELECT grantee, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = 'public'
ORDER BY grantee, table_name;

-- Application user should NOT have DDL permissions in production
REVOKE CREATE ON SCHEMA public FROM app_user;

-- Grant only DML on required tables
GRANT SELECT, INSERT, UPDATE ON TABLE orders TO app_user;
GRANT SELECT ON TABLE products TO app_user;
GRANT USAGE, SELECT ON SEQUENCE orders_id_seq TO app_user;
```

Principle: the application database user should have the absolute minimum grants to run the application. DDL (CREATE, DROP, ALTER) belongs only to a migration user with separate credentials.

---

## 4. ABAC at the Database Layer

For complex multi-tenant access patterns, implement attribute-based policies that consider both user attributes and resource attributes.

```sql
-- Supabase: department-scoped access using JWT claims
CREATE POLICY "department_members_see_department_data"
  ON documents FOR SELECT
  USING (
    department_id = (auth.jwt() -> 'app_metadata' ->> 'department_id')::uuid
    OR auth.jwt() ->> 'role' = 'admin'
  );

-- Attribute: data classification level
CREATE POLICY "clearance_level_access"
  ON sensitive_documents FOR SELECT
  USING (
    classification_level <= (auth.jwt() -> 'app_metadata' ->> 'clearance_level')::int
  );
```

---

## 5. Field Masking / Data Redaction

Return obfuscated values to callers who lack the permission to see full data. Masking happens at the application layer or via database views.

```typescript
// Application-layer masking
function maskUser(user: User, requesterRole: string) {
  if (requesterRole === 'admin') return user

  return {
    ...user,
    email: maskEmail(user.email),         // j***@example.com
    phone: user.phone?.replace(/.(?=.{4})/g, '*'),  // ****1234
    ssn: undefined,                         // omit entirely
    creditCardLast4: user.creditCardLast4, // safe to return
  }
}

function maskEmail(email: string): string {
  const [local, domain] = email.split('@')
  return `${local[0]}***@${domain}`
}
```

```sql
-- Database view with masking for support staff
CREATE VIEW users_support_view AS
SELECT
  id,
  name,
  LEFT(email, 1) || '***@' || SPLIT_PART(email, '@', 2) AS email,
  REGEXP_REPLACE(phone, '\d(?=\d{4})', '*', 'g') AS phone,
  created_at
FROM users;

GRANT SELECT ON users_support_view TO support_role;
```

---

## 6. Dynamic Data Masking (DDM)

DDM masks data at query time without altering the stored value. The full value is only visible to privileged roles.

### SQL Server DDM

```sql
-- Apply masking functions to columns
ALTER TABLE Customers
  ALTER COLUMN Email ADD MASKED WITH (FUNCTION = 'email()');

ALTER TABLE Customers
  ALTER COLUMN Phone ADD MASKED WITH (FUNCTION = 'partial(0, "XXX-XXX-", 4)');

ALTER TABLE Payments
  ALTER COLUMN CardNumber ADD MASKED WITH (FUNCTION = 'partial(0, "****-****-****-", 4)');

-- Grant unmask permission to privileged roles only
GRANT UNMASK TO finance_admin_role;
```

### Snowflake Dynamic Data Masking

```sql
-- Create masking policy
CREATE OR REPLACE MASKING POLICY email_mask AS (val STRING) RETURNS STRING ->
  CASE
    WHEN CURRENT_ROLE() IN ('ANALYST', 'SUPPORT') THEN REGEXP_REPLACE(val, '.+@', '****@')
    ELSE val
  END;

-- Apply to column
ALTER TABLE customers MODIFY COLUMN email SET MASKING POLICY email_mask;
```

---

## 7. Cell-Level Security

The most granular control: restrict access to specific row + column combinations. Achieved by combining RLS with column-level grants or views.

```sql
-- Example: users can see their own salary but not others'
-- Admins and HR can see all salaries

-- Base table has RLS: users see only their own row
ALTER TABLE employee_data ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own_record" ON employee_data FOR SELECT USING (user_id = auth.uid());

-- Salary column is restricted via column-level grant
REVOKE SELECT (salary) ON employee_data FROM authenticated;

-- Create a separate view for HR that joins approved salary access
CREATE VIEW employee_salary_view AS
SELECT e.id, e.name, e.salary
FROM employee_data e
WHERE auth.jwt() ->> 'role' IN ('hr', 'admin')
   OR e.user_id = auth.uid();  -- users can see their own

GRANT SELECT ON employee_salary_view TO authenticated;
```

Checklist:
- [ ] Field masking applied to all PII visible to support/analyst roles
- [ ] DDM enabled on any column that must be masked at query time without altering storage
- [ ] Cell-level security used for salary, health, legal data where both row AND column restriction is needed
- [ ] Masking policies tested by querying as each role in staging
