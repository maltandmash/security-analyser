# Cryptography

Covers encryption at rest, encryption in transit, end-to-end encryption, password hashing, and key management.

---

## 1. Encryption at Rest

### Application-Level Field Encryption

Use AES-256-GCM for encrypting individual fields. GCM mode provides both confidentiality and integrity (authenticated encryption).

```typescript
import crypto from 'crypto'

const ALGORITHM = 'aes-256-gcm'
const KEY_LENGTH = 32  // 256 bits

function encrypt(plaintext: string, keyHex: string): string {
  const key = Buffer.from(keyHex, 'hex')
  const iv = crypto.randomBytes(12)  // 96-bit IV for GCM
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv)

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ])
  const authTag = cipher.getAuthTag()

  // Store IV + authTag + ciphertext together
  return Buffer.concat([iv, authTag, encrypted]).toString('base64')
}

function decrypt(ciphertext: string, keyHex: string): string {
  const key = Buffer.from(keyHex, 'hex')
  const data = Buffer.from(ciphertext, 'base64')

  const iv = data.slice(0, 12)
  const authTag = data.slice(12, 28)
  const encrypted = data.slice(28)

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv)
  decipher.setAuthTag(authTag)

  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]).toString('utf8')
}
```

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

def encrypt(plaintext: str, key: bytes) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt(ciphertext_b64: str, key: bytes) -> str:
    data = base64.b64decode(ciphertext_b64)
    nonce, ciphertext = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()
```

❌ NEVER:
```typescript
// ECB mode — identical plaintext blocks produce identical ciphertext (reveals patterns)
crypto.createCipheriv('aes-256-ecb', key, '')

// Custom/home-grown encryption schemes
function myEncrypt(text: string) { return Buffer.from(text).toString('base64') }  // this is NOT encryption

// Storing encryption keys in the same database as encrypted data
await db.create({ encryptedField: encrypted, encryptionKey: key })  // catastrophic
```

### Database-Level Encryption

- **PostgreSQL pgcrypto**: `pgp_sym_encrypt(data, passphrase)` — column-level encryption in SQL
- **Transparent Data Encryption (TDE)**: SQL Server, Oracle, MySQL Enterprise — encrypts the entire database file
- **AWS RDS**: enable storage encryption at creation time (cannot be enabled after); uses AES-256

```sql
-- PostgreSQL pgcrypto field encryption
SELECT pgp_sym_encrypt('sensitive data', 'passphrase') AS encrypted_value;
SELECT pgp_sym_decrypt(encrypted_value::bytea, 'passphrase') FROM table;
```

Disk-level encryption:
- AWS EBS: enable encryption on all volumes (default: CMK managed by KMS)
- AWS S3: use SSE-KMS (customer-managed key) for sensitive buckets — not SSE-S3 (AWS-managed key)
- Local servers: LUKS on Linux, BitLocker on Windows

---

## 2. Encryption in Transit

### TLS Configuration

Minimum TLS 1.2; prefer TLS 1.3 for all new deployments.

```nginx
# Nginx TLS hardening
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;  # let clients pick from the allowed list
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;  # disable — forward secrecy

# HSTS — browsers remember HTTPS for 1 year
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

Disabled cipher suites (must not appear):
- RC4, DES, 3DES, EXPORT ciphers
- MD5 and SHA-1 in cipher suites
- Anonymous DH (aNULL, eNULL)
- Non-forward-secret ciphers (RSA key exchange without ECDHE/DHE)

Test with:
```bash
# SSL Labs (external)
# testssl.sh (local)
docker run --rm drwetter/testssl.sh https://yourapp.com

# Check supported protocols and ciphers
openssl s_client -connect yourapp.com:443 -tls1_1  # should fail if TLS 1.1 disabled
```

### HSTS (HTTP Strict Transport Security)

```typescript
// Express / Node.js
import helmet from 'helmet'

app.use(helmet.hsts({
  maxAge: 31536000,        // 1 year in seconds
  includeSubDomains: true,
  preload: true,
}))
```

### Certificate Management

- Certificate expiry must be monitored — set alarms at 30 days and 7 days before expiry
- Use Let's Encrypt with auto-renewal (certbot, cert-manager) or AWS ACM (auto-renews)
- Pin certificates for mobile applications to prevent MITM via rogue CAs

---

## 3. End-to-End Encryption (E2EE)

E2EE: data is encrypted client-side and the server never sees plaintext. Required for messaging, health records, legal documents, and financial data where even the operator should not have access.

```typescript
// Client-side encryption using libsodium (via tweetnacl)
import nacl from 'tweetnacl'
import { encodeBase64, decodeBase64, encodeUTF8, decodeUTF8 } from 'tweetnacl-util'

// Generate key pair for each user (store private key client-side only, never send to server)
const keyPair = nacl.box.keyPair()

// Encrypt message for recipient
function encryptForRecipient(message: string, recipientPublicKey: Uint8Array, senderSecretKey: Uint8Array): string {
  const nonce = nacl.randomBytes(nacl.box.nonceLength)
  const messageBytes = encodeUTF8(message)
  const encrypted = nacl.box(messageBytes, nonce, recipientPublicKey, senderSecretKey)
  return encodeBase64(new Uint8Array([...nonce, ...encrypted]))
}

// Decrypt
function decryptFromSender(ciphertext: string, senderPublicKey: Uint8Array, recipientSecretKey: Uint8Array): string {
  const data = decodeBase64(ciphertext)
  const nonce = data.slice(0, nacl.box.nonceLength)
  const encrypted = data.slice(nacl.box.nonceLength)
  const decrypted = nacl.box.open(encrypted, nonce, senderPublicKey, recipientSecretKey)
  if (!decrypted) throw new Error('Decryption failed')
  return decodeUTF8(decrypted)
}
```

E2EE checklist:
- [ ] Private keys never leave the client — server stores only public keys
- [ ] Key derivation from password uses Argon2id or scrypt, not just SHA-256
- [ ] Key rotation mechanism exists for compromised keys
- [ ] Server-side plaintext search (if needed) uses homomorphic encryption or searchable encryption — never decrypts server-side

---

## 4. Password Hashing

❌ NEVER:
```typescript
// Unsalted hash — rainbow table attack trivial
crypto.createHash('sha256').update(password).digest('hex')

// MD5, SHA-1 — computationally cheap, easily reversed
crypto.createHash('md5').update(password).digest('hex')

// bcrypt with low cost factor
bcrypt.hash(password, 4)  // cost 4 is trivially fast on modern hardware
```

✅ ALWAYS — Argon2id (recommended for new systems):

```typescript
import argon2 from 'argon2'

// Hash — Argon2id is the OWASP recommended choice
const hash = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 65536,  // 64 MiB — adjust based on server memory
  timeCost: 3,        // 3 iterations
  parallelism: 4,
})

// Verify
const valid = await argon2.verify(hash, password)
```

```python
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)

hash = ph.hash(password)

# Rehash if parameters have been upgraded
if ph.check_needs_rehash(hash):
    hash = ph.hash(password)
```

bcrypt (acceptable for existing systems, cost factor 12+):
```typescript
import bcrypt from 'bcrypt'
const SALT_ROUNDS = 12

const hash = await bcrypt.hash(password, SALT_ROUNDS)
const valid = await bcrypt.compare(password, hash)
```

Integrity hashing (files, checksums — not passwords):
```typescript
// SHA-256 for file integrity
const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex')
// SHA-3 (Keccak) for higher-security contexts
const hash = crypto.createHash('sha3-256').update(data).digest('hex')
```

---

## 5. Key Management & Rotation

### AWS KMS — Envelope Encryption

```typescript
import { KMSClient, GenerateDataKeyCommand, DecryptCommand } from '@aws-sdk/client-kms'

const kms = new KMSClient({ region: process.env.AWS_REGION })

// Generate data encryption key (DEK)
async function generateDataKey() {
  const command = new GenerateDataKeyCommand({
    KeyId: process.env.KMS_KEY_ID,
    KeySpec: 'AES_256',
  })
  const response = await kms.send(command)
  return {
    plaintext: response.Plaintext!,      // use to encrypt data, then discard from memory
    encrypted: response.CiphertextBlob!, // store alongside encrypted data
  }
}

// Decrypt DEK to decrypt data
async function decryptDataKey(encryptedKey: Uint8Array): Promise<Uint8Array> {
  const command = new DecryptCommand({ CiphertextBlob: encryptedKey })
  const response = await kms.send(command)
  return response.Plaintext!
}
```

Key rotation schedule:
| Key type | Rotation frequency | Notes |
|----------|-------------------|-------|
| AWS KMS CMK (symmetric) | Annual (automatic) | Enable auto-rotation in KMS |
| JWT signing keys (RS256) | 90 days | Overlap period for in-flight tokens |
| Database encryption keys | Annual | Requires re-encryption of data |
| TLS certificates | 90 days | Automated via ACM/Let's Encrypt |
| API signing keys | 90 days | Automated via Vault/Secrets Manager |

### HSM (Hardware Security Module)

Required for:
- PCI-DSS compliance (cardholder data environment)
- CA private keys
- High-value cryptographic operations

Options:
- **AWS CloudHSM** — FIPS 140-2 Level 3, dedicated hardware, you manage keys
- **AWS KMS with HSM backing** — FIPS 140-2 Level 2 by default, Level 3 with CloudHSM key store
- **Thales / nCipher** — on-premises HSM for data centre deployments

Checklist:
- [ ] AES-256-GCM used for all symmetric encryption (not ECB, not CBC without MAC)
- [ ] TLS 1.2 minimum, TLS 1.3 preferred; RC4/DES/3DES disabled
- [ ] HSTS header with `max-age=31536000; includeSubDomains; preload`
- [ ] Argon2id (cost ≥ 64MiB/3 iterations) or bcrypt (rounds ≥ 12) for passwords
- [ ] KMS auto-rotation enabled for all symmetric CMKs
- [ ] Certificate expiry alarms configured at 30 days
- [ ] No private keys stored in source code, CI environment variables, or container images
