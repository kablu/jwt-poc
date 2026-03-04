# JWS (JSON Web Signature) — Complete RFC 7515 Development Plan

> **RFC 7515 — JSON Web Signature (JWS)** | Author: Kablu | Date: 2026-03-04
>
> *"Content integrity, authenticity, and non-repudiation using digital signatures over JSON data structures."*

---

## Table of Contents

1. [RFC 7515 — Point-by-Point Specification](#1-rfc-7515--point-by-point-specification)
2. [JOSE Suite — Where JWS Fits](#2-jose-suite--where-jws-fits)
3. [JWS vs Traditional Signature — Full Comparison](#3-jws-vs-traditional-signature--full-comparison)
4. [Layman Examples — Explain to the Team](#4-layman-examples--explain-to-the-team)
5. [JWS Structure Anatomy](#5-jws-structure-anatomy)
6. [JWS Serialization Formats](#6-jws-serialization-formats)
7. [JWS Algorithms — Complete Reference (RFC 7518)](#7-jws-algorithms--complete-reference-rfc-7518)
8. [Spring Boot + Java Implementation](#8-spring-boot--java-implementation)
9. [Phase-wise Development Plan](#9-phase-wise-development-plan)
10. [Security Considerations (RFC 7515 §8)](#10-security-considerations-rfc-7515-8)
11. [Advanced JWS Patterns](#11-advanced-jws-patterns)
12. [Decision Matrix](#12-decision-matrix)

---

## 1. RFC 7515 — Point-by-Point Specification

### 1.1 Introduction (RFC 7515 §1)

RFC 7515 defines **JSON Web Signature (JWS)** as a standard that:

- Represents **digitally signed** or **MACed** content using JSON-based data structures
- Provides **integrity** (content not altered), **authenticity** (who signed it), and optionally **non-repudiation** (cannot deny signing)
- Is part of the **JOSE (JSON Object Signing and Encryption)** framework
- Published: May 2015 by IETF (Internet Engineering Task Force)
- Authors: M. Jones, J. Bradley, N. Sakimura

```
JWS is NOT encryption — it signs and verifies, but content is visible.
For encryption, use JWE (RFC 7516).
```

---

### 1.2 Terminology (RFC 7515 §2)

| Term | RFC Definition | Simple Meaning |
|------|---------------|----------------|
| **JWS** | JSON Web Signature | The signed message (header + payload + signature) |
| **Payload** | The bytes to be signed | Your actual data (JSON, text, binary) |
| **JOSE Header** | Set of parameters describing cryptographic operations | The "instruction manual" telling verifier HOW to verify |
| **JWS Compact Serialization** | URL-safe base64url(header).base64url(payload).base64url(signature) | 3-part dot-separated string — most common form |
| **JWS JSON Serialization** | Full JSON object form supporting multiple signatures | Used when multiple parties must sign the same payload |
| **Header Parameters** | Key-value pairs in the JOSE Header | Metadata like algorithm (alg), key ID (kid), type (typ) |
| **JWS Signing Input** | ASCII(BASE64URL(header) || '.' || BASE64URL(payload)) | Exact bytes that get signed |
| **Base64url** | URL-safe Base64 without padding | Encoding that removes +, /, = characters for URL safety |
| **Unprotected Header** | Header not included in signature computation | Only in JSON Serialization; not integrity-protected |
| **Detached Content** | Payload transmitted separately from the JWS token | Payload omitted from compact serialization |

---

### 1.3 JWS Overview (RFC 7515 §3)

RFC 7515 §3 describes the two serialization forms:

#### §3.1 — JWS Compact Serialization
```
BASE64URL(JWS Protected Header) || '.' ||
BASE64URL(JWS Payload)          || '.' ||
BASE64URL(JWS Signature)
```
- **Single signature only** (one signer)
- URL-safe — can be used in HTTP headers, query params
- Every part is Base64url encoded
- **This is what JWT uses** — JWT is a specific use of JWS Compact Serialization

#### §3.2 — JWS JSON Serialization
```json
{
  "payload": "<BASE64URL(JWS Payload)>",
  "signatures": [
    {
      "protected": "<BASE64URL(JWS Protected Header 1)>",
      "header": { "kid": "key-01" },
      "signature": "<BASE64URL(JWS Signature 1)>"
    },
    {
      "protected": "<BASE64URL(JWS Protected Header 2)>",
      "header": { "kid": "key-02" },
      "signature": "<BASE64URL(JWS Signature 2)>"
    }
  ]
}
```
- **Multiple signatures** supported (multiple signers, multiple algorithms)
- More verbose but richer
- Used in Open Banking, PSD2, legal document signing

---

### 1.4 JOSE Header Parameters (RFC 7515 §4)

The JOSE Header is a JSON object containing parameters about the signature. RFC 7515 §4.1 defines **registered header parameter names**.

#### §4.1.1 — `alg` (Algorithm) **REQUIRED**

```json
{ "alg": "RS256" }
```

- **MUST be present** in all JWS tokens
- Identifies the cryptographic algorithm used to sign the payload
- Values defined in RFC 7518 (JWA): RS256, PS256, ES256, HS256, EdDSA, etc.
- `"none"` = unsecured JWS (DANGEROUS — reject in production)

#### §4.1.2 — `jku` (JWK Set URL)

```json
{ "jku": "https://auth-server.example.com/.well-known/jwks.json" }
```

- URL of a JWK Set (RFC 7517) containing the public key to verify with
- Server should validate this URL is from a trusted source
- **Security risk**: never blindly fetch and use a URL from an untrusted token

#### §4.1.3 — `jwk` (JSON Web Key)

```json
{
  "jwk": {
    "kty": "RSA",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFb...",
    "e": "AQAB"
  }
}
```

- The **public key itself** embedded directly in the header
- Used in self-signed scenarios or when JWKS endpoint is not available
- **Security risk**: verify the key is from a trusted source before using it

#### §4.1.4 — `kid` (Key ID) **IMPORTANT**

```json
{ "kid": "auth-server-key-03" }
```

- Identifies **which key** was used to sign
- Receiver uses `kid` to look up the correct public key in the JWKS
- **Key rotation**: when multiple keys exist in JWKS, `kid` picks the right one
- In our auth-server: `kid` values are `auth-server-key-01` to `auth-server-key-10`

#### §4.1.5 — `x5u` (X.509 URL)

- URL pointing to X.509 certificate or chain
- For PKI/certificate-based scenarios (TLS client certificates)

#### §4.1.6 — `x5c` (X.509 Certificate Chain)

```json
{ "x5c": ["MIIE...base64-encoded-cert..."] }
```

- Embeds the X.509 certificate chain directly in the header
- Used when integrating JWS with traditional PKI infrastructure

#### §4.1.7 — `x5t` (X.509 Certificate SHA-1 Thumbprint)

- SHA-1 thumbprint of the DER-encoded X.509 certificate
- Used to identify which certificate was used for signing

#### §4.1.8 — `x5t#S256` (X.509 Certificate SHA-256 Thumbprint)

- SHA-256 thumbprint (preferred over SHA-1)
- More secure than `x5t`

#### §4.1.9 — `typ` (Type)

```json
{ "typ": "JWT" }
```

- Declares the media type of the JWS
- `JWT` = this is a JSON Web Token (JWS Compact Serialization with JSON payload)
- `at+JWT` = Access Token (RFC 9068 — JWT Access Tokens)
- Optional but recommended for clarity

#### §4.1.10 — `cty` (Content Type)

```json
{ "cty": "JWT" }
```

- Declares the media type of the **payload** content
- Used in nested JWT scenarios (JWS inside JWE): `{ "cty": "JWT" }`
- Tells the verifier how to interpret the payload after signature verification

#### §4.1.11 — `crit` (Critical)

```json
{ "crit": ["exp", "nbf"] }
```

- Lists header parameters that **MUST be understood** by the implementation
- If an implementation doesn't understand a parameter listed in `crit`, it MUST reject the token
- Used for forward compatibility and custom extension parameters

---

### 1.5 Producing a JWS — Step by Step (RFC 7515 §5.1)

RFC 7515 Section 5.1 defines the exact algorithm for creating a JWS:

```
STEP 1: Create the JOSE Header
─────────────────────────────
{ "alg": "RS256", "kid": "auth-server-key-03", "typ": "JWT" }

STEP 2: Base64url encode the JOSE Header
────────────────────────────────────────
eyJhbGciOiJSUzI1NiIsImtpZCI6ImF1dGgtc2VydmVyLWtleS0wMyIsInR5cCI6IkpXVCJ9

STEP 3: Create the JWS Payload
───────────────────────────────
{ "sub": "user123", "aud": "resource-server", "exp": 1735689600 }

STEP 4: Base64url encode the Payload
─────────────────────────────────────
eyJzdWIiOiJ1c2VyMTIzIiwiYXVkIjoicmVzb3VyY2Utc2VydmVyIiwiZXhwIjoxNzM1Njg5NjAwfQ

STEP 5: Create the JWS Signing Input
──────────────────────────────────────
ASCII( BASE64URL(Header) + "." + BASE64URL(Payload) )
= "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0"
  ← This exact string of bytes is what gets signed

STEP 6: Compute the Signature
──────────────────────────────
signature = RSA_PKCS1_v1.5_SHA256_SIGN( private_key, JWS_Signing_Input )
         OR RSASSA-PSS for PS256
         OR ECDSA for ES256

STEP 7: Base64url encode the Signature
────────────────────────────────────────
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c...

STEP 8: Assemble the JWS Compact Serialization
────────────────────────────────────────────────
BASE64URL(Header) + "." + BASE64URL(Payload) + "." + BASE64URL(Signature)
```

---

### 1.6 Validating a JWS — Step by Step (RFC 7515 §5.2)

RFC 7515 Section 5.2 defines the validation algorithm:

```
STEP 1: Parse the JWS Compact Serialization
─────────────────────────────────────────────
Split by "." → [encoded_header, encoded_payload, encoded_signature]
Verify exactly 3 parts (or 5 for JWE)

STEP 2: Base64url decode the JOSE Header
─────────────────────────────────────────
header = BASE64URL_DECODE(encoded_header)
Parse as JSON → { "alg": "RS256", "kid": "auth-server-key-03" }

STEP 3: Validate Header Parameters
─────────────────────────────────────
- Check "alg" is NOT "none" (reject unsecured JWS)
- Check "alg" is in your allowed-algorithms list
- If "crit" is present, verify all listed params are understood

STEP 4: Identify the Verification Key
───────────────────────────────────────
- Use "kid" to look up public key from JWKS
- OR use "jku" to fetch JWKS (validate URL first!)
- OR use "x5c" / "x5t" for certificate-based lookup

STEP 5: Reconstruct JWS Signing Input
───────────────────────────────────────
signing_input = ASCII( encoded_header + "." + encoded_payload )
← Same as what was signed in Step 5 of production

STEP 6: Verify the Signature
──────────────────────────────
signature_bytes = BASE64URL_DECODE(encoded_signature)
valid = RSA_VERIFY( public_key, signing_input, signature_bytes )
If NOT valid → REJECT the token immediately

STEP 7: Decode the Payload
────────────────────────────
payload = BASE64URL_DECODE(encoded_payload)
Parse as JSON (for JWT) or treat as raw bytes

STEP 8: Validate Payload Claims (application level)
──────────────────────────────────────────────────────
- exp: not expired
- nbf: not before current time
- iss: from expected issuer
- aud: intended for this recipient
- sub: subject is known/authorized
```

---

### 1.7 Key Identification (RFC 7515 §4.1.4 + §7)

RFC 7515 recommends using `kid` to identify keys. The full key identification strategy:

```
Token Header:  { "kid": "auth-server-key-03" }
              ↓
Verifier:     1. Look in local JWKS cache for kid="auth-server-key-03"
              2. If not found → fetch JWKS from jwk-set-uri
              3. Find the key with matching kid
              4. Use that public key to verify signature
              5. Cache the JWKS (respect Cache-Control header)
```

Our auth-server serves keys at `/.well-known/jwks.json`:
```json
{
  "keys": [
    { "kty": "RSA", "kid": "auth-server-key-01", "use": "sig", "alg": "RS256", "n": "...", "e": "AQAB" },
    { "kty": "RSA", "kid": "auth-server-key-02", "use": "sig", "alg": "RS256", "n": "...", "e": "AQAB" },
    ...
    { "kty": "RSA", "kid": "auth-server-key-10", "use": "sig", "alg": "RS256", "n": "...", "e": "AQAB" }
  ]
}
```

---

### 1.8 Unsecured JWS — `alg: none` (RFC 7515 §6)

RFC 7515 §6 defines "Unsecured JWS" with `"alg": "none"`:

```json
Header: { "alg": "none" }
Signature: "" (empty string)
JWS: eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyMTIzIn0.
```

**⚠️ CRITICAL SECURITY WARNING:**
- NEVER accept `alg: none` in production
- The infamous "algorithm confusion attack" exploits libraries that accept `alg: none`
- **Always whitelist allowed algorithms and reject anything not in the whitelist**
- Spring Security's `NimbusJwtDecoder` rejects `alg: none` by default ✅

---

## 2. JOSE Suite — Where JWS Fits

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         JOSE Framework                                  │
│              (JSON Object Signing and Encryption)                       │
├─────────────┬──────────────┬────────────┬───────────┬───────────────────┤
│  RFC 7515   │  RFC 7516    │  RFC 7517  │  RFC 7518 │   RFC 7519        │
│    JWS      │    JWE       │    JWK     │    JWA    │    JWT            │
│             │              │            │           │                   │
│  JSON Web   │  JSON Web    │  JSON Web  │  JSON Web │  JSON Web         │
│  Signature  │  Encryption  │  Key       │ Algorithms│  Token            │
│             │              │            │           │                   │
│  Integrity  │  Confidential│  Key       │  RS256    │  Claims-based     │
│  Authenticity│ ity (encrypt)│  Format   │  PS256    │  token (uses JWS  │
│  Non-repud. │  CANNOT read │  Storage  │  ES256    │  or JWE as        │
│  CAN read   │  without key │  Exchange │  HS256    │  container)       │
│  payload    │              │  JWKS      │  EdDSA    │                   │
├─────────────┴──────────────┴────────────┴───────────┴───────────────────┤
│                                                                         │
│  JWT = JWS (signed) OR JWE (encrypted)                                 │
│  JWT uses JWS Compact Serialization with JSON payload = JWT             │
│  JWK defines the KEY FORMAT used by JWS and JWE                        │
│  JWA defines the ALGORITHMS used by JWS and JWE                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Relationship Diagram

```
Your Private Key (JWK format, RSA-2048)
          │
          │  sign()
          ▼
    JWS Signing Process (RFC 7515)
    ├── Algorithm: RS256 (defined in JWA RFC 7518)
    ├── Key ID: kid (references key in JWK Set RFC 7517)
    └── Result: JWS Token (Header.Payload.Signature)
                    │
                    │  If payload = JWT claims → it's a JWT (RFC 7519)
                    │  If payload = arbitrary bytes → it's plain JWS
                    ▼
            Transport (HTTP Header / URL / Body)
                    │
                    ▼
    JWS Verification (RFC 7515)
    ├── Parse header, find kid
    ├── Fetch JWKS (RFC 7517 format) from auth-server
    ├── Select key matching kid, verify alg (RFC 7518)
    └── Verify signature → VALID or INVALID
```

---

## 3. JWS vs Traditional Signature — Full Comparison

### 3.1 What is a "Traditional Signature"?

Traditional digital signatures (outside JOSE world):
- XML DSig (W3C) — used in SAML, SOAP web services, XML documents
- CMS/PKCS#7 (RFC 5652) — binary format for S/MIME emails, code signing
- PGP/GPG — for email and file signing
- PDF signatures — Adobe-compatible digital signatures
- Raw RSA/ECDSA — bare cryptographic signature bytes

### 3.2 Comparison Table

| Dimension | JWS (RFC 7515) | Traditional (XML DSig / CMS) |
|-----------|----------------|------------------------------|
| **Format** | JSON / URL-safe compact string | XML (XML DSig), Binary (CMS/PKCS#7) |
| **Payload** | Any bytes (base64url encoded) | XML nodes (XML DSig), arbitrary binary (CMS) |
| **Header Location** | Inside the token itself | Separate metadata element |
| **Key Reference** | `kid`, `jku`, `jwk` in JOSE Header | KeyInfo in XML DSig; Certificate in CMS |
| **Algorithm** | `alg` claim: RS256, ES256, HS256 | AlgorithmMethod URLs in XML DSig |
| **Multiple Signatures** | JWS JSON Serialization (`signatures` array) | XML DSig enveloping; CMS SignedData |
| **Detached Payload** | Yes — RFC 7797 (payload outside token) | Yes — XML DSig enveloped/detaching |
| **Transport** | HTTP Header, URL param, JSON field | MIME part, SOAP envelope, file attachment |
| **Parsing Complexity** | Simple (Base64url decode + JSON parse) | Complex (XML parsing, ASN.1 decoding) |
| **Web/REST Friendly** | ✅ Designed for REST/HTTP | ❌ Designed for document/enterprise |
| **Human Readable** | Partially (payload decoded) | ❌ XML verbose or binary |
| **Library Support** | Wide (Nimbus, jose4j, Spring) | XML DSig: Java built-in; CMS: Bouncy Castle |
| **Key Format** | JWK (RFC 7517) — JSON | X.509 Certificate (DER/PEM) |
| **JWKS Discovery** | `/.well-known/jwks.json` auto-discovery | PKI / Certificate Authority path |
| **Use in OAuth2/OIDC** | ✅ Native — JWTs ARE JWS tokens | ❌ Not standard (SAML uses XML DSig) |
| **Algorithm Agility** | Single `alg` field change | Complex XML namespace and URL changes |
| **Canonical Form** | Always Base64url encoded | XML c14n (canonicalization) required |
| **Typical Use** | APIs, OAuth2, microservices | Enterprise SOA, government documents, S/MIME |

### 3.3 When to Choose JWS Over Traditional

```
Choose JWS when:
✅ Building REST APIs or microservices
✅ OAuth2 / OpenID Connect ecosystem
✅ HTTP Authorization headers
✅ Mobile apps, single-page applications
✅ Short-lived access tokens
✅ You want auto-discovery via JWKS

Choose Traditional (CMS/XML DSig) when:
✅ Signing PDF documents or legal contracts
✅ S/MIME email signing
✅ SAML-based enterprise SSO
✅ Code signing (JAR, MSI, PKCS#7)
✅ Long-term archival (10+ years) — XML DSig with timestamps
✅ Regulatory compliance requiring X.509 certificates
```

---

## 4. Layman Examples — Explain to the Team

### Example 1: Speed Post with Seal (JWS Compact = Speed Post)

> **Scenario**: Ek registered speed post bhejo — contents visible hain, par seal authentic hai.

```
Traditional Registered Post:
─────────────────────────────
📬 Envelope (Header):    "From: Post Office Kanpur, Certified Mail"
📄 Letter (Payload):     "Dear Customer, Your account is activated."
🔏 Wax Seal (Signature): Post Office ka official stamp
─────────────────────────
→ Koi bhi letter padh sakta hai (not encrypted)
→ Lekin seal se pata chalta hai ki Post Office ne bheja hai

JWS Compact Serialization:
───────────────────────────
Header:    { "alg": "RS256", "kid": "auth-server-key-01" }  ← Post Office ka stamp ID
Payload:   { "sub": "user123", "scope": "movies:read" }     ← Letter content
Signature: SflKxwRJSMeKKF2QT4fw...                          ← Digital seal

→ Anyone can READ the payload (Base64url decode)
→ But ONLY the holder of the private key could have SIGNED it
→ Anyone with the PUBLIC key can VERIFY the signature
```

---

### Example 2: Aadhar Card (kid = Unique Key Identifier)

> **Scenario**: Jab tum Aadhar dikhate ho, officer check karta hai ki genuine UIDAI se aaya hai ya nahi.

```
Aadhar Card:
─────────────
📛 Name: Ramesh Kumar          ← Payload claims (name, aadhaar number)
🔢 Number: 1234 5678 9012      ← sub claim
📅 DOB: 01/01/1990             ← birthdate claim
🏛️ UIDAI Logo + QR Code       ← kid + signature (UIDAI private key se sign)

Verification:
─────────────
Officer scans QR → Finds "kid": "UIDAI-2024-KEY-01" in QR
→ Fetches UIDAI public key for that kid
→ Verifies QR signature → ✅ Authentic

JWS Analogy:
─────────────
Header: { "kid": "UIDAI-2024-KEY-01", "alg": "RS256" }
Payload: { "name": "Ramesh Kumar", "dob": "1990-01-01", "aadhaar": "XXXX-XXXX-9012" }
Signature: [UIDAI's digital signature]

kid = UIDAI ne bataya "mera kaun sa key use hua" → verifier sahi public key use kare
```

---

### Example 3: WhatsApp Group Admin (HMAC vs RSA — HS256 vs RS256)

> **Scenario**: Group admin message bhejta hai. Sab verify kar sakte hain par sirf admin sign kar sakta hai.

```
HMAC (HS256) — Shared Secret — WhatsApp Group (Admin + Members know secret):
─────────────────────────────────────────────────────────────────────────────
🔑 Admin + all members have the same secret key
📝 Admin signs message with secret
✅ Any member can verify (they know secret)
❌ But any member can ALSO forge messages (they know secret!)
→ Use HS256 only for single-service scenarios (same app signs and verifies)

RSA (RS256) — Asymmetric — Like Government ID System:
──────────────────────────────────────────────────────
🔐 Only Government (Auth Server) has PRIVATE key
📢 Everyone has access to PUBLIC key (from JWKS endpoint)
📝 Government signs your identity document with private key
✅ Anyone can verify using public key
❌ No one else can forge because they don't have private key
→ Use RS256 for OAuth2, APIs, distributed systems
```

---

### Example 4: Bank Cheque (JWS Token = Signed Cheque)

> **Scenario**: Bank cheque — content dikhta hai, but signature authenticate karta hai.

```
Bank Cheque:
─────────────
📋 Cheque Fields:          | JWS Token:
   Pay to: Ramesh Kumar    |   Payload: { "sub": "resource-client" }
   Amount: ₹50,000         |   Payload: { "scope": "movies:read" }
   Date: 04-03-2026        |   Payload: { "exp": 1741219200 }
   Account: XXXXXXX8901    |   Payload: { "iss": "http://localhost:9000" }
   ─────────────────────   |   ──────────────────────────────────────────
   [Your Signature]        |   Signature: (RS256 with auth-server private key)
   Bank Stamp              |   kid: "auth-server-key-03"

Cheque Verification:       | JWS Verification:
Bank clerk checks:         | Resource server:
✅ Signature genuine?      | ✅ Signature valid (via JWKS)?
✅ Amount available?       | ✅ exp not expired?
✅ Date not stale?         | ✅ iss = "http://localhost:9000"?
✅ MICR code matches?      | ✅ scope = "movies:read"?
```

---

### Example 5: Restaurant Token System (JWT Expiry = Token Number)

> **Scenario**: Restaurant deta hai ek token — woh token 2 ghante valid hai, uske baad expire ho jata hai.

```
Restaurant Token:
──────────────────
🎟️  Token #47 | Table: 3 | Time Issued: 1:00 PM | Valid Till: 3:00 PM

JWT:
─────
{
  "jti": "47",           ← Token #47 (JWT ID)
  "sub": "table-3",      ← Table 3
  "iat": 1741176000,     ← 1:00 PM (issued at)
  "exp": 1741183200      ← 3:00 PM (expires at — 2 hours)
}

After 3:00 PM → Token expired → Get new token (new JWT)
This is WHY access tokens are short-lived (1 hour in our POC)

nbf claim (not before):
────────────────────────
Like "Early Bird Token" — "Valid only from 12:00 PM"
{ "nbf": 1741168800 }  ← Don't use before 12:00 PM
```

---

### Example 6: Notarized Document (JWS JSON Serialization = Multiple Signatures)

> **Scenario**: Property deed — buyer, seller, AND notary sab sign karte hain. Teen alag signatures ek document par.

```
Property Deed Signatures:
──────────────────────────
Document: { "property": "Plot #123, Sector 15", "price": "₹50 Lakh" }
Signatures:
  1. Buyer's Signature (Ramesh Kumar)
  2. Seller's Signature (Sita Devi)
  3. Notary's Signature (Sub-Registrar)

JWS JSON Serialization (Multiple Signatures):
──────────────────────────────────────────────
{
  "payload": "eyJwcm9wZXJ0eSI6...",
  "signatures": [
    {
      "protected": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJ1eWVyLWtleSJ9",
      "header": { "kid": "buyer-key", "role": "buyer" },
      "signature": "buyer_signature_bytes..."
    },
    {
      "protected": "eyJhbGciOiJSUzI1NiIsImtpZCI6InNlbGxlci1rZXkifQ",
      "header": { "kid": "seller-key", "role": "seller" },
      "signature": "seller_signature_bytes..."
    },
    {
      "protected": "eyJhbGciOiJSUzI1NiIsImtpZCI6Im5vdGFyeS1rZXkifQ",
      "header": { "kid": "notary-key", "role": "notary" },
      "signature": "notary_signature_bytes..."
    }
  ]
}
→ Used in Open Banking (PSD2), Legal Contracts, Supply Chain
```

---

### Example 7: Courier with Separate Package and Receipt (Detached JWS)

> **Scenario**: Large parcel bhejo — receipt alag, package alag. Receipt par package ka description likha hai.

```
Detached JWS — RFC 7797:
────────────────────────
Normal JWS:    Header.Payload.Signature   ← Payload INSIDE the token

Detached JWS:  Header..Signature          ← Payload OUTSIDE (double dot)
               ↑ payload is EMPTY in the token

Why?
────
✅ Large payloads — file ka signature lena without embedding 10MB file in token
✅ Open Banking (PSD2) — request body sign hoti hai separately
✅ Webhooks — event payload alag, signature HTTP header mein

Example:
Header: { "alg": "RS256", "b64": false }
                          ↑ RFC 7797: payload is NOT base64url encoded
Payload: (sent separately in HTTP body or file)
Signature: (calculated over the raw payload)

HTTP Request with Detached JWS:
─────────────────────────────────
POST /payment HTTP/1.1
x-jws-signature: eyJhbGciOiJSUzI1NiJ9..SflKxwRJSMeKKF2QT...
Content-Type: application/json

{ "amount": 50000, "to": "ramesh@bank.com" }
↑ This is the detached payload — NOT base64 encoded in token
```

---

## 5. JWS Structure Anatomy

### 5.1 Compact Serialization (Used in JWT / OAuth2)

```
eyJhbGciOiJSUzI1NiIsImtpZCI6ImF1dGgtc2VydmVyLWtleS0wMyIsInR5cCI6IkpXVCJ9
.
eyJzdWIiOiJyZXNvdXJjZS1jbGllbnQiLCJzY29wZSI6Im1vdmllczpyZWFkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwiZXhwIjoxNzQxMjE5MjAwfQ
.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
│                    │                    │
│                    │                    └─── Part 3: JWS Signature
│                    │                         Base64url(RSA_SIGN(Part1 + "." + Part2))
│                    │
│                    └──────────────────────── Part 2: JWS Payload
│                                              Base64url({ "sub": "resource-client",
│                                                          "scope": "movies:read",
│                                                          "iss": "http://localhost:9000",
│                                                          "exp": 1741219200 })
│
└───────────────────────────────────────────── Part 1: JOSE Header
                                               Base64url({ "alg": "RS256",
                                                           "kid": "auth-server-key-03",
                                                           "typ": "JWT" })
```

### 5.2 Claims (Payload) Breakdown

```json
{
  "iss": "http://localhost:9000",      // Issuer — who signed this (our auth-server)
  "sub": "resource-client",           // Subject — who this token is about
  "aud": "resource-server",           // Audience — who should accept this (resource-server)
  "exp": 1741219200,                  // Expiration — Unix timestamp (1 hour TTL)
  "nbf": 1741215600,                  // Not Before — valid from this time
  "iat": 1741215600,                  // Issued At — when signed
  "jti": "550e8400-e29b-41d4-a716",  // JWT ID — unique identifier (prevent replay)
  "scope": "movies:read"              // Custom claim — what this client can do
}
```

---

## 6. JWS Serialization Formats

### 6.1 Compact Serialization

```
Format:  BASE64URL(header).BASE64URL(payload).BASE64URL(signature)
Length:  ~300-500 chars for RS256
Use:     HTTP Authorization Bearer header, URL params, cookies
Limit:   Single signature only

curl -H "Authorization: Bearer eyJhbGci..." http://localhost:8080/api/movies
```

### 6.2 Flattened JSON Serialization

```json
{
  "protected": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImF1dGgtc2VydmVyLWtleS0wMSJ9",
  "header":    { "kid": "auth-server-key-01" },
  "payload":   "eyJzdWIiOiJ1c2VyMTIzIn0",
  "signature": "SflKxwRJSMeKKF2QT4fw..."
}
```
- Single signature in JSON format
- Allows `header` (unprotected, not signed) + `protected` (signed)

### 6.3 General JSON Serialization (Multiple Signatures)

```json
{
  "payload": "eyJzdWIiOiJ1c2VyMTIzIn0",
  "signatures": [
    {
      "protected": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0wMSJ9",
      "header": { "kid": "key-01" },
      "signature": "first_signature..."
    },
    {
      "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0wMiJ9",
      "header": { "kid": "key-02" },
      "signature": "second_signature..."
    }
  ]
}
```
- Multiple signers with different algorithms
- Used in Open Banking (PSD2), supply chain, legal docs

---

## 7. JWS Algorithms — Complete Reference (RFC 7518)

RFC 7518 (JWA) defines which algorithms are valid for JWS:

| Algorithm | `alg` Value | Type | Key Type | Security Level | Use Case |
|-----------|-------------|------|----------|----------------|----------|
| HMAC SHA-256 | `HS256` | Symmetric | Shared Secret | Good | Single service, internal |
| HMAC SHA-384 | `HS384` | Symmetric | Shared Secret | Better | Internal APIs |
| HMAC SHA-512 | `HS512` | Symmetric | Shared Secret | Best HMAC | Internal APIs |
| RSASSA-PKCS1-v1_5 SHA-256 | `RS256` | Asymmetric | RSA-2048+ | **Industry Standard** | **OAuth2, APIs** |
| RSASSA-PKCS1-v1_5 SHA-384 | `RS384` | Asymmetric | RSA-3072+ | Higher | Government |
| RSASSA-PKCS1-v1_5 SHA-512 | `RS512` | Asymmetric | RSA-4096+ | Highest RSA | High security |
| RSASSA-PSS SHA-256 | `PS256` | Asymmetric | RSA-2048+ | Better than RS256 | FAPI, Open Banking |
| RSASSA-PSS SHA-384 | `PS384` | Asymmetric | RSA-3072+ | Higher | FAPI |
| RSASSA-PSS SHA-512 | `PS512` | Asymmetric | RSA-4096+ | Highest | FAPI |
| ECDSA P-256 SHA-256 | `ES256` | Asymmetric | EC P-256 | Compact + Fast | Mobile, IoT |
| ECDSA P-384 SHA-384 | `ES384` | Asymmetric | EC P-384 | Higher | Financial |
| ECDSA P-521 SHA-512 | `ES512` | Asymmetric | EC P-521 | Highest EC | Government |
| EdDSA (Ed25519) | `EdDSA` | Asymmetric | Ed25519 | Modern + Fast | New projects |
| None | `none` | None | None | 🚫 INSECURE | **NEVER use** |

**In our POC**: We use `RS256` (RSA-2048) — the most widely supported standard.

---

## 8. Spring Boot + Java Implementation

### 8.1 Project Setup

**build.gradle** (for JWS module):

```gradle
plugins {
    id 'org.springframework.boot' version '3.4.3'
    id 'io.spring.dependency-management' version '1.1.7'
    id 'java'
}

java { sourceCompatibility = JavaVersion.VERSION_21 }

dependencies {
    // Spring Boot Web
    implementation 'org.springframework.boot:spring-boot-starter-web'

    // Spring Security OAuth2 Resource Server (for JWT/JWS validation)
    implementation 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'

    // Nimbus JOSE + JWT — primary JWS library
    implementation 'com.nimbusds:nimbus-jose-jwt:9.37.3'

    // BouncyCastle — advanced crypto (EdDSA, PS256, certificate operations)
    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'
    implementation 'org.bouncycastle:bcpkix-jdk18on:1.78.1'

    // H2 for audit (optional)
    runtimeOnly 'com.h2database:h2'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'

    // Lombok
    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.projectlombok:lombok'

    // Testing
    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    testImplementation 'org.springframework.security:spring-security-test'
}
```

---

### 8.2 JWS Signing Service

```java
package com.poc.jwkpoc.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * JWS Signing Service — RFC 7515
 *
 * Implements Section 5.1 (Producing a JWS):
 * 1. Create JOSE Header with alg + kid
 * 2. Create payload (JWT claims for JWT use case)
 * 3. Compute JWS Signing Input = BASE64URL(header).BASE64URL(payload)
 * 4. Sign using private key → JWS Signature
 * 5. Return JWS Compact Serialization
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class JwsSigningService {

    private final JwkRotationService rotationService;

    /**
     * Produce a JWS token (RFC 7515 §5.1)
     *
     * @param subject  sub claim — who is this token about
     * @param audience aud claim — who should accept this
     * @param scope    custom scope claim
     * @param ttlSecs  token lifetime in seconds
     * @return JWS Compact Serialization: header.payload.signature
     */
    public String sign(String subject, String audience, String scope, long ttlSecs) throws JOSEException {
        // Step 1: Get current signing key (private key for signing)
        RSAKey signingKey = rotationService.getCurrentSigningKey();

        // Step 2: Build JOSE Header (RFC 7515 §4.1)
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)    // §4.1.1 alg
                .keyID(signingKey.getKeyID())                            // §4.1.4 kid
                .type(JOSEObjectType.JWT)                                // §4.1.9 typ
                .build();

        log.debug("Signing with kid={}, alg=RS256", signingKey.getKeyID());

        // Step 3: Build JWS Payload (JWT Claims — RFC 7519)
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("http://localhost:9000")         // iss — our auth-server
                .subject(subject)                        // sub — who the token is for
                .audience(audience)                      // aud — who should verify
                .issueTime(Date.from(now))               // iat
                .notBeforeTime(Date.from(now))           // nbf
                .expirationTime(Date.from(now.plusSeconds(ttlSecs))) // exp
                .jwtID(UUID.randomUUID().toString())     // jti — unique ID
                .claim("scope", scope)                   // custom claim
                .build();

        // Step 4: Create SignedJWT = header + claims
        SignedJWT signedJWT = new SignedJWT(header, claims);

        // Step 5: Compute signature (RFC 7515 §5.1 Steps 6-7)
        // JWS Signing Input = ASCII(BASE64URL(header) + "." + BASE64URL(claims))
        RSASSASigner signer = new RSASSASigner(signingKey);
        signedJWT.sign(signer);

        // Step 6: Return JWS Compact Serialization (RFC 7515 §7.1)
        String jwsToken = signedJWT.serialize();
        log.info("Signed JWT issued. kid={}, sub={}, exp={}", signingKey.getKeyID(), subject, now.plusSeconds(ttlSecs));

        return jwsToken;
    }
}
```

---

### 8.3 JWS Verification Service

```java
package com.poc.jwkpoc.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.Date;
import java.util.Set;

/**
 * JWS Verification Service — RFC 7515 §5.2
 *
 * Implements Section 5.2 (Validating a JWS):
 * 1. Parse Compact Serialization → header + payload + signature
 * 2. Validate header (alg whitelist, kid lookup)
 * 3. Identify verification key from kid + JWKS
 * 4. Reconstruct JWS Signing Input
 * 5. Verify signature
 * 6. Validate claims (exp, nbf, iss, aud)
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class JwsVerificationService {

    private final JwkRotationService rotationService;

    /**
     * Verify a JWS token (RFC 7515 §5.2)
     *
     * @param compactJws The JWS Compact Serialization token
     * @param expectedAudience Expected audience value
     * @return JWTClaimsSet if valid
     * @throws Exception if invalid
     */
    public JWTClaimsSet verify(String compactJws, String expectedAudience) throws Exception {
        // Step 1: Parse the JWS Compact Serialization
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(compactJws);
        } catch (ParseException e) {
            log.warn("Failed to parse JWS token: {}", e.getMessage());
            throw new IllegalArgumentException("Invalid JWS format", e);
        }

        // Step 2: Read header — check alg (RFC 7515 §4.1.1)
        String algValue = signedJWT.getHeader().getAlgorithm().getName();
        String kid = signedJWT.getHeader().getKeyID();
        log.debug("Verifying JWS: alg={}, kid={}", algValue, kid);

        // Step 3: Algorithm whitelist check (RFC 7515 §8.8 — alg:none attack prevention)
        if ("none".equals(algValue)) {
            throw new SecurityException("Unsecured JWS (alg=none) is not accepted");
        }

        // Step 4: Build JWT Processor with JWKS key source
        JWKSet publicJwkSet = rotationService.getPublicJwkSet();
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
                JWSAlgorithm.RS256,
                new ImmutableJWKSet<>(publicJwkSet)
        );
        jwtProcessor.setJWSKeySelector(keySelector);

        // Step 5: Claims validation (exp, nbf, iss, aud)
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                new JWTClaimsSet.Builder()
                        .issuer("http://localhost:9000")
                        .audience(expectedAudience)
                        .build(),
                Set.of("sub", "iat", "jti")  // required claims
        ));

        // Step 6: Process — this runs full RFC 7515 §5.2 validation
        JWTClaimsSet claims = jwtProcessor.process(compactJws, null);
        log.info("JWS verified successfully. sub={}, kid={}", claims.getSubject(), kid);

        return claims;
    }

    /**
     * Quick parse without full verification — for debugging only.
     * NEVER use in production for authorization decisions.
     */
    public JWTClaimsSet parseUnverified(String compactJws) throws ParseException {
        log.warn("⚠️ Parsing JWT WITHOUT verification — debug only!");
        return SignedJWT.parse(compactJws).getJWTClaimsSet();
    }
}
```

---

### 8.4 JWS Controller — REST Endpoints

```java
package com.poc.jwkpoc.controller;

import com.nimbusds.jwt.JWTClaimsSet;
import com.poc.jwkpoc.service.JwsSigningService;
import com.poc.jwkpoc.service.JwsVerificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * JWS Token Controller
 *
 * Demonstrates RFC 7515 JWS operations:
 * POST /api/jws/sign   — produce a JWS token
 * POST /api/jws/verify — validate a JWS token
 * GET  /api/jws/info   — show decoded claims from current JWT
 */
@RestController
@RequestMapping("/api/jws")
@RequiredArgsConstructor
@Slf4j
public class JwsController {

    private final JwsSigningService signingService;
    private final JwsVerificationService verificationService;

    /**
     * POST /api/jws/sign
     * Produces a new JWS token (RFC 7515 §5.1)
     */
    @PostMapping("/sign")
    public ResponseEntity<Map<String, Object>> sign(@RequestBody SignRequest request) throws Exception {
        String jwsToken = signingService.sign(
                request.subject(),
                request.audience(),
                request.scope(),
                3600L  // 1 hour TTL
        );

        // Decode header to show kid
        String[] parts = jwsToken.split("\\.");
        String header = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));

        return ResponseEntity.ok(Map.of(
                "jws_token", jwsToken,
                "header_decoded", header,
                "format", "JWS Compact Serialization (RFC 7515 §7.1)",
                "parts", Map.of(
                        "part1_header", parts[0],
                        "part2_payload", parts[1],
                        "part3_signature", parts[2].substring(0, 20) + "..."
                )
        ));
    }

    /**
     * POST /api/jws/verify
     * Validates a JWS token (RFC 7515 §5.2)
     */
    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verify(@RequestBody VerifyRequest request) {
        try {
            JWTClaimsSet claims = verificationService.verify(
                    request.jwsToken(),
                    "resource-server"
            );

            return ResponseEntity.ok(Map.of(
                    "valid", true,
                    "subject", claims.getSubject(),
                    "issuer", claims.getIssuer(),
                    "expiration", claims.getExpirationTime(),
                    "scope", claims.getStringClaim("scope"),
                    "rfc7515_validation", "All steps in §5.2 passed"
            ));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "valid", false,
                    "error", e.getMessage()
            ));
        }
    }

    /**
     * GET /api/jws/info
     * Show info from the currently presented JWT (already validated by Spring Security)
     */
    @GetMapping("/info")
    public ResponseEntity<Map<String, Object>> info(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(Map.of(
                "sub", jwt.getSubject(),
                "iss", jwt.getIssuer().toString(),
                "kid", jwt.getHeaders().get("kid"),
                "alg", jwt.getHeaders().get("alg"),
                "exp", jwt.getExpiresAt(),
                "scope", jwt.getClaimAsString("scope"),
                "jose_header_params", Map.of(
                        "alg", jwt.getHeaders().get("alg"),       // RFC 7515 §4.1.1
                        "kid", jwt.getHeaders().get("kid"),       // RFC 7515 §4.1.4
                        "typ", jwt.getHeaders().get("typ")        // RFC 7515 §4.1.9
                )
        ));
    }

    record SignRequest(String subject, String audience, String scope) {}
    record VerifyRequest(String jwsToken) {}
}
```

---

### 8.5 Spring Security Filter — JWS Validation

```java
package com.poc.jwkpoc.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Custom JWS Validation Filter
 *
 * Demonstrates manual JWS header extraction and validation.
 * Spring Security's BearerTokenAuthenticationFilter handles this
 * automatically — this is for EDUCATIONAL purposes.
 */
@Slf4j
@RequiredArgsConstructor
public class JwsValidationFilter extends OncePerRequestFilter {

    private final JwtDecoder jwtDecoder;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        // RFC 6750: Bearer Token — extract from Authorization header
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String jwsToken = authHeader.substring(7);  // Remove "Bearer "
            String[] parts = jwsToken.split("\\.");

            if (parts.length == 3) {
                log.debug("JWS Compact Serialization detected:");
                log.debug("  Part 1 (Header):    {} chars", parts[0].length());
                log.debug("  Part 2 (Payload):   {} chars", parts[1].length());
                log.debug("  Part 3 (Signature): {} chars", parts[2].length());

                try {
                    // Decode header to log kid (RFC 7515 §4.1.4)
                    String headerJson = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
                    log.debug("  JOSE Header: {}", headerJson);

                    Jwt jwt = jwtDecoder.decode(jwsToken);
                    log.debug("  Signature verified ✅ for sub={}", jwt.getSubject());
                } catch (JwtException e) {
                    log.warn("  Signature verification FAILED ❌: {}", e.getMessage());
                }
            }
        }

        chain.doFilter(request, response);
    }
}
```

---

### 8.6 Detached JWS — RFC 7797

```java
package com.poc.jwkpoc.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

/**
 * Detached JWS Service — RFC 7797
 *
 * Detached Content: payload is NOT embedded in the JWS token.
 * Used in: Open Banking (PSD2), large payload signing, webhook signing.
 *
 * JWS Token format:  BASE64URL(header)..BASE64URL(signature)
 *                                     ↑↑ double dot = detached payload
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class DetachedJwsService {

    private final JwkRotationService rotationService;

    /**
     * Sign with detached payload (RFC 7797)
     *
     * @param payloadBytes The raw payload bytes (e.g., HTTP request body)
     * @return JWS token WITHOUT payload: BASE64URL(header)..BASE64URL(signature)
     */
    public String signDetached(byte[] payloadBytes) throws JOSEException {
        RSAKey signingKey = rotationService.getCurrentSigningKey();

        // RFC 7797 §4 — b64 header parameter
        // When b64=false, payload is NOT base64url encoded before signing
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(signingKey.getKeyID())
                .base64URLEncodePayload(false)  // RFC 7797: raw payload
                .criticalParams(Set.of("b64"))  // RFC 7515 §4.1.11 crit
                .build();

        // Create payload reference
        Payload payload = new Payload(payloadBytes);

        // Create JWS object
        JWSObject jwsObject = new JWSObject(header, payload);
        jwsObject.sign(new RSASSASigner(signingKey));

        // Serialize with DETACHED payload — returns header..signature (double dot)
        return jwsObject.serializeDetachedPayload();
    }

    /**
     * Verify a detached JWS (RFC 7797)
     *
     * @param detachedJwsToken The JWS header..signature token (without payload)
     * @param payloadBytes The actual payload bytes (transmitted separately)
     */
    public boolean verifyDetached(String detachedJwsToken, byte[] payloadBytes) throws Exception {
        // Parse detached JWS — must provide payload separately
        JWSObject jwsObject = JWSObject.parseDetachedPayload(
                detachedJwsToken,
                new Base64URL(Base64URL.encode(payloadBytes).toString())
        );

        // Find verification key from kid
        String kid = jwsObject.getHeader().getKeyID();
        RSAKey publicKey = (RSAKey) rotationService.getPublicJwkSet()
                .getKeyByKeyId(kid);

        if (publicKey == null) {
            throw new IllegalArgumentException("Unknown kid: " + kid);
        }

        return jwsObject.verify(new RSASSAVerifier(publicKey.toRSAPublicKey()));
    }
}
```

---

### 8.7 Unit Tests for JWS

```java
package com.poc.jwkpoc.service;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.*;

/**
 * JWS Service Tests — RFC 7515 §5.1 and §5.2
 */
@SpringBootTest
@DisplayName("JWS — RFC 7515 Signing and Verification")
class JwsServiceTest {

    @Autowired JwsSigningService signingService;
    @Autowired JwsVerificationService verificationService;

    @Nested
    @DisplayName("JWS Compact Serialization Structure (RFC 7515 §7.1)")
    class CompactSerializationTests {

        @Test
        @DisplayName("Signed token must have exactly 3 parts separated by dots")
        void signedTokenHasThreeParts() throws Exception {
            String jwsToken = signingService.sign("user123", "resource-server", "movies:read", 3600);
            String[] parts = jwsToken.split("\\.");
            assertThat(parts).hasSize(3);
        }

        @Test
        @DisplayName("Header must contain alg=RS256 (RFC 7515 §4.1.1)")
        void headerContainsAlgRS256() throws Exception {
            String jwsToken = signingService.sign("user123", "resource-server", "movies:read", 3600);
            String headerJson = new String(Base64.getUrlDecoder().decode(jwsToken.split("\\.")[0]));
            assertThat(headerJson).contains("\"alg\":\"RS256\"");
        }

        @Test
        @DisplayName("Header must contain kid (RFC 7515 §4.1.4)")
        void headerContainsKid() throws Exception {
            String jwsToken = signingService.sign("user123", "resource-server", "movies:read", 3600);
            String headerJson = new String(Base64.getUrlDecoder().decode(jwsToken.split("\\.")[0]));
            assertThat(headerJson).contains("kid");
        }

        @Test
        @DisplayName("Payload must be base64url decodable to valid JSON")
        void payloadIsDecodableJson() throws Exception {
            String jwsToken = signingService.sign("user123", "resource-server", "movies:read", 3600);
            String payloadJson = new String(Base64.getUrlDecoder().decode(jwsToken.split("\\.")[1]));
            assertThat(payloadJson).contains("user123");
            assertThat(payloadJson).contains("resource-server");
        }
    }

    @Nested
    @DisplayName("JWS Verification (RFC 7515 §5.2)")
    class VerificationTests {

        @Test
        @DisplayName("Valid JWS token should verify successfully")
        void validTokenVerifiesSuccessfully() throws Exception {
            String jwsToken = signingService.sign("test-client", "resource-server", "movies:read", 3600);
            JWTClaimsSet claims = verificationService.verify(jwsToken, "resource-server");
            assertThat(claims.getSubject()).isEqualTo("test-client");
        }

        @Test
        @DisplayName("Tampered payload must fail signature verification")
        void tamperedPayloadFails() throws Exception {
            String jwsToken = signingService.sign("user123", "resource-server", "movies:read", 3600);
            String[] parts = jwsToken.split("\\.");
            // Tamper: replace payload with different claims
            String tamperedPayload = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"sub\":\"hacker\",\"scope\":\"admin\"}".getBytes());
            String tamperedToken = parts[0] + "." + tamperedPayload + "." + parts[2];

            assertThatThrownBy(() -> verificationService.verify(tamperedToken, "resource-server"))
                    .isInstanceOf(Exception.class);
        }

        @Test
        @DisplayName("Expired token must fail validation")
        void expiredTokenFails() throws Exception {
            // Sign with -1 TTL to create immediately expired token
            String jwsToken = signingService.sign("user123", "resource-server", "movies:read", -1);
            assertThatThrownBy(() -> verificationService.verify(jwsToken, "resource-server"))
                    .isInstanceOf(Exception.class)
                    .hasMessageContaining("expired");
        }

        @Test
        @DisplayName("Wrong audience must fail validation (RFC 7519 §4.1.3)")
        void wrongAudienceFails() throws Exception {
            String jwsToken = signingService.sign("user123", "resource-server", "movies:read", 3600);
            assertThatThrownBy(() -> verificationService.verify(jwsToken, "wrong-audience"))
                    .isInstanceOf(Exception.class);
        }

        @Test
        @DisplayName("Signature with wrong key must fail (algorithm confusion prevention)")
        void wrongKeyFails() throws Exception {
            // Sign with our key, try to verify with different JWKS
            String jwsToken = signingService.sign("user123", "resource-server", "movies:read", 3600);
            // Manipulate last char of signature
            String lastPart = jwsToken.substring(jwsToken.lastIndexOf('.') + 1);
            String badSig = lastPart.substring(0, lastPart.length() - 1) + "X";
            String tamperedToken = jwsToken.substring(0, jwsToken.lastIndexOf('.') + 1) + badSig;

            assertThatThrownBy(() -> verificationService.verify(tamperedToken, "resource-server"))
                    .isInstanceOf(Exception.class);
        }
    }

    @Nested
    @DisplayName("Security Requirements (RFC 7515 §8)")
    class SecurityTests {

        @Test
        @DisplayName("alg=none must be rejected (§8.8 — algorithm confusion attack)")
        void algNoneMustBeRejected() {
            String unsecuredJws = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJoYWNrZXIifQ.";
            assertThatThrownBy(() -> verificationService.verify(unsecuredJws, "resource-server"))
                    .isInstanceOf(Exception.class);
        }
    }
}
```

---

## 9. Phase-wise Development Plan

### Phase 1: Foundation (Week 1)
**Goal**: Set up JWS infrastructure with RS256 signing

```
Tasks:
1. JwsSigningService.java
   - sign(subject, audience, scope, ttl) → compact JWS
   - Uses RSASSASigner from Nimbus JOSE
   - RFC 7515 §5.1 compliant

2. JwsVerificationService.java
   - verify(token, expectedAudience) → JWTClaimsSet
   - RFC 7515 §5.2 compliant
   - alg:none rejection

3. Unit Tests (RFC 7515 §5.1 + §5.2 verification)
   - 3-part structure
   - alg claim
   - kid claim
   - Tamper detection
   - Expiry check
   - Audience check

Deliverable: Working RS256 JWS signing + verification
```

### Phase 2: Key Rotation Integration (Week 2)
**Goal**: Integrate with existing KeyPairRegistryService (10 RSA keys)

```
Tasks:
1. Connect JwsSigningService to KeyPairRegistryService
   - Random key selection from 10 keys for each token
   - OR round-robin key selection
   - OR dedicated signing key (key-01)

2. kid-based verification
   - Parse kid from JWS header
   - Look up from JWKS cache
   - Fallback: fetch from /.well-known/jwks.json

3. JWKS Caching (RFC 7517 §5)
   - Cache public JWKS locally
   - Refresh on kid-not-found
   - Respect Cache-Control: max-age=3600

Deliverable: Multi-key JWS with auto key discovery
```

### Phase 3: Advanced Features (Week 3)
**Goal**: Add PS256, ES256, EdDSA algorithm support

```
Tasks:
1. Multi-algorithm key store
   - RSA-2048 → RS256, PS256
   - EC P-256 → ES256
   - Ed25519 → EdDSA (requires BouncyCastle)

2. Algorithm selection strategy
   - Default: RS256 (most compatible)
   - FAPI compliant: PS256 (required for Open Banking)
   - Mobile/IoT: ES256 (smaller tokens, faster)

3. FAPI 2.0 considerations
   - PS256 mandatory
   - DPoP tokens (RFC 9449)

Deliverable: Algorithm-agile JWS service
```

### Phase 4: Detached JWS (Week 4)
**Goal**: Implement RFC 7797 (Open Banking / PSD2 patterns)

```
Tasks:
1. DetachedJwsService.java
   - signDetached(payloadBytes) → header..signature
   - verifyDetached(token, payloadBytes) → boolean

2. HTTP Middleware for Detached JWS
   - Request signing filter (client-side)
   - Request verification filter (server-side)
   - x-jws-signature header convention

3. Integration with existing MovieController
   - Secure sensitive endpoints with Detached JWS

Deliverable: RFC 7797 Detached JWS implementation
```

### Phase 5: JWS JSON Serialization (Week 5)
**Goal**: Multi-signature JWS for legal/regulatory scenarios

```
Tasks:
1. JwsJsonSerializationService.java
   - signMultiple(payload, signers[]) → JWS JSON
   - verifyAll(jwsJson) → List<VerificationResult>
   - verifyAny(jwsJson) → boolean

2. Multi-signer workflow
   - Sequential signing (each party adds signature)
   - Parallel signing (all sign same payload simultaneously)
   - Threshold signatures (n-of-m required)

3. Use Case: Movie Review Multi-Sign
   - Director signs movie details
   - Distributor counter-signs
   - Platform verifies both

Deliverable: Multi-signature JWS workflow
```

---

## 10. Security Considerations (RFC 7515 §8)

RFC 7515 Section 8 defines mandatory security requirements:

### 10.1 §8.1 — Cryptographic Strength
```
✅ Minimum RSA-2048 bits (RS256/PS256)
✅ Use EC P-256 or higher for ES256
✅ HMAC-SHA256 with secrets ≥ 256 bits for HS256
❌ NEVER use RSA-1024 (broken)
❌ NEVER use MD5 or SHA-1 based signatures
```

### 10.2 §8.2 — Key Rollover
```
✅ Regularly rotate signing keys (monthly in our POC)
✅ Maintain overlap window (2 active keys)
✅ Use kid to identify key version
✅ Retire old keys gracefully (audit trail in H2)
```

### 10.3 §8.3 — Algorithm Restrictions
```
✅ Whitelist allowed algorithms explicitly
✅ REJECT alg=none — CRITICAL
✅ REJECT algorithms not in your whitelist
✅ Use JWSAlgorithm.RS256 explicitly — not JWSAlgorithm.parse(headerValue)
```

### 10.4 §8.4 — Handling Claims
```
✅ Validate exp (expiration) BEFORE trusting claims
✅ Validate nbf (not before) if present
✅ Validate iss (issuer) against known list
✅ Validate aud (audience) — reject tokens not for you
✅ Use short token lifetimes (1 hour access, 24 hour refresh)
```

### 10.5 §8.5 — Key Identification
```
✅ Always use kid to identify signing key
✅ Validate jku URL is from trusted domain BEFORE fetching
✅ Validate jwk embedded public key against trust store
✅ NEVER blindly use a public key from the token header
```

### 10.6 §8.8 — Algorithm Confusion Attacks
```
ATTACK: Attacker changes RSA token header to HS256, signs with public key
DEFENSE:
✅ Never use string comparison for algorithm selection
✅ Explicitly specify allowed algorithms in key selector
✅ Spring Security's NimbusJwtDecoder rejects this by default

// Safe key selector — only accepts RS256:
JWSKeySelector<SecurityContext> keySelector =
    new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
// This will REJECT any token with alg != RS256
```

---

## 11. Advanced JWS Patterns

### 11.1 DPoP — Demonstrating Proof of Possession (RFC 9449)

```
Normal Bearer Token:
   Any party with the token can use it
   Stolen token = full compromise

DPoP Token:
   Token is BOUND to the client's private key
   Stolen token is USELESS without the private key

DPoP Header:
   Every request carries a DPoP proof (short-lived JWS)
   { "typ": "dpop+jwt", "alg": "ES256", "jwk": { client's public key } }
   { "htu": "https://api.example.com/movies",
     "htm": "GET",
     "iat": now,
     "jti": "unique-nonce" }

Use when: High-security APIs, financial applications
```

### 11.2 Nested JWT (JWS inside JWE)

```
JWS(claims) → signed but readable
JWE(JWS(claims)) → signed AND encrypted

Header: { "cty": "JWT" }  ← §4.1.10: payload is a JWT
        ↑ signals that outer envelope contains a JWT

Use when:
- Claims are sensitive and must not be readable by intermediaries
- End-to-end encrypted tokens in multi-hop architectures
```

### 11.3 JWT Access Tokens — RFC 9068

```
Standardized structure for OAuth2 access tokens as JWTs:

Header: { "alg": "RS256", "kid": "key-01", "typ": "at+JWT" }
                                                    ↑ RFC 9068 media type

Payload:
{
  "iss": "http://localhost:9000",
  "sub": "resource-client",
  "aud": ["resource-server"],
  "client_id": "resource-client",   ← RFC 9068 REQUIRED
  "iat": ...,
  "exp": ...,
  "jti": "...",
  "scope": "movies:read"            ← RFC 9068 REQUIRED
}
```

---

## 12. Decision Matrix

### Which Algorithm?

```
┌────────────────────────────────────────────────────────────────────────┐
│                    Algorithm Selection Guide                           │
├──────────────┬──────────────────────────────────────────────────────────┤
│ Requirement  │ Recommended Algorithm                                   │
├──────────────┼──────────────────────────────────────────────────────────┤
│ Standard API │ RS256 (RSA-2048 + SHA-256) ← OUR CHOICE               │
│ Open Banking │ PS256 (RSA-PSS 2048 + SHA-256) — FAPI mandatory       │
│ Mobile/IoT   │ ES256 (ECDSA P-256 + SHA-256) — smaller tokens       │
│ Edge Speed   │ EdDSA (Ed25519) — fastest, smallest                   │
│ Internal SVC │ HS256 (HMAC + SHA-256) — OK if same service           │
│ Government   │ RS512 or PS512 (RSA-4096) — highest assurance        │
└──────────────┴──────────────────────────────────────────────────────────┘
```

### Which Serialization?

```
┌─────────────────┬────────────────────────────────────────────────────────┐
│ Serialization   │ Use When                                               │
├─────────────────┼────────────────────────────────────────────────────────┤
│ Compact         │ HTTP Authorization Bearer token (99% of cases)        │
│ Flattened JSON  │ When you need unprotected header params               │
│ General JSON    │ Multi-signature: legal docs, Open Banking, PSD2       │
│ Detached (7797) │ Large payloads, webhook signing, Open Banking body    │
└─────────────────┴────────────────────────────────────────────────────────┘
```

### JWS vs JWE?

```
┌─────────────────────────┬────────────────┬────────────────────────────────┐
│ Requirement             │ Use            │ Why                            │
├─────────────────────────┼────────────────┼────────────────────────────────┤
│ Just verify who sent it │ JWS (RFC 7515) │ Signature only                 │
│ Claims visible to all   │ JWS (RFC 7515) │ Payload is Base64url (visible) │
│ Claims must be hidden   │ JWE (RFC 7516) │ Payload encrypted              │
│ Both visible + encrypted│ JWS inside JWE │ Sign then encrypt (nested JWT) │
└─────────────────────────┴────────────────┴────────────────────────────────┘
```

---

## Quick Reference — RFC 7515 Section Map

| Section | Topic | Key Point |
|---------|-------|-----------|
| §1 | Introduction | JWS = integrity + authenticity, not encryption |
| §2 | Terminology | JWS, Payload, JOSE Header, Signing Input definitions |
| §3.1 | Compact Serialization | 3-part dot-separated: header.payload.signature |
| §3.2 | JSON Serialization | Multi-signature support |
| §4.1.1 | `alg` parameter | REQUIRED — algorithm identifier |
| §4.1.4 | `kid` parameter | Key ID — identifies which key in JWKS |
| §4.1.9 | `typ` parameter | Token type (JWT, at+JWT) |
| §4.1.11 | `crit` parameter | Critical extensions — must understand or reject |
| §5.1 | Producing JWS | 8-step signing algorithm |
| §5.2 | Validating JWS | 8-step verification algorithm |
| §6 | Unsecured JWS | `alg=none` — MUST REJECT in production |
| §7.1 | Compact Serialization | BASE64URL(H).BASE64URL(P).BASE64URL(S) |
| §7.2 | JSON Serialization | `{ "payload": ..., "signatures": [...] }` |
| §8.8 | Algorithm Confusion | Whitelist algorithms — reject `alg=none` |

---

*Document maintained at: `docs/jws/plan.md`*
*Last updated: 2026-03-04*
*RFC References: RFC 7515 (JWS), RFC 7516 (JWE), RFC 7517 (JWK), RFC 7518 (JWA), RFC 7519 (JWT), RFC 7797 (Detached JWS), RFC 9068 (JWT Access Tokens), RFC 9449 (DPoP)*
