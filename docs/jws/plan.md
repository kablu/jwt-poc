# JWS (JSON Web Signature) — Complete Brainstorming & Implementation Plan

> RFC 7515 — JSON Web Signature (JWS) | Author: Kablu | Date: 2026-03-04

---

## Table of Contents

1. [What is JWS? — RFC 7515 Deep Dive](#1-what-is-jws--rfc-7515-deep-dive)
2. [JWS vs JWT vs JWK — Key Differences](#2-jws-vs-jwt-vs-jwk--key-differences)
3. [JWS Structure Anatomy](#3-jws-structure-anatomy)
4. [JWS Serialization Formats](#4-jws-serialization-formats)
5. [JWS Algorithms — Complete Reference](#5-jws-algorithms--complete-reference)
6. [JWS Use Cases](#6-jws-use-cases)
7. [Spring Boot Implementation Approaches](#7-spring-boot-implementation-approaches)
8. [Implementation Deep Dives](#8-implementation-deep-dives)
9. [JWS in PKI / Certificate Context](#9-jws-in-pki--certificate-context)
10. [JWS Detached Payload](#10-jws-detached-payload)
11. [Multi-Signature JWS (JSON Serialization)](#11-multi-signature-jws-json-serialization)
12. [Security Considerations](#12-security-considerations)
13. [Tools, Libraries & Ecosystem](#13-tools-libraries--ecosystem)
14. [Decision Matrix — Which Approach to Use?](#14-decision-matrix--which-approach-to-use)
15. [Open Questions & Future Exploration](#15-open-questions--future-exploration)

---

## 1. What is JWS? — RFC 7515 Deep Dive

**JWS = JSON Web Signature** — a standard for representing **digitally signed** or **MACed** content using JSON-based data structures.

RFC 7515 defines:
- How to represent a **signed message** in compact or JSON form
- How to represent the **signing algorithm** and **key reference** in the header
- How the **signature** is computed and verified
- Part of the JOSE (JSON Object Signing and Encryption) suite:
  - RFC 7515 — JWS (JSON Web Signature) ← **this**
  - RFC 7516 — JWE (JSON Web Encryption)
  - RFC 7517 — JWK (JSON Web Key)
  - RFC 7518 — JWA (JSON Web Algorithms)
  - RFC 7519 — JWT (JSON Web Token)

### Core Concept

```
Payload (any content)  +  Signing Key  →  JWS (signed message)
                                              │
                                    Anyone with public key
                                    can VERIFY the signature
```

### Why JWS?

```
Problem:   Data transport mein tamper ho sakta hai
Solution:  JWS signature guarantee karta hai:
           ✅ Integrity   — data tamper nahi hua
           ✅ Authenticity — sahi source ne sign kiya
           ✅ Non-repudiation — signer deny nahi kar sakta (asymmetric only)
```

### JWS vs Simple Signature

| Aspect             | Traditional Signature    | JWS (RFC 7515)                     |
|--------------------|--------------------------|-------------------------------------|
| Format             | Binary (DER/PEM)         | JSON / Base64URL text               |
| Transport          | Binary protocols         | HTTP, REST APIs                     |
| Metadata           | None                     | alg, kid, x5t, typ embedded         |
| Multi-signature    | Complex                  | Built-in (JSON Serialization)       |
| Interoperability   | Platform-specific        | Language-agnostic                   |
| Key reference      | Out-of-band              | kid / x5t in header                 |

---

## 2. JWS vs JWT vs JWK — Key Differences

> Teen alag specs — teen alag problems solve karte hain

```
┌─────────────────────────────────────────────────────────────────┐
│  JWK  = KEY          (RFC 7517) — Key represent karta hai       │
│  JWS  = SIGNED DATA  (RFC 7515) — Data sign karta hai          │
│  JWT  = JWS + CLAIMS (RFC 7519) — JWS jisme JSON claims hain   │
└─────────────────────────────────────────────────────────────────┘

JWT is a SPECIAL CASE of JWS
  → JWT = JWS where payload = JSON claims set
  → JWS = more general (payload = ANYTHING — XML, binary, JSON)
```

### Comparison Table

| Aspect            | JWK (RFC 7517)          | JWS (RFC 7515)               | JWT (RFC 7519)                |
|-------------------|-------------------------|-------------------------------|-------------------------------|
| **Kya hai**       | Cryptographic KEY        | Signed DATA container         | Signed CLAIMS token           |
| **Payload**       | Key material (n, e, d)   | Any bytes                     | JSON claims (sub, iss, exp)   |
| **Purpose**       | Key distribution         | Data integrity + authenticity | Authentication, Authorization |
| **Dependency**    | Independent              | Needs JWK for key             | Built on JWS                  |
| **Header**        | No header                | JOSE header (alg, kid)        | JOSE header (alg, kid, typ)   |
| **Example**       | RSA public key           | Signed API request body       | Access token, ID token        |

### Relationship Diagram

```
JWA (RFC 7518) — Algorithms
  └── defines: RS256, HS256, ES256, PS256...

JWK (RFC 7517) — Keys
  └── stores: RSA key, EC key, symmetric key

JWS (RFC 7515) — Signing
  └── uses: JWA algorithms + JWK keys
  └── produces: Compact / JSON serialized signed content

JWT (RFC 7519) — Token
  └── IS-A: JWS where payload = JSON claims
  └── adds: sub, iss, exp, aud claim semantics
```

---

## 3. JWS Structure Anatomy

### Compact Serialization (Most Common)

```
BASE64URL(JWS Header) . BASE64URL(JWS Payload) . BASE64URL(JWS Signature)

Example:
eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0wMSJ9    ← Header (Base64URL)
.
eyJkYXRhIjoiSGVsbG8gV29ybGQiLCJ0cyI6MTcwOX0   ← Payload (Base64URL)
.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c   ← Signature (Base64URL)
```

### JWS Header — JOSE Header Parameters

```
┌─────────────────────────────────────────────────────────────────┐
│                      JOSE HEADER                                │
│                                                                 │
│  alg   [REQUIRED]  Algorithm: RS256 | ES256 | HS256 | PS256    │
│  kid   [OPTIONAL]  Key ID — JWK set mein key dhundne ke liye   │
│  typ   [OPTIONAL]  Type: "JWT" | "JWS" | "JOSE"               │
│  cty   [OPTIONAL]  Content Type: "JSON" | "application/json"  │
│  jku   [OPTIONAL]  JWK Set URL — keys ka URL                  │
│  jwk   [OPTIONAL]  Embedded JWK — public key in header         │
│  x5u   [OPTIONAL]  X.509 Certificate URL                       │
│  x5c   [OPTIONAL]  X.509 Certificate Chain (DER encoded)       │
│  x5t   [OPTIONAL]  X.509 SHA-1 Thumbprint                      │
│  x5t#S256 [OPTIONAL] X.509 SHA-256 Thumbprint                  │
│  crit  [OPTIONAL]  Critical extensions list                     │
└─────────────────────────────────────────────────────────────────┘
```

### JWS Header Examples

```json
// Minimal Header — symmetric (HMAC)
{
  "alg": "HS256"
}

// Asymmetric with key reference
{
  "alg": "RS256",
  "kid": "auth-server-key-01",
  "typ": "JWS"
}

// With embedded public JWK
{
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
  }
}

// With X.509 Certificate
{
  "alg": "RS256",
  "x5t#S256": "sha256-thumbprint-base64url",
  "x5c": ["MIIEpAIBAAKCAQEA..."]
}
```

### Signature Computation

```
JWS Signing Input = ASCII(BASE64URL(UTF8(JWS Header)) || '.' || BASE64URL(JWS Payload))

Signature = Sign(JWS Signing Input, PrivateKey, Algorithm)

Final JWS  = BASE64URL(Header) + "." + BASE64URL(Payload) + "." + BASE64URL(Signature)
```

---

## 4. JWS Serialization Formats

### Format 1: Compact Serialization (Default)

```
header.payload.signature

Use Case: HTTP headers, URL parameters, cookies
Limitation: Single signature only
```

```
eyJhbGciOiJSUzI1NiJ9.eyJkYXRhIjoiSGVsbG8ifQ.SflKxwRJSMeKKF2QT4fw
```

### Format 2: JSON Serialization (Multi-signature)

```json
{
  "payload": "eyJkYXRhIjoiSGVsbG8gV29ybGQifQ",
  "signatures": [
    {
      "protected": "eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS1rZXkifQ",
      "header":    { "kid": "rsa-key-01" },
      "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB..."
    },
    {
      "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImVjLWtleSJ9",
      "header":    { "kid": "ec-key-01" },
      "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM..."
    }
  ]
}
```

### Format 3: Flattened JSON Serialization (Single signature, JSON form)

```json
{
  "payload":   "eyJkYXRhIjoiSGVsbG8gV29ybGQifQ",
  "protected": "eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS1rZXkifQ",
  "header":    { "kid": "rsa-key-01" },
  "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB..."
}
```

### Which Serialization to Use?

```
Compact    → REST APIs, JWT tokens, HTTP headers   (most common)
JSON       → Multi-signature workflows, document signing
Flattened  → Single signature + non-protected headers needed
```

---

## 5. JWS Algorithms — Complete Reference

### Asymmetric Algorithms (Recommended)

```
RSA:
  RS256  = RSASSA-PKCS1-v1_5 + SHA-256  (Most widely supported)
  RS384  = RSASSA-PKCS1-v1_5 + SHA-384
  RS512  = RSASSA-PKCS1-v1_5 + SHA-512
  PS256  = RSASSA-PSS + SHA-256          (More secure than PKCS1)
  PS384  = RSASSA-PSS + SHA-384
  PS512  = RSASSA-PSS + SHA-512

Elliptic Curve:
  ES256  = ECDSA + P-256 + SHA-256       (Smaller keys, faster)
  ES384  = ECDSA + P-384 + SHA-384
  ES512  = ECDSA + P-521 + SHA-512

EdDSA (Modern):
  EdDSA  = Ed25519 or Ed448              (Fastest, most secure)
```

### Symmetric Algorithms (Shared Secret)

```
HMAC:
  HS256  = HMAC + SHA-256
  HS384  = HMAC + SHA-384
  HS512  = HMAC + SHA-512

  ⚠️ WARNING: Both parties share same secret — no non-repudiation
```

### Special Value

```
  none   = No signature (UNSECURED JWS)
  ⛔ NEVER use in production — security vulnerability!
```

### Algorithm Selection Guide

```
┌──────────────────────────────────────────────────────────────┐
│                  ALGORITHM DECISION TREE                      │
│                                                               │
│  Need non-repudiation?                                        │
│    YES → Asymmetric (RSA or EC)                              │
│      Performance critical? → ES256 (EC is faster than RSA)  │
│      Wide compatibility?   → RS256 (RSA everywhere)          │
│      Maximum security?     → PS256 (PSS > PKCS1)            │
│      Modern stack?         → EdDSA (Ed25519)                 │
│    NO  → Symmetric (HS256) — microservices internal only     │
│                                                               │
│  Key Size:                                                    │
│    RSA: 2048 min, 4096 preferred                             │
│    EC:  P-256 (128-bit security)                             │
│    Ed:  Ed25519 (255-bit key = 128-bit security)             │
└──────────────────────────────────────────────────────────────┘
```

---

## 6. JWS Use Cases

```
1. API Request Signing
   Client signs HTTP request body → Server verifies before processing
   Used in: Open Banking (UK), PSD2 (EU), AWS Signature V4

2. JWT Tokens
   JWT = JWS where payload = JSON claims
   Access tokens, ID tokens, refresh tokens

3. Document Signing
   Legal documents, contracts, audit logs
   Multi-signature workflow (JSON Serialization)

4. Webhook Payload Signing
   GitHub, Stripe, Twilio sign webhook payloads with HMAC-SHA256
   Receiver verifies before processing

5. Software Artifact Signing
   JAR signing, container image signing (Sigstore/Cosign)
   Supply chain security

6. ACME Protocol (Let's Encrypt)
   JWS used for all ACME API requests
   Account keys, challenge responses

7. DPoP — Demonstrating Proof of Possession (RFC 9449)
   Client sends JWS proof with each API request
   Binds token to client's key pair

8. mTLS Certificate Binding
   JWS thumbprint ties access token to TLS certificate

9. Verifiable Credentials (W3C)
   JWS used to sign credentials in digital identity systems

10. PSD2 / Open Banking
    API requests signed using JWS for financial regulation compliance
```

---

## 7. Spring Boot Implementation Approaches

```
APPROACH 1: Manual JWS with Nimbus JOSE + JWT
            Full control, sign/verify any payload

APPROACH 2: Spring Security JWS Filter
            Verify incoming signed requests via filter

APPROACH 3: JWS for Webhook Signing / Verification
            Sign outgoing webhooks, verify incoming

APPROACH 4: Detached JWS (Payload not in token)
            HTTP message signing (FAPI, Open Banking)

APPROACH 5: Multi-Signature JWS (JSON Serialization)
            Multiple parties sign same document

APPROACH 6: JWS with X.509 Certificates (PKI)
            Certificate chain in JWS header (x5c)

APPROACH 7: JWS Request Object (JAR — RFC 9101)
            OAuth2 signed request objects

APPROACH 8: DPoP Proof (RFC 9449)
            Client-generated JWS proof per request
```

---

## 8. Implementation Deep Dives

### Approach 1: Manual JWS with Nimbus JOSE + JWT

**Best for:** Signing any arbitrary payload — not just JWT claims.

**Dependencies (build.gradle):**

```gradle
implementation 'com.nimbusds:nimbus-jose-jwt:9.37.3'
implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'
```

**JWS Signing Service:**

```java
@Service
@RequiredArgsConstructor
@Slf4j
public class JwsSigningService {

    private final JwkRotationService jwkRotationService;

    /**
     * Sign any payload as JWS Compact Serialization
     * Payload can be JSON, XML, plain text, or any bytes
     *
     * @param payload  Raw string payload to sign
     * @return         Compact JWS: header.payload.signature
     */
    public String sign(String payload) {
        RSAKey signingKey = jwkRotationService.getCurrentSigningKey();
        try {
            JWSSigner signer = new RSASSASigner(signingKey);

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(signingKey.getKeyID())
                .type(new JOSEObjectType("JWS"))
                .build();

            JWSObject jwsObject = new JWSObject(
                header,
                new Payload(payload)          // Payload = any content
            );

            jwsObject.sign(signer);
            String compactJws = jwsObject.serialize();

            log.debug("Signed payload with kid={}", signingKey.getKeyID());
            return compactJws;

        } catch (JOSEException e) {
            throw new JwsException("Failed to sign payload", e);
        }
    }

    /**
     * Sign with EC key (ES256) — faster than RSA
     */
    public String signWithEc(String payload, ECKey ecKey) {
        try {
            JWSSigner signer = new ECDSASigner(ecKey);

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(ecKey.getKeyID())
                .build();

            JWSObject jwsObject = new JWSObject(header, new Payload(payload));
            jwsObject.sign(signer);
            return jwsObject.serialize();

        } catch (JOSEException e) {
            throw new JwsException("Failed to sign with EC key", e);
        }
    }

    /**
     * Sign with HMAC (HS256) — symmetric, shared secret
     * Use only for internal microservice-to-microservice calls
     */
    public String signWithHmac(String payload, OctetSequenceKey hmacKey) {
        try {
            JWSSigner signer = new MACSigner(hmacKey);

            JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
            JWSObject jwsObject = new JWSObject(header, new Payload(payload));
            jwsObject.sign(signer);
            return jwsObject.serialize();

        } catch (JOSEException e) {
            throw new JwsException("Failed to sign with HMAC", e);
        }
    }

    /**
     * Sign binary payload (file, image, document)
     */
    public String signBinary(byte[] binaryPayload, RSAKey signingKey) {
        try {
            JWSSigner signer = new RSASSASigner(signingKey);

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(signingKey.getKeyID())
                .contentType("application/octet-stream")
                .build();

            JWSObject jwsObject = new JWSObject(
                header,
                new Payload(Base64URL.encode(binaryPayload))
            );

            jwsObject.sign(signer);
            return jwsObject.serialize();

        } catch (JOSEException e) {
            throw new JwsException("Failed to sign binary payload", e);
        }
    }
}
```

**JWS Verification Service:**

```java
@Service
@RequiredArgsConstructor
@Slf4j
public class JwsVerificationService {

    private final JwkRotationService jwkRotationService;

    /**
     * Verify a compact JWS string
     * Finds the correct key by kid in header, then verifies signature
     *
     * @param compactJws  header.payload.signature string
     * @return            Verified payload string
     */
    public String verify(String compactJws) {
        try {
            JWSObject jwsObject = JWSObject.parse(compactJws);
            String kid = jwsObject.getHeader().getKeyID();

            // Find matching public key from JWKS by kid
            JWKSet publicJwkSet = jwkRotationService.getPublicJwkSet();
            JWK matchedKey = publicJwkSet.getKeyByKeyId(kid);

            if (matchedKey == null) {
                throw new JwsException("No matching public key found for kid=" + kid);
            }

            // Verify signature
            JWSVerifier verifier = new RSASSAVerifier((RSAKey) matchedKey);
            boolean valid = jwsObject.verify(verifier);

            if (!valid) {
                throw new JwsException("JWS signature verification FAILED");
            }

            log.debug("JWS verified successfully with kid={}", kid);
            return jwsObject.getPayload().toString();

        } catch (ParseException | JOSEException e) {
            throw new JwsException("JWS verification error: " + e.getMessage(), e);
        }
    }

    /**
     * Parse JWS header without verification — for inspection only
     * ⚠️ Do NOT use for security decisions
     */
    public Map<String, Object> parseHeaderUnverified(String compactJws) {
        try {
            JWSObject jwsObject = JWSObject.parse(compactJws);
            return Map.of(
                "algorithm", jwsObject.getHeader().getAlgorithm().getName(),
                "kid",       jwsObject.getHeader().getKeyID(),
                "type",      jwsObject.getHeader().getType() != null
                             ? jwsObject.getHeader().getType().getType() : "none"
            );
        } catch (ParseException e) {
            throw new JwsException("Failed to parse JWS header", e);
        }
    }
}
```

---

### Approach 2: Spring Security JWS Filter

**Best for:** Verifying signed HTTP requests at API gateway level.

```java
@Component
@RequiredArgsConstructor
@Slf4j
public class JwsRequestVerificationFilter extends OncePerRequestFilter {

    private final JwsVerificationService jwsVerificationService;

    private static final String JWS_HEADER = "X-JWS-Signature";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String jwsSignature = request.getHeader(JWS_HEADER);

        // JWS header missing → reject
        if (jwsSignature == null || jwsSignature.isBlank()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                "Missing X-JWS-Signature header");
            return;
        }

        try {
            // Read body for verification
            String requestBody = new String(request.getInputStream().readAllBytes());

            // Verify JWS signature
            String verifiedPayload = jwsVerificationService.verify(jwsSignature);

            // Cross-check payload matches request body
            if (!verifiedPayload.equals(requestBody)) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "JWS payload does not match request body");
                return;
            }

            log.debug("JWS request verification passed");
            filterChain.doFilter(request, response);

        } catch (JwsException e) {
            log.warn("JWS verification failed: {}", e.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                "JWS signature invalid: " + e.getMessage());
        }
    }
}
```

---

### Approach 3: Webhook Signing & Verification

**Best for:** GitHub/Stripe style webhook signature verification.

```java
@Service
@Slf4j
public class WebhookSigningService {

    /**
     * Sign outgoing webhook payload
     * Client verifies using our public key from JWKS endpoint
     */
    public String signWebhook(Object eventPayload, RSAKey signingKey)
            throws JsonProcessingException, JOSEException {

        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(eventPayload);

        JWSSigner signer = new RSASSASigner(signingKey);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID(signingKey.getKeyID())
            .contentType("application/json")
            .build();

        JWSObject jws = new JWSObject(header, new Payload(json));
        jws.sign(signer);

        return jws.serialize(); // Include in response header
    }

    /**
     * Verify incoming webhook (signed by external party)
     * Their public key is fetched from their JWKS endpoint
     */
    public boolean verifyIncomingWebhook(String jwsSignature,
                                          String expectedPayload,
                                          JWKSet externalJwks)
            throws ParseException, JOSEException {

        JWSObject jws = JWSObject.parse(jwsSignature);
        String kid = jws.getHeader().getKeyID();

        JWK key = externalJwks.getKeyByKeyId(kid);
        if (key == null) return false;

        JWSVerifier verifier = new RSASSAVerifier(((RSAKey) key).toPublicJWK());
        boolean sigValid = jws.verify(verifier);

        // Also verify payload matches what we received
        boolean payloadValid = jws.getPayload().toString().equals(expectedPayload);

        return sigValid && payloadValid;
    }
}
```

---

### Approach 4: Detached JWS — HTTP Message Signing (Open Banking / FAPI)

**Best for:** PSD2, Open Banking UK, Financial Grade API (FAPI).

```
What is Detached Payload?
  Normal JWS:    header.payload.signature
  Detached JWS:  header..signature  (payload removed — sent separately in body)

Why?
  HTTP body is the payload — no need to Base64URL encode it in JWS
  Reduces size, preserves original content type
```

```java
@Service
@Slf4j
public class DetachedJwsService {

    /**
     * Create Detached JWS — payload Base64URL encoded is REMOVED from token
     * Used in Open Banking, PSD2 compliance
     *
     * Request:
     *   Header: x-jws-signature: eyJhbGci...HEADER..eyJhbGci...SIGNATURE
     *   Body:   {"amount": 100, "currency": "EUR"}  ← payload is here, not in JWS
     */
    public String createDetachedJws(String payload, RSAKey signingKey)
            throws JOSEException {

        JWSSigner signer = new RSASSASigner(signingKey);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.PS256)
            .keyID(signingKey.getKeyID())
            .build();

        JWSObject jws = new JWSObject(header, new Payload(payload));
        jws.sign(signer);

        // Serialize with DETACHED payload → header..signature
        return jws.serialize(true);   // true = detach payload
    }

    /**
     * Verify Detached JWS
     * Reattach the actual payload from request body before verifying
     */
    public boolean verifyDetachedJws(String detachedJws,
                                      String actualPayload,
                                      RSAKey publicKey)
            throws ParseException, JOSEException {

        // Reattach payload: header..sig → header.payload.sig
        String[] parts = detachedJws.split("\\.");
        if (parts.length != 3 || !parts[1].isEmpty()) {
            throw new JwsException("Not a detached JWS — payload part must be empty");
        }

        String reattached = parts[0] + "."
            + Base64URL.encode(actualPayload)
            + "." + parts[2];

        JWSObject jws = JWSObject.parse(reattached);
        JWSVerifier verifier = new RSASSAVerifier(publicKey.toRSAPublicKey());
        return jws.verify(verifier);
    }
}
```

---

### Approach 5: Multi-Signature JWS (JSON Serialization)

**Best for:** Document signing where multiple parties must co-sign.

```java
@Service
@Slf4j
public class MultiSignatureJwsService {

    /**
     * Multiple parties sign same document
     * Used in: Legal document signing, Trade Finance, Supply Chain
     *
     * Output (JSON Serialization):
     * {
     *   "payload": "eyJkb2N1bWVudCI6Ii4uLiJ9",
     *   "signatures": [
     *     { "protected": "...", "signature": "..." },  ← Signer 1 (RSA)
     *     { "protected": "...", "signature": "..." }   ← Signer 2 (EC)
     *   ]
     * }
     */
    public String multiSign(String documentPayload, List<JWK> signingKeys)
            throws JOSEException {

        Payload payload = new Payload(documentPayload);
        List<JWSObjectJSON.Signature> signatures = new ArrayList<>();

        for (JWK key : signingKeys) {
            JWSHeader header;
            JWSSigner signer;

            if (key instanceof RSAKey rsaKey) {
                header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(rsaKey.getKeyID()).build();
                signer = new RSASSASigner(rsaKey);
            } else if (key instanceof ECKey ecKey) {
                header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(ecKey.getKeyID()).build();
                signer = new ECDSASigner(ecKey);
            } else {
                throw new JwsException("Unsupported key type: " + key.getKeyType());
            }

            JWSObjectJSON.Signature sig = new JWSObjectJSON.Signature(
                header, null, signer
            );
            signatures.add(sig);
        }

        JWSObjectJSON jwsJson = new JWSObjectJSON(payload);
        signatures.forEach(sig -> {
            try {
                jwsJson.sign(sig.getHeader(), sig.getSigner());
            } catch (JOSEException e) {
                throw new JwsException("Failed to sign with key", e);
            }
        });

        return jwsJson.serializeGeneral(); // Full JSON serialization
    }

    /**
     * Verify ALL signatures in a multi-signature JWS document
     * ALL signatures must be valid for the document to be accepted
     */
    public boolean verifyAll(String multiSigJws, JWKSet publicJwkSet)
            throws ParseException, JOSEException {

        JWSObjectJSON jwsJson = JWSObjectJSON.parse(multiSigJws);

        for (JWSObjectJSON.Signature sig : jwsJson.getSignatures()) {
            String kid = sig.getHeader().getKeyID();
            JWK key = publicJwkSet.getKeyByKeyId(kid);

            if (key == null) {
                log.warn("No key found for kid={}", kid);
                return false;
            }

            JWSVerifier verifier = (key instanceof RSAKey rsaKey)
                ? new RSASSAVerifier(rsaKey.toRSAPublicKey())
                : new ECDSAVerifier(((ECKey) key).toECPublicKey());

            if (!sig.verify(verifier)) {
                log.warn("Signature failed for kid={}", kid);
                return false;
            }
        }

        log.info("All {} signatures verified successfully", jwsJson.getSignatures().size());
        return true;
    }
}
```

---

### Approach 6: JWS with X.509 Certificate Chain (PKI Integration)

**Best for:** Enterprise PKI, Worldline/WLCA, financial systems.

```java
@Service
@Slf4j
public class CertificateJwsService {

    /**
     * Sign payload embedding X.509 certificate chain in JWS header
     * Receiver can verify trust chain without separate key distribution
     *
     * Header contains:
     *   x5c: [leaf-cert, intermediate-cert, root-cert]  ← Full chain
     *   x5t#S256: SHA-256 thumbprint of leaf cert
     */
    public String signWithCertificate(String payload,
                                       PrivateKey privateKey,
                                       X509Certificate[] certChain)
            throws Exception {

        // Build x5c chain (DER encoded certificates)
        List<Base64> x5c = new ArrayList<>();
        for (X509Certificate cert : certChain) {
            x5c.add(Base64.encode(cert.getEncoded()));
        }

        // Compute SHA-256 thumbprint of leaf certificate
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        Base64URL thumbprint = Base64URL.encode(
            sha256.digest(certChain[0].getEncoded())
        );

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
            .x509CertChain(x5c)
            .x509CertSHA256Thumbprint(thumbprint)
            .type(new JOSEObjectType("JWS"))
            .build();

        JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
        JWSObject jws = new JWSObject(header, new Payload(payload));
        jws.sign(signer);

        return jws.serialize();
    }

    /**
     * Verify JWS by extracting certificate from header and validating trust chain
     */
    public String verifyWithCertChain(String compactJws,
                                       X509Certificate trustedRoot)
            throws Exception {

        JWSObject jws = JWSObject.parse(compactJws);
        List<Base64> x5c = jws.getHeader().getX509CertChain();

        if (x5c == null || x5c.isEmpty()) {
            throw new JwsException("No certificate chain in JWS header");
        }

        // Parse certificates from x5c header
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs = new ArrayList<>();
        for (Base64 certBase64 : x5c) {
            certs.add((X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(certBase64.decode())
            ));
        }

        // Validate certificate chain against trusted root
        validateCertChain(certs, trustedRoot);

        // Verify JWS signature using leaf certificate's public key
        RSAKey publicKey = new RSAKey.Builder(
            (RSAPublicKey) certs.get(0).getPublicKey()
        ).build();

        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        if (!jws.verify(verifier)) {
            throw new JwsException("JWS signature verification FAILED");
        }

        return jws.getPayload().toString();
    }

    private void validateCertChain(List<X509Certificate> chain,
                                    X509Certificate trustedRoot) throws Exception {
        // Certificate validity period check
        for (X509Certificate cert : chain) {
            cert.checkValidity();
        }
        // Full PKIX validation (trust chain, CRL, OCSP) can be added here
        log.info("Certificate chain validated. Leaf subject={}",
            chain.get(0).getSubjectX500Principal().getName());
    }
}
```

---

### Approach 7: DPoP Proof (RFC 9449) — Demonstrating Proof of Possession

**Best for:** Token theft prevention — ties access token to client's key pair.

```java
@Service
@Slf4j
public class DpopService {

    /**
     * Generate DPoP Proof JWS
     * Client sends this with every API request to prove it holds the private key
     *
     * DPoP Header: { "typ": "dpop+jwt", "alg": "RS256", "jwk": {public key} }
     * DPoP Claims: { "jti": uuid, "htm": "GET", "htu": url, "iat": now }
     */
    public String generateDpopProof(RSAKey clientKey,
                                     String httpMethod,
                                     String httpUrl)
            throws JOSEException {

        // Embed PUBLIC key in header (receiver uses it to verify)
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
            .type(new JOSEObjectType("dpop+jwt"))
            .jwk(clientKey.toPublicJWK())     // Public key embedded
            .build();

        Instant now = Instant.now();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .jwtID(UUID.randomUUID().toString())   // jti — unique per request
            .claim("htm", httpMethod.toUpperCase()) // HTTP method
            .claim("htu", httpUrl)                  // HTTP URL
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(30))) // Short-lived!
            .build();

        SignedJWT dpopProof = new SignedJWT(header, claims);
        dpopProof.sign(new RSASSASigner(clientKey));

        return dpopProof.serialize();
    }

    /**
     * Validate incoming DPoP Proof at resource server
     */
    public boolean validateDpopProof(String dpopProofJwt,
                                      String expectedMethod,
                                      String expectedUrl)
            throws ParseException, JOSEException {

        SignedJWT dpop = SignedJWT.parse(dpopProofJwt);

        // Extract embedded public key from header
        JWK embeddedKey = dpop.getHeader().getJWK();
        if (embeddedKey == null) {
            throw new JwsException("DPoP proof missing embedded JWK");
        }

        // Verify signature with embedded key
        JWSVerifier verifier = new RSASSAVerifier(
            ((RSAKey) embeddedKey).toRSAPublicKey()
        );
        if (!dpop.verify(verifier)) return false;

        // Validate claims
        JWTClaimsSet claims = dpop.getJWTClaimsSet();
        boolean methodMatch = expectedMethod.equalsIgnoreCase(
            claims.getStringClaim("htm")
        );
        boolean urlMatch = expectedUrl.equals(claims.getStringClaim("htu"));
        boolean notExpired = claims.getExpirationTime().after(new Date());

        return methodMatch && urlMatch && notExpired;
    }
}
```

---

## 9. JWS in PKI / Certificate Context

### JWS + X.509 — How They Complement Each Other

```
Traditional PKI:
  Certificate → contains public key + identity
  Signature   → DER/PEM encoded, binary

JWS + PKI:
  x5c header   → X.509 certificate chain embedded in JWS
  x5t#S256     → Certificate thumbprint for quick lookup
  Signature    → Base64URL encoded, HTTP-friendly

Benefit:
  JWS wraps PKI signatures in a JSON/HTTP-friendly format
  Suitable for REST APIs, microservices, cloud environments
```

### Certificate Thumbprint vs kid

```
kid      → Internal key identifier (custom string)
           "auth-server-key-01"

x5t#S256 → SHA-256 hash of the DER-encoded certificate
           Standard way to reference a certificate
           Used in: Open Banking, FAPI, TLS client auth binding

Use both:
{
  "alg":       "RS256",
  "kid":       "auth-server-key-01",
  "x5t#S256":  "sha256-thumbprint-of-corresponding-certificate"
}
```

### JWS Thumbprint (RFC 7638)

```java
// Compute JWK Thumbprint — used in DPoP, ACME, certificate binding
public String computeThumbprint(JWK jwk) throws JOSEException {
    // Canonical JSON form of key parameters → SHA-256 → Base64URL
    Base64URL thumbprint = jwk.computeThumbprint();
    return thumbprint.toString();
}

// Used in DPoP confirmation claim (cnf) in access token:
// { "cnf": { "jkt": "<thumbprint>" } }
```

---

## 10. JWS Detached Payload

### What & Why

```
Normal JWS:   header.payload.signature
              Payload is embedded in the token

Detached JWS: header..signature
              Payload is REMOVED from serialization
              Sent separately (e.g., HTTP request body)

Use Cases:
  - Open Banking UK (x-jws-signature header)
  - PSD2 API signing
  - Large payloads (avoid double encoding)
  - Preserve original content-type of payload
```

### HTTP Message Signing with Detached JWS

```
HTTP Request:
  POST /payments
  Content-Type: application/json
  x-jws-signature: eyJhbGciOiJQUzI1NiIsImtpZCI6ImtleS0wMSJ9..SflKxwRJSMeK

  {
    "amount": 500,
    "currency": "EUR",
    "creditor": "DE89370400440532013000"
  }

x-jws-signature value = header..signature (payload detached)
Server reattaches body as payload → verifies signature
```

---

## 11. Multi-Signature JWS (JSON Serialization)

### Use Cases

```
1. Trade Finance
   Exporter signs → Bank signs → Insurance signs
   All three signatures on same trade document

2. Software Deployment Approval
   Developer signs → QA signs → Security signs
   Deployment proceeds only if all sign

3. Legal Contracts
   Party A signs → Party B signs → Notary signs

4. Regulatory Compliance
   Transaction → Risk team signs → Compliance signs → Audit trail
```

### Multi-Signature Flow

```
Document
   │
   ├─── Signer 1 (RSA, kid=rsa-key-01) ──► Signature 1
   ├─── Signer 2 (EC,  kid=ec-key-01)  ──► Signature 2
   └─── Signer 3 (RSA, kid=rsa-key-03) ──► Signature 3

Output (JSON Serialization):
{
  "payload": "base64url(document)",
  "signatures": [
    { "protected": "base64url(header1)", "signature": "base64url(sig1)" },
    { "protected": "base64url(header2)", "signature": "base64url(sig2)" },
    { "protected": "base64url(header3)", "signature": "base64url(sig3)" }
  ]
}
```

---

## 12. Security Considerations

### Critical Rules

```
⛔ NEVER use alg=none in production
   → Attacker can forge tokens by removing signature

⛔ NEVER trust header alg blindly
   → Verify alg matches expected algorithm before verification
   → Algorithm confusion attack: RS256 → HS256 with public key as secret

⛔ NEVER embed private key in JWS header (jwk field)
   → Only public keys in jwk header field

⛔ NEVER use HS256 for public APIs
   → Both parties share same secret = no non-repudiation

⛔ NEVER accept JWS without verifying kid matches known key
   → Key injection attack

✅ Always validate:
   - Algorithm matches expected (whitelist approach)
   - kid is in your trusted JWKS
   - Signature is valid
   - Timestamp claims (exp, iat, nbf) if present
   - Content-type matches expected payload format
```

### Algorithm Confusion Attack

```
Attacker trick:
  Server uses RS256 (asymmetric)
  Attacker changes alg to HS256 (symmetric)
  Uses the PUBLIC key as the HMAC secret
  Server validates with public key as HMAC secret → PASSES ⚠️

Defense:
  Whitelist allowed algorithms:
  if (!allowedAlgorithms.contains(jws.getHeader().getAlgorithm())) {
      throw new JwsException("Algorithm not allowed: " + alg);
  }
```

### JWS Security Checklist

```
□ Use RS256 or ES256 minimum (asymmetric preferred)
□ RSA key size: 2048 minimum, 4096 for high-security
□ Validate algorithm before verification (whitelist)
□ Validate kid against known JWKS
□ Set JWS expiry for time-sensitive operations
□ Use unique jti for replay protection
□ Use HTTPS for JWKS endpoint
□ Rotate signing keys regularly (monthly minimum)
□ Keep 2 keys active during rotation overlap window
□ Log all signing and verification events for audit
```

---

## 13. Tools, Libraries & Ecosystem

### Java Libraries

| Library                  | Version   | Use Case                              |
|--------------------------|-----------|---------------------------------------|
| `nimbus-jose-jwt`        | 9.37.3    | Full JWS/JWT/JWK support (recommended)|
| `bcprov-jdk18on`         | 1.78.1    | BouncyCastle — PKI, X.509, PEM parsing|
| `bcpkix-jdk18on`         | 1.78.1    | BouncyCastle — PKIX, CMS signing      |
| `spring-security-oauth2` | 6.x       | OAuth2 / OIDC integration             |
| `jose4j`                 | 0.9.x     | Alternative to Nimbus                 |

### Testing Tools

```
jwt.io          → Decode and inspect JWS/JWT online
mkjwk.org       → Generate JWK key pairs online
Postman         → Test signed API requests
curl            → Command-line JWS testing
```

### Command Line

```bash
# Decode JWS header (first part)
echo "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0wMSJ9" | base64 -d
# Output: {"alg":"RS256","kid":"key-01"}

# Decode JWS payload (second part)
echo "eyJkYXRhIjoiSGVsbG8gV29ybGQifQ" | base64 -d
# Output: {"data":"Hello World"}

# Verify JWS with openssl
openssl dgst -sha256 -verify public.pem -signature sig.bin payload.txt
```

---

## 14. Decision Matrix — Which Approach to Use?

```
┌────────────────────────────────────────────────────────────────────┐
│ SCENARIO                           │ APPROACH                      │
├────────────────────────────────────┼───────────────────────────────│
│ API request body signing           │ Approach 1 (Manual JWS)       │
│ JWT token issuance                 │ JWT (JWS specialization)       │
│ Incoming request verification      │ Approach 2 (Filter)           │
│ Webhook signing (outgoing)         │ Approach 3 (Webhook)          │
│ Webhook verification (incoming)    │ Approach 3 (Webhook)          │
│ Open Banking / PSD2                │ Approach 4 (Detached JWS)     │
│ Multi-party document signing       │ Approach 5 (Multi-sig)        │
│ Enterprise PKI integration         │ Approach 6 (X.509 + JWS)     │
│ Token theft prevention             │ Approach 7 (DPoP RFC 9449)    │
│ Internal microservices             │ HS256 (Approach 1 symmetric)  │
│ Worldline / WLCA PKI               │ Approach 6 + BouncyCastle     │
└────────────────────────────────────┴───────────────────────────────┘
```

### Algorithm Decision Matrix

```
┌──────────────────────────────────────────────────────────────────┐
│ REQUIREMENT              │ ALGORITHM  │ REASON                    │
├──────────────────────────┼────────────┼───────────────────────────│
│ Maximum compatibility    │ RS256      │ Supported everywhere       │
│ Maximum security (RSA)   │ PS256      │ PSS > PKCS1               │
│ Smallest key, fast       │ ES256      │ P-256 = 256-bit key       │
│ Modern, fastest          │ EdDSA      │ Ed25519, 255-bit key      │
│ Internal only            │ HS256      │ Shared secret, fastest    │
│ Banking / FAPI           │ PS256      │ Required by FAPI spec     │
│ Open Banking UK          │ PS256      │ OB security profile       │
└──────────────────────────┴────────────┴───────────────────────────┘
```

---

## 15. Open Questions & Future Exploration

```
1. Post-Quantum JWS
   □ ML-DSA (CRYSTALS-Dilithium) as JWS signing algorithm
   □ Draft RFC: draft-ietf-jose-dilithium
   □ Hybrid: RSA + ML-DSA composite signature

2. HTTP Message Signatures (RFC 9421)
   □ More structured HTTP signing than detached JWS
   □ Signs specific HTTP headers + body
   □ Future direction for Open Banking APIs

3. JSON-LD Signatures + JWS
   □ Verifiable Credentials (W3C)
   □ Self-Sovereign Identity (SSI)
   □ DID (Decentralized Identifiers)

4. JWS + HSM Integration
   □ Private key never leaves HSM
   □ PKCS#11 provider for signing
   □ Cloud KMS (AWS KMS, Azure Key Vault)

5. Selective Disclosure JWS
   □ SD-JWT (draft-ietf-oauth-selective-disclosure-jwt)
   □ Reveal only specific claims to specific parties
   □ Privacy-preserving credentials

6. JWS Key Rotation Automation
   □ Automated rotation without downtime
   □ JWKS caching strategies at resource server
   □ Cache invalidation on rotation

7. JWS Performance Benchmarks
   □ RS256 vs ES256 vs EdDSA throughput
   □ Key size impact on signing speed
   □ HMAC vs asymmetric for high-frequency APIs

8. Compliance
   □ eIDAS 2.0 (EU digital identity)
   □ ETSI TS 119 312 (cryptographic algorithms)
   □ FIPS 140-3 compliant JWS implementation
```

---

## Development Plan — Implementation Order

```
Phase 1: Core JWS Engine
  □ JwsSigningService    — sign(payload, key) for RSA, EC, HMAC
  □ JwsVerificationService — verify(compactJws, jwks)
  □ JwsException         — domain exception
  □ Unit Tests           — sign/verify round-trip, tamper detection

Phase 2: HTTP Integration
  □ JwsController        — POST /api/jws/sign, POST /api/jws/verify
  □ JwsRequestFilter     — verify incoming signed requests
  □ JwsResponseSigner    — sign outgoing API responses
  □ Integration Tests    — full HTTP flow

Phase 3: Advanced Features
  □ DetachedJwsService   — Open Banking style x-jws-signature
  □ MultiSignatureService — JSON serialization, multi-party signing
  □ WebhookSigningService — sign/verify webhook payloads
  □ DpopService          — RFC 9449 proof of possession

Phase 4: PKI Integration
  □ CertificateJwsService — x5c, x5t#S256 in header
  □ BouncyCastle integration — PEM/DER parsing
  □ Certificate chain validation
  □ HSM signing (PKCS#11)

Phase 5: Security Hardening
  □ Algorithm whitelist enforcement
  □ Algorithm confusion attack prevention
  □ jti replay protection (H2 DB)
  □ Key rotation integration
  □ Audit logging
```

---

*Plan generated: 2026-03-04 | RFC 7515 (JWS) | Spring Boot 3.4.3 | Nimbus JOSE + JWT 9.37.3*
